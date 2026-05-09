"""Core SHAKEN certificate issuance and lifecycle manager."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from stir_shaken_acme import (
    IssuanceValidationError,
    ShakenCertificateManager,
    ShakenCertificatePolicy,
    ShakenSubject,
    StipaSettings,
    StirShakenIssuanceResult,
    TnAuthList,
)
from stir_shaken_toolkit.providers.peeringhub import PeeringhubIssuer

from shaken_cert_manager.config import ManagerConfig
from shaken_cert_manager.errors import ManagerError, ValidationError
from shaken_cert_manager.files import (
    FileLock,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    now_utc,
    read_json,
)
from shaken_cert_manager.status import (
    CRITICAL,
    OK,
    StatusChecker,
    WARNING,
)


class ShakenCertManager:
    """Orchestrate SHAKEN certificate issue, renewal, status, and cleanup."""

    def __init__(self, config: ManagerConfig) -> None:
        self.config = config
        self.certificates = ShakenCertificateManager()

    def status(self, nagios: bool = False, json_output: bool = False) -> int:
        """Print manager status.

        :param nagios: Print Nagios output.
        :type nagios: bool
        :param json_output: Print JSON output.
        :type json_output: bool
        :return: Exit code.
        :rtype: int
        """

        result = StatusChecker(self.config).check()
        if json_output:
            print(
                json.dumps(
                    {
                        "code": result.code,
                        "summary": result.summary,
                        "fields": result.fields,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        elif nagios:
            print(result.nagios_line())
        else:
            print(result.summary)
            for key, value in result.fields.items():
                print(f"{key}: {value}")
        return result.code

    def issue_initial(self, wait_lock: bool = False) -> int:
        """Issue an initial certificate when none is active.

        :param wait_lock: Wait for manager lock.
        :type wait_lock: bool
        :return: Exit code.
        :rtype: int
        """

        with FileLock(self.config.lock_path, wait_lock):
            self.prune_live_links()
            if StatusChecker(self.config).check().code in {OK, WARNING}:
                self.write_last_attempt(
                    "issue-initial",
                    "no_renewal_needed",
                    "active certificate already exists",
                )
                return 0
            self.issue_certificate("issue-initial", force=True)
            return 0

    def renew(self, wait_lock: bool = False) -> int:
        """Renew only when policy requires it.

        :param wait_lock: Wait for manager lock.
        :type wait_lock: bool
        :return: Exit code.
        :rtype: int
        """

        with FileLock(self.config.lock_path, wait_lock):
            self.prune_live_links()
            if not self.renewal_required():
                self.write_last_attempt(
                    "renew",
                    "no_renewal_needed",
                    "active certificate outside renewal window",
                )
                return 0
            self.issue_certificate("renew", force=False)
            return 0

    def force_renew(self, wait_lock: bool = False) -> int:
        """Force a certificate renewal.

        :param wait_lock: Wait for manager lock.
        :type wait_lock: bool
        :return: Exit code.
        :rtype: int
        """

        with FileLock(self.config.lock_path, wait_lock):
            self.prune_live_links()
            self.issue_certificate("force-renew", force=True)
            return 0

    def cleanup(self, wait_lock: bool = False) -> int:
        """Remove expired inactive archives and old failed archives.

        :param wait_lock: Wait for manager lock.
        :type wait_lock: bool
        :return: Exit code.
        :rtype: int
        """

        with FileLock(self.config.lock_path, wait_lock):
            self.prune_live_links()
            active_generation_id = self.active_generation_id()
            cutoff = datetime.now(UTC) - timedelta(
                days=self.config.retention_days_after_expiry
            )
            for manifest_path in self.config.archive_dir.glob("*/manifest.json"):
                manifest = read_json(manifest_path)
                generation_id = str(manifest.get("generation_id", ""))
                if generation_id == active_generation_id:
                    continue
                not_after = parse_timestamp(str(manifest.get("not_after", "")))
                if not_after is None or not_after > cutoff:
                    continue
                shutil.rmtree(manifest_path.parent)
            self.prune_failed_archives()
            self.prune_live_links()
            self.write_last_attempt("cleanup", "success", "cleanup complete")
            return 0

    def renewal_required(self) -> bool:
        """Return whether a renewal is required.

        :return: Whether renewal is required.
        :rtype: bool
        """

        result = StatusChecker(self.config).check()
        if result.code == CRITICAL:
            return True
        if result.code == WARNING:
            days_remaining = result.fields.get("days_remaining")
            return (
                isinstance(days_remaining, int)
                and days_remaining <= self.config.renew_before_days
            )
        return False

    def issue_certificate(self, command: str, force: bool) -> None:
        """Perform a full transactional certificate issuance.

        :param command: Command name.
        :type command: str
        :param force: Whether issuance is forced.
        :type force: bool
        :return: None.
        :rtype: None
        """

        if not self.config.enabled:
            self.write_last_attempt(
                command, "no_renewal_needed", "SHAKEN certificate management disabled"
            )
            return
        started_at = now_utc()
        generation_id = self.new_generation_id()
        transaction_dir = self.config.work_dir / generation_id
        transaction_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        live_generation_created = False
        try:
            self.preflight()
            issuer = self.prepare_peeringhub_issuer(generation_id)
            result = issuer.issue(
                self.config.stipa_spc,
                not_before=self.config.not_before,
                not_after=self.config.not_after,
            )
            csr_pem_path = transaction_dir / "csr.pem"
            csr_der_path = transaction_dir / "csr.der"
            atomic_write_bytes(csr_pem_path, result.csr_pem, 0o600)
            atomic_write_bytes(csr_der_path, result.csr_der, 0o600)
            archive_dir = self.config.archive_dir / generation_id
            archive_dir.mkdir(parents=True, mode=0o711, exist_ok=False)
            leaf_archive_path = archive_dir / "leaf.pem"
            chain_archive_path = archive_dir / "certificate-chain.pem"
            shutil.copy2(csr_pem_path, archive_dir / "csr.pem")
            shutil.copy2(csr_der_path, archive_dir / "csr.der")
            atomic_write_text(chain_archive_path, result.chain_pem, 0o644)
            atomic_write_text(leaf_archive_path, result.leaf_pem, 0o644)
            atomic_write_json(archive_dir / "order.json", result.valid_order, 0o600)
            atomic_write_json(
                archive_dir / "authorization.json", result.authorization, 0o600
            )
            atomic_write_json(
                archive_dir / "challenge.json", result.submitted_challenge, 0o600
            )
            if result.certificate_details is None:
                raise ValidationError("issued certificate details are missing")
            manifest = self.build_manifest(
                generation_id=generation_id,
                cert_details=result.certificate_details.as_dict(),
                tn_auth_list_value=result.tn_auth_list_value,
                installed_key_path=self.config.acme_account_key_path,
                chain_archive_path=chain_archive_path,
                leaf_archive_path=leaf_archive_path,
                order_url=result.order_url,
                authorization_url=result.authorization_url,
                finalize_url=result.finalize_url,
                certificate_url=result.certificate_url,
                stipa_token=result.stipa_token,
                account_state=result.account_state,
                deploy_hook_status="pending",
            )
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            self.create_live_generation_links(generation_id, archive_dir)
            live_generation_created = True
            try:
                deploy_hook_status = self.run_deploy_hook(
                    archive_dir / "manifest.json"
                )
            except Exception:
                self.remove_live_generation_links(generation_id)
                raise
            manifest["deploy_hook_status"] = deploy_hook_status
            manifest["deployed_at"] = now_utc()
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            self.update_live_current(generation_id)
            atomic_write_json(self.config.active_manifest_path, manifest, 0o600)
            shutil.rmtree(transaction_dir)
            self.write_last_attempt(
                command,
                "success",
                "certificate issued",
                started_at=started_at,
                generation_id=generation_id,
            )
        except IssuanceValidationError as exc:
            if live_generation_created:
                self.remove_live_generation_links(generation_id)
            self.archive_validation_failure(generation_id, exc.partial_result)
            self.record_failure(
                command, generation_id, transaction_dir, started_at, exc
            )
            raise
        except Exception as exc:
            if live_generation_created:
                self.remove_live_generation_links(generation_id)
            self.record_failure(
                command, generation_id, transaction_dir, started_at, exc
            )
            raise

    def preflight(self) -> None:
        """Validate local prerequisites before network issuance.

        :return: None.
        :rtype: None
        """

        private_dirs = [
            self.config.work_dir,
            self.config.failed_dir,
            self.config.account_dir,
        ]
        traversable_dirs = [
            self.config.state_dir,
            self.config.archive_dir,
        ]
        for directory in private_dirs:
            self.ensure_directory_mode(directory, 0o700)
        for directory in traversable_dirs:
            self.ensure_directory_mode(directory, 0o711)
        self.ensure_directory_mode(self.config.live_dir, 0o755)
        if not self.config.acme_account_key_path.exists():
            raise ValidationError(
                f"ACME account private key is missing: {self.config.acme_account_key_path}"
            )

    def ensure_directory_mode(self, directory: Path, mode: int) -> None:
        """Create a directory and enforce its permissions.

        :param directory: Directory path.
        :type directory: Path
        :param mode: Directory mode.
        :type mode: int
        :return: None.
        :rtype: None
        """

        directory.mkdir(parents=True, mode=mode, exist_ok=True)
        os.chmod(directory, mode)

    def run_deploy_hook(self, manifest_path: Path) -> str:
        """Run the configured deploy hook for an archived generation.

        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :return: Hook status string.
        :rtype: str
        :raises ManagerError: If the deploy hook fails or times out.
        """

        if not self.config.deploy_hook:
            return "disabled"
        manifest = read_json(manifest_path)
        environment = self.deploy_hook_environment(manifest_path, manifest)
        try:
            result = subprocess.run(
                self.config.deploy_hook,
                check=False,
                env=environment,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.deploy_hook_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ManagerError(
                f"deploy hook timed out after {self.config.deploy_hook_timeout_seconds} seconds"
            ) from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or f"exit code {result.returncode}"
            raise ManagerError(f"deploy hook failed: {detail}")
        return "success"

    def deploy_hook_environment(
        self, manifest_path: Path, manifest: dict[str, Any]
    ) -> dict[str, str]:
        """Build deploy hook environment values.

        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :param manifest: Manifest values.
        :type manifest: dict[str, Any]
        :return: Hook environment.
        :rtype: dict[str, str]
        """

        environment = dict(os.environ)
        archive_dir = manifest_path.parent
        live_generation_dir = self.live_generation_dir(
            str(manifest["generation_id"])
        )
        live_current_dir = self.config.live_dir / "current"
        hook_values = {
            "SHAKEN_GENERATION_ID": manifest.get("generation_id"),
            "SHAKEN_ENVIRONMENT": manifest.get("peeringhub_environment"),
            "SHAKEN_SERVER_ID": manifest.get("server_id"),
            "SHAKEN_SPC": manifest.get("stipa_spc"),
            "SHAKEN_PRIVATE_KEY_PATH": manifest.get("certificate_private_key_path"),
            "SHAKEN_ARCHIVE_DIR": archive_dir,
            "SHAKEN_LIVE_DIR": self.config.live_dir,
            "SHAKEN_LIVE_GENERATION_DIR": live_generation_dir,
            "SHAKEN_LIVE_LEAF_CERT_PATH": live_generation_dir / "leaf.pem",
            "SHAKEN_LIVE_CHAIN_CERT_PATH": live_generation_dir
            / "certificate-chain.pem",
            "SHAKEN_LIVE_CURRENT_DIR": live_current_dir,
            "SHAKEN_LIVE_CURRENT_CHAIN_CERT_PATH": live_current_dir
            / "certificate-chain.pem",
            "SHAKEN_MANIFEST_PATH": manifest_path,
            "SHAKEN_LEAF_CERT_PATH": manifest.get("leaf_certificate_path"),
            "SHAKEN_CHAIN_CERT_PATH": manifest.get("certificate_chain_path"),
            "SHAKEN_CSR_PEM_PATH": archive_dir / "csr.pem",
            "SHAKEN_CSR_DER_PATH": archive_dir / "csr.der",
            "SHAKEN_NOT_BEFORE": manifest.get("not_before"),
            "SHAKEN_NOT_AFTER": manifest.get("not_after"),
            "SHAKEN_FINGERPRINT_SHA256": manifest.get("fingerprint_sha256"),
            "SHAKEN_PREVIOUS_GENERATION_ID": manifest.get("previous_generation_id"),
        }
        for key, value in hook_values.items():
            environment[key] = "" if value is None else str(value)
        return environment

    def build_manifest(self, **values: Any) -> dict[str, Any]:
        """Build an active/archive manifest.

        :param values: Manifest source values.
        :type values: Any
        :return: Manifest object.
        :rtype: dict[str, Any]
        """

        cert_details = values["cert_details"]
        generation_id = str(values["generation_id"])
        subject = self.build_subject(generation_id).to_x509_name().rfc4514_string()
        return {
            "generation_id": generation_id,
            "server_id": self.config.server_id,
            "peeringhub_environment": self.config.peeringhub_environment,
            "stipa_spc": self.config.stipa_spc,
            "stipa_sp_id": self.config.stipa_sp_id,
            "subject": subject,
            "tn_auth_list_value": values["tn_auth_list_value"],
            "certificate_private_key_path": str(values["installed_key_path"]),
            "certificate_private_key_source": "peeringhub_acme_account_key",
            "certificate_chain_path": str(values["chain_archive_path"]),
            "leaf_certificate_path": str(values["leaf_archive_path"]),
            "live_generation_dir": str(
                self.live_generation_dir(str(values["generation_id"]))
            ),
            "live_certificate_chain_path": str(
                self.live_generation_dir(str(values["generation_id"]))
                / "certificate-chain.pem"
            ),
            "live_leaf_certificate_path": str(
                self.live_generation_dir(str(values["generation_id"])) / "leaf.pem"
            ),
            "serial_number": cert_details["serial_number"],
            "not_before": cert_details["not_before"],
            "not_after": cert_details["not_after"],
            "issuer": cert_details["issuer"],
            "subject_key_identifier": "",
            "fingerprint_sha256": cert_details["fingerprint_sha256"],
            "acme_account_url": values["account_state"].account_url,
            "acme_account_key_fingerprint": values[
                "account_state"
            ].account_key_fingerprint,
            "acme_order_url": values["order_url"],
            "acme_authorization_url": values["authorization_url"],
            "acme_finalize_url": values["finalize_url"],
            "acme_certificate_url": values["certificate_url"],
            "stipa_token_jti": values["stipa_token"].jti,
            "stipa_token_exp": values["stipa_token"].exp,
            "stipa_x5u": values["stipa_token"].x5u,
            "stipa_crl_url": values["stipa_token"].crl_url,
            "installed_at": now_utc(),
            "previous_generation_id": self.active_generation_id(),
            "deploy_hook": self.config.deploy_hook,
            "deploy_hook_status": values["deploy_hook_status"],
        }

    def record_failure(
        self,
        command: str,
        generation_id: str,
        transaction_dir: Path,
        started_at: str,
        exc: Exception,
    ) -> None:
        """Record a sanitized failure manifest.

        :param command: Command name.
        :type command: str
        :param generation_id: Generation ID.
        :type generation_id: str
        :param transaction_dir: Transaction directory.
        :type transaction_dir: Path
        :param started_at: Start timestamp.
        :type started_at: str
        :param exc: Exception.
        :type exc: Exception
        :return: None.
        :rtype: None
        """

        failed_dir = self.config.failed_dir / generation_id
        if self.config.retain_failed_transactions:
            failed_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            atomic_write_json(
                failed_dir / "failure.json",
                {
                    "generation_id": generation_id,
                    "command": command,
                    "sanitized_error": str(exc),
                    "failed_at": now_utc(),
                },
                0o600,
            )
        if transaction_dir.exists():
            shutil.rmtree(transaction_dir)
        self.write_last_attempt(
            command,
            "failed",
            str(exc),
            started_at=started_at,
            generation_id=generation_id,
            active_generation_unchanged=True,
        )
        self.prune_failed_archives()

    def archive_validation_failure(
        self, generation_id: str, result: StirShakenIssuanceResult
    ) -> None:
        """Archive downloaded certificate artifacts after validation failure.

        :param generation_id: Generation ID.
        :type generation_id: str
        :param result: Partial issuance result.
        :type result: StirShakenIssuanceResult
        :return: None.
        :rtype: None
        """

        if not self.config.retain_failed_transactions:
            return
        failed_dir = self.config.failed_dir / generation_id
        failed_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        atomic_write_bytes(failed_dir / "csr.pem", result.csr_pem, 0o600)
        atomic_write_bytes(failed_dir / "csr.der", result.csr_der, 0o600)
        atomic_write_text(failed_dir / "leaf.pem", result.leaf_pem, 0o600)
        atomic_write_text(
            failed_dir / "certificate-chain.pem", result.chain_pem, 0o600
        )
        atomic_write_json(failed_dir / "order.json", result.valid_order, 0o600)
        atomic_write_json(
            failed_dir / "authorization.json", result.authorization, 0o600
        )
        atomic_write_json(
            failed_dir / "challenge.json", result.submitted_challenge, 0o600
        )
        atomic_write_json(
            failed_dir / "issuance.json",
            {
                "account": result.account_state.__dict__,
                "authorization_url": result.authorization_url,
                "certificate_private_key_path": str(result.certificate_key_path),
                "certificate_private_key_source": "peeringhub_acme_account_key",
                "certificate_url": result.certificate_url,
                "finalize_url": result.finalize_url,
                "order_url": result.order_url,
                "stipa_token_exp": result.stipa_token.exp,
                "stipa_token_jti": result.stipa_token.jti,
                "tn_auth_list_value": result.tn_auth_list_value,
                "validation_error": result.validation_error,
            },
            0o600,
        )

    def write_last_attempt(
        self,
        command: str,
        result: str,
        reason: str,
        started_at: str | None = None,
        generation_id: str | None = None,
        active_generation_unchanged: bool = False,
    ) -> None:
        """Write the last-attempt manifest.

        :param command: Command name.
        :type command: str
        :param result: Attempt result.
        :type result: str
        :param reason: Reason text.
        :type reason: str
        :param started_at: Optional start timestamp.
        :type started_at: str | None
        :param generation_id: Optional generation ID.
        :type generation_id: str | None
        :param active_generation_unchanged: Whether active generation was unchanged.
        :type active_generation_unchanged: bool
        :return: None.
        :rtype: None
        """

        atomic_write_json(
            self.config.last_attempt_path,
            {
                "started_at": started_at or now_utc(),
                "finished_at": now_utc(),
                "command": command,
                "result": result,
                "reason": reason,
                "generation_id": generation_id,
                "active_generation_unchanged": active_generation_unchanged,
            },
            0o600,
        )

    def prune_failed_archives(self) -> None:
        """Limit retained failed transaction archives.

        :return: None.
        :rtype: None
        """

        failed_dirs = sorted(
            [path for path in self.config.failed_dir.iterdir() if path.is_dir()],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for directory in failed_dirs[self.config.max_failed_transactions_retained :]:
            shutil.rmtree(directory)

    def prune_live_links(self) -> None:
        """Remove expired or broken live generation symlink trees.

        :return: None.
        :rtype: None
        """

        if not self.config.live_dir.exists():
            return
        now = datetime.now(UTC)
        for directory in self.config.live_dir.iterdir():
            if directory.name == "current":
                continue
            if not directory.is_dir() and not directory.is_symlink():
                continue
            generation_id = directory.name
            manifest_path = self.config.archive_dir / generation_id / "manifest.json"
            if not manifest_path.exists():
                self.remove_live_path(directory)
                continue
            try:
                manifest = read_json(manifest_path)
            except (OSError, ValueError, json.JSONDecodeError):
                self.remove_live_path(directory)
                continue
            not_after = parse_timestamp(str(manifest.get("not_after", "")))
            if not_after is None or not_after <= now:
                self.remove_live_path(directory)
        self.remove_stale_live_current()

    def create_live_generation_links(
        self, generation_id: str, archive_dir: Path
    ) -> None:
        """Create a live symlink tree for a generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :param archive_dir: Archive directory.
        :type archive_dir: Path
        :return: None.
        :rtype: None
        """

        self.ensure_directory_mode(self.config.live_dir, 0o755)
        final_dir = self.live_generation_dir(generation_id)
        temporary_dir = (
            self.config.live_dir / f".{generation_id}.{secrets.token_hex(4)}"
        )
        if final_dir.exists() or final_dir.is_symlink():
            raise ValidationError(f"live generation already exists: {final_dir}")
        temporary_dir.mkdir(mode=0o755)
        for name in ["leaf.pem", "certificate-chain.pem"]:
            target = archive_dir / name
            link_target = os.path.relpath(target, start=final_dir)
            (temporary_dir / name).symlink_to(link_target)
        os.replace(temporary_dir, final_dir)

    def update_live_current(self, generation_id: str) -> None:
        """Atomically point live/current at a generation directory.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: None.
        :rtype: None
        """

        self.ensure_directory_mode(self.config.live_dir, 0o755)
        current_path = self.config.live_dir / "current"
        temporary_path = self.config.live_dir / f".current.{secrets.token_hex(4)}"
        temporary_path.symlink_to(generation_id, target_is_directory=True)
        os.replace(temporary_path, current_path)

    def remove_live_generation_links(self, generation_id: str) -> None:
        """Remove a live symlink tree for a generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: None.
        :rtype: None
        """

        self.remove_live_path(self.live_generation_dir(generation_id))
        self.remove_stale_live_current()

    def remove_stale_live_current(self) -> None:
        """Remove live/current when it points at a missing generation.

        :return: None.
        :rtype: None
        """

        current_path = self.config.live_dir / "current"
        if current_path.is_symlink() and not current_path.exists():
            current_path.unlink()

    def remove_live_path(self, path: Path) -> None:
        """Remove a live path without following symlinked directories.

        :param path: Path to remove.
        :type path: Path
        :return: None.
        :rtype: None
        """

        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)

    def live_generation_dir(self, generation_id: str) -> Path:
        """Return the live directory for a generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: Live generation directory.
        :rtype: Path
        """

        return self.config.live_dir / generation_id

    def active_generation_id(self) -> str | None:
        """Return active generation ID if present.

        :return: Generation ID or ``None``.
        :rtype: str | None
        """

        if not self.config.active_manifest_path.exists():
            return None
        try:
            return str(read_json(self.config.active_manifest_path).get("generation_id"))
        except (OSError, ValueError):
            return None

    def new_generation_id(self) -> str:
        """Create a generation ID.

        :return: Generation ID.
        :rtype: str
        """

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return f"{self.config.server_id}-{timestamp}-{secrets.token_hex(5)}"

    def prepare_peeringhub_issuer(self, generation_id: str) -> PeeringhubIssuer:
        """Build a Peeringhub issuer for one certificate generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: Peeringhub issuer.
        :rtype: PeeringhubIssuer
        """

        issuer_kwargs = {
            "profile": self.config.peeringhub_profile(),
            "account_key_path": self.config.acme_account_key_path,
            "account_state_path": self.config.acme_account_state_path,
            "acme_kid": self.config.acme_kid,
            "stipa_settings": self.stipa_settings(),
            "certificate_policy": self.certificate_policy(generation_id),
        }
        if self.config.acme_timeout_seconds is not None:
            issuer_kwargs["acme_timeout_seconds"] = self.config.acme_timeout_seconds
        if self.config.acme_bad_nonce_retries is not None:
            issuer_kwargs["acme_bad_nonce_retries"] = self.config.acme_bad_nonce_retries
        if self.config.acme_poll_interval_seconds is not None:
            issuer_kwargs["acme_poll_interval_seconds"] = (
                self.config.acme_poll_interval_seconds
            )
        if self.config.acme_poll_timeout_seconds is not None:
            issuer_kwargs["acme_poll_timeout_seconds"] = (
                self.config.acme_poll_timeout_seconds
            )
        return PeeringhubIssuer.build(**issuer_kwargs)

    def stipa_settings(self) -> StipaSettings:
        """Build reusable STI-PA settings from manager configuration.

        :return: STI-PA settings.
        :rtype: StipaSettings
        """

        stipa_kwargs = {
            "base_url": self.config.stipa_url(),
            "user_id": self.config.stipa_user_id,
            "password": self.config.stipa_password,
            "sp_id": self.config.stipa_sp_id,
            "expected_crl_url": self.config.expected_crl_url(),
            "ca": False,
        }
        if self.config.stipa_timeout_seconds is not None:
            stipa_kwargs["timeout_seconds"] = self.config.stipa_timeout_seconds
        if self.config.acme_poll_timeout_seconds is not None:
            stipa_kwargs["minimum_token_lifetime_seconds"] = (
                self.config.acme_poll_timeout_seconds
            )
        return StipaSettings(
            **stipa_kwargs,
        )

    def certificate_policy(self, generation_id: str) -> ShakenCertificatePolicy:
        """Build reusable SHAKEN certificate policy.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: Certificate policy.
        :rtype: ShakenCertificatePolicy
        """

        return ShakenCertificatePolicy(
            subject=self.build_subject(generation_id),
            tn_auth_list_der=TnAuthList(self.config.stipa_spc).der(),
            expected_crl_url=self.config.expected_crl_url(),
            minimum_certificate_lifetime_days=(
                self.config.minimum_certificate_lifetime_days
            ),
            include_crl_distribution_points=(
                self.config.include_crl_distribution_points
            ),
        )

    def build_subject(self, generation_id: str) -> ShakenSubject:
        """Build the configured certificate subject.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: SHAKEN subject.
        :rtype: ShakenSubject
        """

        template_values = {
            "generation_id": generation_id,
            "server_id": self.config.server_id,
            "stipa_spc": self.config.stipa_spc,
            "organization": self.config.shaken_subject_organization,
        }
        if self.config.shaken_subject_organization_template:
            organization = render_subject_template(
                self.config.shaken_subject_organization_template, template_values
            )
        else:
            organization = (
                f"{self.config.shaken_subject_organization} "
                f"{self.config.server_id} {generation_id}"
            )
        if self.config.shaken_subject_common_name_template:
            common_name = render_subject_template(
                self.config.shaken_subject_common_name_template, template_values
            )
        elif self.config.subject_strategy == "conservative_cn_unique_o":
            common_name = f"SHAKEN {self.config.stipa_spc}"
        else:
            common_name = (
                f"SHAKEN {self.config.stipa_spc} {self.config.server_id} {generation_id}"
            )
        return ShakenSubject(
            country=self.config.shaken_subject_country,
            state=self.config.shaken_subject_state,
            locality=self.config.shaken_subject_locality,
            organization=organization,
            organizational_unit=self.config.shaken_subject_organizational_unit,
            common_name=common_name,
        )


def render_subject_template(template: str, values: dict[str, str]) -> str:
    """Render a certificate subject template.

    :param template: Format string template.
    :type template: str
    :param values: Template values.
    :type values: dict[str, str]
    :return: Rendered subject value.
    :rtype: str
    :raises ValidationError: If the template references an unknown field.
    """

    try:
        return template.format(**values)
    except KeyError as exc:
        field_name = str(exc.args[0])
        raise ValidationError(
            f"Unknown certificate subject template field: {field_name}"
        ) from exc


def parse_timestamp(value: str) -> datetime | None:
    """Parse a manifest timestamp.

    :param value: Timestamp text.
    :type value: str
    :return: Parsed timestamp or ``None``.
    :rtype: datetime | None
    """

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
