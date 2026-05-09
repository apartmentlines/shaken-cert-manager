"""Core SHAKEN certificate issuance and lifecycle manager."""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import signal
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

LOGGER = logging.getLogger(__name__)


class ShakenCertManager:
    """Orchestrate SHAKEN certificate issue, renewal, status, and cleanup."""

    def __init__(self, config: ManagerConfig) -> None:
        self.config: ManagerConfig = config
        self.certificates: ShakenCertificateManager = ShakenCertificateManager()

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
        LOGGER.debug(
            "Status command result: code=%s summary=%s json_output=%s nagios=%s",
            result.code,
            result.summary,
            json_output,
            nagios,
        )
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

    def issue_initial(self) -> int:
        """Issue an initial certificate when none is active.

        :return: Exit code.
        :rtype: int
        """

        LOGGER.info("Issue-initial command started")
        with FileLock(self.config.lock_path):
            if not self.config.enabled:
                LOGGER.info(
                    "Initial issuance skipped: SHAKEN certificate management disabled"
                )
                self.write_last_attempt(
                    "issue-initial",
                    "disabled",
                    "SHAKEN certificate management disabled",
                    active_generation_unchanged=True,
                )
                return 0
            self.prune_live_links()
            result = StatusChecker(self.config).check()
            if result.code in {OK, WARNING}:
                LOGGER.info(
                    "Initial issuance skipped: active certificate already exists"
                )
                LOGGER.debug(
                    "Issue-initial status result: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                self.write_last_attempt(
                    "issue-initial",
                    "no_renewal_needed",
                    "active certificate already exists",
                    active_generation_unchanged=True,
                )
                return 0
            self.issue_certificate("issue-initial", force=True)
            LOGGER.info("Issue-initial command completed")
            return 0

    def renew(self) -> int:
        """Renew only when policy requires it.

        :return: Exit code.
        :rtype: int
        """

        LOGGER.info("Renew command started")
        with FileLock(self.config.lock_path):
            if not self.config.enabled:
                LOGGER.info("Renewal skipped: SHAKEN certificate management disabled")
                self.write_last_attempt(
                    "renew",
                    "disabled",
                    "SHAKEN certificate management disabled",
                    active_generation_unchanged=True,
                )
                return 0
            self.prune_live_links()
            if not self.renewal_required():
                LOGGER.info(
                    "Renewal skipped: active certificate outside renewal window"
                )
                self.write_last_attempt(
                    "renew",
                    "no_renewal_needed",
                    "active certificate outside renewal window",
                    active_generation_unchanged=True,
                )
                return 0
            self.issue_certificate("renew", force=False)
            LOGGER.info("Renew command completed")
            return 0

    def force_renew(self) -> int:
        """Force a certificate renewal.

        :return: Exit code.
        :rtype: int
        """

        LOGGER.info("Force-renew command started")
        with FileLock(self.config.lock_path):
            if not self.config.enabled:
                LOGGER.info(
                    "Force-renew skipped: SHAKEN certificate management disabled"
                )
                self.write_last_attempt(
                    "force-renew",
                    "disabled",
                    "SHAKEN certificate management disabled",
                    active_generation_unchanged=True,
                )
                return 0
            self.prune_live_links()
            self.issue_certificate("force-renew", force=True)
            LOGGER.info("Force-renew command completed")
            return 0

    def cleanup(self) -> int:
        """Remove expired inactive archives and old failed archives.

        :return: Exit code.
        :rtype: int
        """

        LOGGER.info("Cleanup command started")
        with FileLock(self.config.lock_path):
            if not self.config.enabled:
                LOGGER.info("Cleanup skipped: SHAKEN certificate management disabled")
                self.write_last_attempt(
                    "cleanup",
                    "disabled",
                    "SHAKEN certificate management disabled",
                    active_generation_unchanged=True,
                )
                return 0
            self.prune_live_links()
            active_generation_id = self.active_generation_id()
            cutoff = datetime.now(UTC) - timedelta(
                days=self.config.retention_days_after_expiry
            )
            removed_archives = 0
            for manifest_path in self.config.archive_dir.glob("*/manifest.json"):
                manifest = read_json(manifest_path)
                generation_id = str(manifest.get("generation_id", ""))
                if generation_id == active_generation_id:
                    continue
                not_after = parse_timestamp(str(manifest.get("not_after", "")))
                if not_after is None or not_after > cutoff:
                    continue
                LOGGER.info(
                    "Removing expired inactive archive: generation_id=%s path=%s",
                    generation_id,
                    manifest_path.parent,
                )
                shutil.rmtree(manifest_path.parent)
                removed_archives += 1
            self.prune_failed_archives()
            self.prune_live_links()
            self.write_last_attempt(
                "cleanup",
                "success",
                "cleanup complete",
                active_generation_unchanged=True,
            )
            LOGGER.info(
                "Cleanup command completed: removed_archives=%s", removed_archives
            )
            return 0

    def renewal_required(self) -> bool:
        """Return whether a renewal is required.

        :return: Whether renewal is required.
        :rtype: bool
        """

        result = StatusChecker(self.config).check()
        if result.code == CRITICAL:
            LOGGER.debug(
                "Renewal required: status_code=%s summary=%s",
                result.code,
                result.summary,
            )
            return True
        if result.code == WARNING:
            days_remaining = result.fields.get("days_remaining")
            required = (
                isinstance(days_remaining, int)
                and days_remaining <= self.config.renew_before_days
            )
            LOGGER.debug(
                "Renewal warning decision: required=%s days_remaining=%s "
                + "renew_before_days=%s summary=%s",
                required,
                days_remaining,
                self.config.renew_before_days,
                result.summary,
            )
            return required
        LOGGER.debug(
            "Renewal not required: status_code=%s summary=%s",
            result.code,
            result.summary,
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
            LOGGER.info("Issuance skipped: SHAKEN certificate management disabled")
            self.write_last_attempt(
                command,
                "disabled",
                "SHAKEN certificate management disabled",
                active_generation_unchanged=True,
            )
            return
        started_at = now_utc()
        try:
            self.preflight()
            self.refresh_account_state_if_needed()
        except Exception as exc:
            self.write_last_attempt(
                command,
                "failed",
                str(exc),
                started_at=started_at,
                active_generation_unchanged=True,
            )
            raise
        generation_id = self.new_generation_id()
        transaction_dir = self.config.work_dir / generation_id
        LOGGER.info(
            "Certificate issuance started: command=%s generation_id=%s force=%s",
            command,
            generation_id,
            force,
        )
        LOGGER.debug(
            "Certificate issuance paths: transaction_dir=%s archive_dir=%s "
            + "live_generation_dir=%s",
            transaction_dir,
            self.config.archive_dir / generation_id,
            self.live_generation_dir(generation_id),
        )
        transaction_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        live_generation_created = False
        active_generation_changed = False
        try:
            issuer = self.prepare_peeringhub_issuer(generation_id)
            LOGGER.debug(
                "Calling toolkit issuer: generation_id=%s stipa_spc=%s "
                + "not_before=%s not_after=%s",
                generation_id,
                self.config.stipa_spc,
                self.config.not_before,
                self.config.not_after,
            )
            result = issuer.issue(
                self.config.stipa_spc,
                not_before=self.config.not_before,
                not_after=self.config.not_after,
            )
            LOGGER.debug(
                "Toolkit issuer returned certificate: generation_id=%s order_url=%s "
                + "certificate_url=%s",
                generation_id,
                result.order_url,
                result.certificate_url,
            )
            csr_pem_path = transaction_dir / "csr.pem"
            csr_der_path = transaction_dir / "csr.der"
            atomic_write_bytes(csr_pem_path, result.csr_pem, 0o600)
            atomic_write_bytes(csr_der_path, result.csr_der, 0o600)
            LOGGER.debug(
                "Transaction CSR artifacts written: csr_pem_path=%s csr_der_path=%s",
                csr_pem_path,
                csr_der_path,
            )
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
            LOGGER.debug(
                "Archived issuance artifacts: archive_dir=%s leaf=%s chain=%s",
                archive_dir,
                leaf_archive_path,
                chain_archive_path,
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
                pre_activate_hook_status="pending",
                deploy_hook_status="pending",
            )
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            LOGGER.debug(
                "Archive manifest written: path=%s serial_number=%s not_after=%s",
                archive_dir / "manifest.json",
                manifest.get("serial_number"),
                manifest.get("not_after"),
            )
            self.create_live_generation_links(generation_id, archive_dir)
            live_generation_created = True
            try:
                pre_activate_hook_status = self.run_pre_activate_hook(
                    archive_dir / "manifest.json"
                )
            except Exception:
                manifest["pre_activate_hook_status"] = "failed"
                atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
                raise
            manifest["pre_activate_hook_status"] = pre_activate_hook_status
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            self.update_live_current(generation_id)
            active_generation_changed = True
            manifest["activated_at"] = now_utc()
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            atomic_write_json(self.config.active_manifest_path, manifest, 0o600)
            try:
                deploy_hook_status = self.run_deploy_hook(archive_dir / "manifest.json")
            except Exception as exc:
                deploy_hook_status = "failed"
                LOGGER.warning("Deploy hook failed after activation: %s", exc)
            manifest["deploy_hook_status"] = deploy_hook_status
            manifest["deploy_hook_finished_at"] = now_utc()
            atomic_write_json(archive_dir / "manifest.json", manifest, 0o600)
            atomic_write_json(self.config.active_manifest_path, manifest, 0o600)
            LOGGER.debug(
                "Active manifest updated: path=%s generation_id=%s",
                self.config.active_manifest_path,
                generation_id,
            )
            shutil.rmtree(transaction_dir)
            LOGGER.debug("Transaction directory removed: path=%s", transaction_dir)
            self.write_last_attempt(
                command,
                "success",
                "certificate issued",
                started_at=started_at,
                generation_id=generation_id,
                active_generation_unchanged=False,
            )
            LOGGER.info(
                "Certificate issuance completed: generation_id=%s archive_dir=%s "
                + "live_current=%s",
                generation_id,
                archive_dir,
                self.config.live_dir / "current",
            )
        except IssuanceValidationError as exc:
            if live_generation_created and not active_generation_changed:
                LOGGER.warning(
                    "Validation failed; rolling back live generation links: "
                    + "generation_id=%s",
                    generation_id,
                )
                self.remove_live_generation_links(generation_id)
            self.archive_validation_failure(generation_id, exc.partial_result)
            self.record_failure(
                command,
                generation_id,
                transaction_dir,
                started_at,
                exc,
                active_generation_unchanged=not active_generation_changed,
            )
            raise
        except Exception as exc:
            if live_generation_created and not active_generation_changed:
                LOGGER.warning(
                    "Issuance failed; rolling back live generation links: "
                    + "generation_id=%s",
                    generation_id,
                )
                self.remove_live_generation_links(generation_id)
            self.record_failure(
                command,
                generation_id,
                transaction_dir,
                started_at,
                exc,
                active_generation_unchanged=not active_generation_changed,
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
            LOGGER.debug("Preflight ensuring private directory: path=%s", directory)
            self.ensure_directory_mode(directory, 0o700)
        for directory in traversable_dirs:
            LOGGER.debug("Preflight ensuring traversable directory: path=%s", directory)
            self.ensure_directory_mode(directory, 0o711)
        LOGGER.debug("Preflight ensuring live directory: path=%s", self.config.live_dir)
        self.ensure_directory_mode(self.config.live_dir, 0o755)
        if not self.config.acme_account_key_path.exists():
            details = (
                "ACME account private key is missing: "
                + f"{self.config.acme_account_key_path}. Create or provision the "
                + "Peeringhub ACME account key before running shaken-cert-manager. "
                + "For manual setup of the configured account directory, run: "
                + "stir-shaken-toolkit peeringhub-account-setup --account-dir "
                + f"{self.config.account_dir}. If acme_account_key_path is set "
                + "outside account_dir, create the key at that exact path or "
                + "update the manager config"
            )
            if self.config.acme_account_state_path.exists():
                details = (
                    details
                    + ". ACME account state cache exists at "
                    + f"{self.config.acme_account_state_path}, but account.json is "
                    + "recoverable cache and cannot replace account.key"
                )
            raise ValidationError(details)
        LOGGER.debug(
            "Preflight completed: acme_account_key_path=%s",
            self.config.acme_account_key_path,
        )

    def refresh_account_state_if_needed(self) -> None:
        """Refresh recoverable ACME account state before certificate issuance.

        :return: None.
        :rtype: None
        """

        if self.config.acme_account_state_path.exists():
            LOGGER.debug(
                "ACME account state cache exists: path=%s",
                self.config.acme_account_state_path,
            )
            return
        LOGGER.info(
            "ACME account state cache missing; refreshing from Peeringhub using "
            + "configured account key"
        )
        issuer = self.prepare_peeringhub_account_issuer()
        state = issuer.prepare_account()
        LOGGER.info(
            "ACME account state refreshed: account_url=%s status=%s state_path=%s",
            state.account_url,
            state.status,
            self.config.acme_account_state_path,
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
        LOGGER.debug("Directory mode ensured: path=%s mode=%s", directory, oct(mode))

    def run_pre_activate_hook(self, manifest_path: Path) -> str:
        """Run the configured pre-activation hook for an archived generation.

        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :return: Hook status string.
        :rtype: str
        :raises ManagerError: If the pre-activation hook fails or times out.
        """

        return self.run_lifecycle_hook(
            hook_name="Pre-activate hook",
            command=self.config.pre_activate_hook,
            timeout_seconds=self.config.pre_activate_hook_timeout_seconds,
            manifest_path=manifest_path,
            include_current_links=False,
            fail_on_error=True,
        )

    def run_deploy_hook(self, manifest_path: Path) -> str:
        """Run the configured post-activation deploy hook.

        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :return: Hook status string.
        :rtype: str
        """

        return self.run_lifecycle_hook(
            hook_name="Deploy hook",
            command=self.config.deploy_hook,
            timeout_seconds=self.config.deploy_hook_timeout_seconds,
            manifest_path=manifest_path,
            include_current_links=True,
            fail_on_error=False,
        )

    def run_lifecycle_hook(
        self,
        hook_name: str,
        command: str,
        timeout_seconds: int,
        manifest_path: Path,
        include_current_links: bool,
        fail_on_error: bool,
    ) -> str:
        """Run a configured lifecycle hook.

        :param hook_name: Human-readable hook name.
        :type hook_name: str
        :param command: Hook command string.
        :type command: str
        :param timeout_seconds: Hook timeout.
        :type timeout_seconds: int
        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :param include_current_links: Include live/current environment values.
        :type include_current_links: bool
        :param fail_on_error: Raise when the hook fails.
        :type fail_on_error: bool
        :return: Hook status string.
        :rtype: str
        :raises ManagerError: If a required hook fails or times out.
        """

        if not command:
            LOGGER.info("%s disabled", hook_name)
            return "disabled"
        manifest = read_json(manifest_path)
        environment = self.hook_environment(
            manifest_path, manifest, include_current_links=include_current_links
        )
        LOGGER.info("%s started", hook_name)
        LOGGER.debug(
            "%s invocation: command=%s timeout_seconds=%s manifest_path=%s "
            + "generation_id=%s",
            hook_name,
            command,
            timeout_seconds,
            manifest_path,
            manifest.get("generation_id"),
        )
        result: subprocess.CompletedProcess[str]
        try:
            result = self.run_hook_command(command, environment, timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            self.log_hook_timeout_output(hook_name, exc)
            LOGGER.warning(
                "%s timed out: timeout_seconds=%s", hook_name, timeout_seconds
            )
            if fail_on_error:
                raise ManagerError(
                    f"{hook_name.lower()} timed out after {timeout_seconds} seconds"
                ) from exc
            return "timeout"
        LOGGER.debug(
            "%s completed: returncode=%s stdout_present=%s stderr_present=%s",
            hook_name,
            result.returncode,
            bool(result.stdout.strip()),
            bool(result.stderr.strip()),
        )
        if result.stdout.strip():
            LOGGER.debug("%s stdout:\n%s", hook_name, result.stdout.strip())
        if result.stderr.strip():
            LOGGER.debug("%s stderr:\n%s", hook_name, result.stderr.strip())
        if result.returncode != 0:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            detail = stderr or stdout or f"exit code {result.returncode}"
            LOGGER.warning("%s failed: %s", hook_name, detail)
            if fail_on_error:
                raise ManagerError(f"{hook_name.lower()} failed: {detail}")
            return "failed"
        LOGGER.info("%s succeeded", hook_name)
        return "success"

    def run_hook_command(
        self, command: str, environment: dict[str, str], timeout_seconds: int
    ) -> subprocess.CompletedProcess[str]:
        """Run a lifecycle hook command in its own process group.

        :param command: Hook command string.
        :type command: str
        :param environment: Hook environment.
        :type environment: dict[str, str]
        :param timeout_seconds: Hook timeout.
        :type timeout_seconds: int
        :return: Completed hook process.
        :rtype: subprocess.CompletedProcess[str]
        :raises subprocess.TimeoutExpired: If the hook times out.
        """

        process = subprocess.Popen(
            command,
            env=environment,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            self.terminate_hook_process_group(process)
            stdout, stderr = process.communicate()
            exc.stdout = stdout.encode("utf-8")
            exc.stderr = stderr.encode("utf-8")
            raise
        return subprocess.CompletedProcess(
            args=command,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def terminate_hook_process_group(self, process: subprocess.Popen[str]) -> None:
        """Terminate a lifecycle hook process group after timeout.

        :param process: Hook process.
        :type process: subprocess.Popen[str]
        :return: None.
        :rtype: None
        """

        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return

    def log_hook_timeout_output(
        self, hook_name: str, exc: subprocess.TimeoutExpired
    ) -> None:
        """Log lifecycle hook output captured before a timeout.

        :param hook_name: Human-readable hook name.
        :type hook_name: str
        :param exc: Timeout exception.
        :type exc: subprocess.TimeoutExpired
        :return: None.
        :rtype: None
        """

        stdout = self.timeout_output_text(exc.stdout).strip()
        stderr = self.timeout_output_text(exc.stderr).strip()
        if stdout:
            LOGGER.debug("%s timed out with stdout:\n%s", hook_name, stdout)
        if stderr:
            LOGGER.debug("%s timed out with stderr:\n%s", hook_name, stderr)

    def timeout_output_text(self, output: bytes | None) -> str:
        """Decode captured timeout output for logging.

        :param output: Captured timeout output.
        :type output: bytes | None
        :return: Decoded output.
        :rtype: str
        """

        if output is None:
            return ""
        return output.decode("utf-8", errors="replace")

    def hook_environment(
        self,
        manifest_path: Path,
        manifest: dict[str, Any],
        include_current_links: bool,
    ) -> dict[str, str]:
        """Build lifecycle hook environment values.

        :param manifest_path: Archived manifest path.
        :type manifest_path: Path
        :param manifest: Manifest values.
        :type manifest: dict[str, Any]
        :param include_current_links: Include live/current environment values.
        :type include_current_links: bool
        :return: Hook environment.
        :rtype: dict[str, str]
        """

        environment = dict(os.environ)
        archive_dir = manifest_path.parent
        subject = self.build_subject(str(manifest["generation_id"]))
        live_generation_dir = self.live_generation_dir(str(manifest["generation_id"]))
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
            "SHAKEN_MANIFEST_PATH": manifest_path,
            "SHAKEN_LEAF_CERT_PATH": manifest.get("leaf_certificate_path"),
            "SHAKEN_CHAIN_CERT_PATH": manifest.get("certificate_chain_path"),
            "SHAKEN_CSR_PEM_PATH": archive_dir / "csr.pem",
            "SHAKEN_CSR_DER_PATH": archive_dir / "csr.der",
            "SHAKEN_NOT_BEFORE": manifest.get("not_before"),
            "SHAKEN_NOT_AFTER": manifest.get("not_after"),
            "SHAKEN_FINGERPRINT_SHA256": manifest.get("fingerprint_sha256"),
            "SHAKEN_PREVIOUS_GENERATION_ID": manifest.get("previous_generation_id"),
            "SHAKEN_SUBJECT": manifest.get("subject"),
            "SHAKEN_SUBJECT_COMMON_NAME": subject.common_name,
            "SHAKEN_SUBJECT_COUNTRY": subject.country,
            "SHAKEN_SUBJECT_LOCALITY": subject.locality,
            "SHAKEN_SUBJECT_ORGANIZATION": subject.organization,
            "SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT": subject.organizational_unit,
            "SHAKEN_SUBJECT_STATE": subject.state,
        }
        if include_current_links:
            live_current_dir = self.config.live_dir / "current"
            hook_values.update(
                {
                    "SHAKEN_LIVE_CURRENT_DIR": live_current_dir,
                    "SHAKEN_LIVE_CURRENT_LEAF_CERT_PATH": live_current_dir / "leaf.pem",
                    "SHAKEN_LIVE_CURRENT_CHAIN_CERT_PATH": live_current_dir
                    / "certificate-chain.pem",
                }
            )
        for key, value in hook_values.items():
            environment[key] = "" if value is None else str(value)
        LOGGER.debug(
            "Lifecycle hook environment prepared: keys=%s include_current_links=%s",
            sorted(hook_values),
            include_current_links,
        )
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
        LOGGER.debug(
            "Building manifest: generation_id=%s subject=%s previous_generation_id=%s",
            generation_id,
            subject,
            self.active_generation_id(),
        )
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
            "pre_activate_hook": self.config.pre_activate_hook,
            "pre_activate_hook_status": values["pre_activate_hook_status"],
            "deploy_hook_status": values["deploy_hook_status"],
            "deploy_hook": self.config.deploy_hook,
        }

    def record_failure(
        self,
        command: str,
        generation_id: str,
        transaction_dir: Path,
        started_at: str,
        exc: Exception,
        *,
        active_generation_unchanged: bool,
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
        :param active_generation_unchanged: Whether active generation was unchanged.
        :type active_generation_unchanged: bool
        :return: None.
        :rtype: None
        """

        failed_dir = self.config.failed_dir / generation_id
        if self.config.retain_failed_transactions:
            failed_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            LOGGER.warning(
                "Recording failed issuance: generation_id=%s failed_dir=%s error=%s",
                generation_id,
                failed_dir,
                exc,
            )
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
            LOGGER.debug(
                "Removing failed transaction directory: path=%s", transaction_dir
            )
            shutil.rmtree(transaction_dir)
        self.write_last_attempt(
            command,
            "failed",
            str(exc),
            started_at=started_at,
            generation_id=generation_id,
            active_generation_unchanged=active_generation_unchanged,
        )
        self.prune_failed_archives()
        LOGGER.debug(
            "Failure state recorded: generation_id=%s active_generation_unchanged=%s",
            generation_id,
            active_generation_unchanged,
        )

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
            LOGGER.debug(
                "Validation failure artifacts not retained: generation_id=%s",
                generation_id,
            )
            return
        failed_dir = self.config.failed_dir / generation_id
        failed_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        LOGGER.warning(
            "Retaining validation failure artifacts: generation_id=%s failed_dir=%s",
            generation_id,
            failed_dir,
        )
        atomic_write_bytes(failed_dir / "csr.pem", result.csr_pem, 0o600)
        atomic_write_bytes(failed_dir / "csr.der", result.csr_der, 0o600)
        atomic_write_text(failed_dir / "leaf.pem", result.leaf_pem, 0o600)
        atomic_write_text(failed_dir / "certificate-chain.pem", result.chain_pem, 0o600)
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
        LOGGER.debug(
            "Validation failure artifact archive completed: generation_id=%s",
            generation_id,
        )

    def write_last_attempt(
        self,
        command: str,
        result: str,
        reason: str,
        started_at: str | None = None,
        generation_id: str | None = None,
        *,
        active_generation_unchanged: bool,
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

        LOGGER.debug(
            "Writing last attempt: command=%s result=%s generation_id=%s "
            + "active_generation_unchanged=%s path=%s",
            command,
            result,
            generation_id,
            active_generation_unchanged,
            self.config.last_attempt_path,
        )
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
        removed = 0
        for directory in failed_dirs[self.config.max_failed_transactions_retained :]:
            LOGGER.info("Pruning old failed transaction archive: path=%s", directory)
            shutil.rmtree(directory)
            removed += 1
        LOGGER.debug(
            "Failed transaction pruning completed: retained_limit=%s removed=%s",
            self.config.max_failed_transactions_retained,
            removed,
        )

    def prune_live_links(self) -> None:
        """Remove expired or broken live generation symlink trees.

        :return: None.
        :rtype: None
        """

        if not self.config.live_dir.exists():
            LOGGER.debug("Live directory does not exist; skipping prune")
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
                LOGGER.warning(
                    "Removing live link with missing manifest: generation_id=%s "
                    + "path=%s manifest_path=%s",
                    generation_id,
                    directory,
                    manifest_path,
                )
                self.remove_live_path(directory)
                continue
            try:
                manifest = read_json(manifest_path)
            except (OSError, ValueError, json.JSONDecodeError):
                LOGGER.warning(
                    "Removing live link with unreadable manifest: generation_id=%s "
                    + "path=%s manifest_path=%s",
                    generation_id,
                    directory,
                    manifest_path,
                )
                self.remove_live_path(directory)
                continue
            not_after = parse_timestamp(str(manifest.get("not_after", "")))
            if not_after is None or not_after <= now:
                LOGGER.info(
                    "Removing expired live generation link: generation_id=%s "
                    + "path=%s not_after=%s",
                    generation_id,
                    directory,
                    manifest.get("not_after"),
                )
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
        LOGGER.debug(
            "Creating live generation links: generation_id=%s temporary_dir=%s "
            + "final_dir=%s archive_dir=%s",
            generation_id,
            temporary_dir,
            final_dir,
            archive_dir,
        )
        temporary_dir.mkdir(mode=0o755)
        for name in ["leaf.pem", "certificate-chain.pem"]:
            target = archive_dir / name
            link_target = os.path.relpath(target, start=final_dir)
            (temporary_dir / name).symlink_to(link_target)
            LOGGER.debug(
                "Created temporary live artifact symlink: path=%s target=%s",
                temporary_dir / name,
                link_target,
            )
        os.replace(temporary_dir, final_dir)
        LOGGER.info(
            "Live generation links created: generation_id=%s path=%s",
            generation_id,
            final_dir,
        )

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
        LOGGER.info(
            "Live current symlink updated: generation_id=%s path=%s",
            generation_id,
            current_path,
        )

    def remove_live_generation_links(self, generation_id: str) -> None:
        """Remove a live symlink tree for a generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: None.
        :rtype: None
        """

        LOGGER.debug(
            "Removing live generation links: generation_id=%s",
            generation_id,
        )
        self.remove_live_path(self.live_generation_dir(generation_id))
        self.remove_stale_live_current()

    def remove_stale_live_current(self) -> None:
        """Remove live/current when it points at a missing generation.

        :return: None.
        :rtype: None
        """

        current_path = self.config.live_dir / "current"
        if current_path.is_symlink() and not current_path.exists():
            LOGGER.warning("Removing stale live/current symlink: path=%s", current_path)
            current_path.unlink()

    def remove_live_path(self, path: Path) -> None:
        """Remove a live path without following symlinked directories.

        :param path: Path to remove.
        :type path: Path
        :return: None.
        :rtype: None
        """

        if path.is_symlink() or path.is_file():
            LOGGER.debug("Removing live file or symlink: path=%s", path)
            path.unlink(missing_ok=True)
        elif path.is_dir():
            LOGGER.debug("Removing live directory: path=%s", path)
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
            LOGGER.debug(
                "No active manifest exists: path=%s", self.config.active_manifest_path
            )
            return None
        try:
            return str(read_json(self.config.active_manifest_path).get("generation_id"))
        except (OSError, ValueError) as exc:
            LOGGER.debug(
                "Active manifest unreadable: path=%s error=%s",
                self.config.active_manifest_path,
                exc,
            )
            return None

    def new_generation_id(self) -> str:
        """Create a generation ID.

        :return: Generation ID.
        :rtype: str
        """

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        generation_id = f"{self.config.server_id}-{timestamp}-{secrets.token_hex(5)}"
        LOGGER.debug("Generated certificate generation id: %s", generation_id)
        return generation_id

    def prepare_peeringhub_issuer(self, generation_id: str) -> PeeringhubIssuer:
        """Build a Peeringhub issuer for one certificate generation.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: Peeringhub issuer.
        :rtype: PeeringhubIssuer
        """

        acme_timeout_seconds = (
            self.config.acme_timeout_seconds
            if self.config.acme_timeout_seconds is not None
            else 30
        )
        acme_bad_nonce_retries = (
            self.config.acme_bad_nonce_retries
            if self.config.acme_bad_nonce_retries is not None
            else 2
        )
        acme_poll_interval_seconds = (
            self.config.acme_poll_interval_seconds
            if self.config.acme_poll_interval_seconds is not None
            else 5
        )
        acme_poll_timeout_seconds = (
            self.config.acme_poll_timeout_seconds
            if self.config.acme_poll_timeout_seconds is not None
            else 180
        )
        LOGGER.debug(
            "Prepared Peeringhub issuer settings: generation_id=%s environment=%s "
            + "acme_base_url=%s account_key_path=%s account_state_path=%s "
            + "acme_kid_configured=%s acme_timeout_seconds=%s "
            + "acme_bad_nonce_retries=%s acme_poll_interval_seconds=%s "
            + "acme_poll_timeout_seconds=%s",
            generation_id,
            self.config.peeringhub_environment,
            self.config.acme_url(),
            self.config.acme_account_key_path,
            self.config.acme_account_state_path,
            bool(self.config.acme_kid),
            acme_timeout_seconds,
            acme_bad_nonce_retries,
            acme_poll_interval_seconds,
            acme_poll_timeout_seconds,
        )
        return PeeringhubIssuer.build(
            profile=self.config.peeringhub_profile(),
            account_key_path=self.config.acme_account_key_path,
            account_state_path=self.config.acme_account_state_path,
            acme_kid=self.config.acme_kid,
            stipa_settings=self.stipa_settings(),
            certificate_policy=self.certificate_policy(generation_id),
            acme_timeout_seconds=acme_timeout_seconds,
            acme_bad_nonce_retries=acme_bad_nonce_retries,
            acme_poll_interval_seconds=acme_poll_interval_seconds,
            acme_poll_timeout_seconds=acme_poll_timeout_seconds,
        )

    def prepare_peeringhub_account_issuer(self) -> PeeringhubIssuer:
        """Build a Peeringhub issuer for ACME account state refresh.

        :return: Peeringhub issuer.
        :rtype: PeeringhubIssuer
        """

        timeout_seconds = (
            self.config.acme_timeout_seconds
            if self.config.acme_timeout_seconds is not None
            else 30
        )
        bad_nonce_retries = (
            self.config.acme_bad_nonce_retries
            if self.config.acme_bad_nonce_retries is not None
            else 2
        )
        LOGGER.debug(
            "Prepared Peeringhub account issuer settings: environment=%s "
            + "acme_base_url=%s account_key_path=%s account_state_path=%s "
            + "acme_kid_configured=%s timeout_seconds=%s bad_nonce_retries=%s",
            self.config.peeringhub_environment,
            self.config.acme_url(),
            self.config.acme_account_key_path,
            self.config.acme_account_state_path,
            bool(self.config.acme_kid),
            timeout_seconds,
            bad_nonce_retries,
        )
        return PeeringhubIssuer.for_account_status(
            environment=self.config.peeringhub_environment,
            acme_base_url=self.config.acme_url(),
            account_key_path=self.config.acme_account_key_path,
            account_state_path=self.config.acme_account_state_path,
            acme_kid=self.config.acme_kid,
            timeout_seconds=timeout_seconds,
            bad_nonce_retries=bad_nonce_retries,
        )

    def stipa_settings(self) -> StipaSettings:
        """Build reusable STI-PA settings from manager configuration.

        :return: STI-PA settings.
        :rtype: StipaSettings
        """

        timeout_seconds = (
            self.config.stipa_timeout_seconds
            if self.config.stipa_timeout_seconds is not None
            else 30
        )
        minimum_token_lifetime_seconds = (
            self.config.acme_poll_timeout_seconds
            if self.config.acme_poll_timeout_seconds is not None
            else 180
        )
        LOGGER.debug(
            "Prepared STI-PA settings: base_url=%s sp_id=%s user_id_configured=%s "
            + "expected_crl_url=%s timeout_seconds=%s ca=%s "
            + "minimum_token_lifetime_seconds=%s",
            self.config.stipa_url(),
            self.config.stipa_sp_id,
            bool(self.config.stipa_user_id),
            self.config.expected_crl_url(),
            timeout_seconds,
            False,
            minimum_token_lifetime_seconds,
        )
        return StipaSettings(
            base_url=self.config.stipa_url(),
            user_id=self.config.stipa_user_id,
            password=self.config.stipa_password,
            sp_id=self.config.stipa_sp_id,
            expected_crl_url=self.config.expected_crl_url(),
            timeout_seconds=timeout_seconds,
            ca=False,
            minimum_token_lifetime_seconds=minimum_token_lifetime_seconds,
        )

    def certificate_policy(self, generation_id: str) -> ShakenCertificatePolicy:
        """Build reusable SHAKEN certificate policy.

        :param generation_id: Generation ID.
        :type generation_id: str
        :return: Certificate policy.
        :rtype: ShakenCertificatePolicy
        """

        subject = self.build_subject(generation_id)
        LOGGER.debug(
            "Prepared certificate policy: generation_id=%s subject=%s "
            + "expected_crl_url=%s minimum_certificate_lifetime_days=%s "
            + "include_crl_distribution_points=%s",
            generation_id,
            subject.to_x509_name().rfc4514_string(),
            self.config.expected_crl_url(),
            self.config.minimum_certificate_lifetime_days,
            self.config.include_crl_distribution_points,
        )
        return ShakenCertificatePolicy(
            subject=subject,
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

        organization = self.config.shaken_subject_organization
        template_values = {
            "generation_id": generation_id,
            "server_id": self.config.server_id,
            "stipa_spc": self.config.stipa_spc,
            "organization": organization,
        }
        if self.config.shaken_subject_common_name_template:
            common_name = render_subject_template(
                self.config.shaken_subject_common_name_template, template_values
            )
        elif self.config.subject_strategy == "stable_common_name":
            common_name = f"SHAKEN {self.config.stipa_spc}"
        else:
            common_name = f"SHAKEN {self.config.stipa_spc} {self.config.server_id} {generation_id}"
        subject = ShakenSubject(
            country=self.config.shaken_subject_country,
            state=self.config.shaken_subject_state,
            locality=self.config.shaken_subject_locality,
            organization=organization,
            organizational_unit=self.config.shaken_subject_organizational_unit,
            common_name=common_name,
        )
        LOGGER.debug(
            "Built certificate subject: generation_id=%s common_name=%s "
            + "organization=%s strategy=%s",
            generation_id,
            common_name,
            organization,
            self.config.subject_strategy,
        )
        return subject


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
