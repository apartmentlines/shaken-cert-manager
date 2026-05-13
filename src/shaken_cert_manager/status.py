"""Runtime status and Nagios output for SHAKEN certificates."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from stir_shaken_acme import CertificateInspector, ShakenCertificateManager
from stir_shaken_acme.errors import ShakenValidationError

from shaken_cert_manager.config import ManagerConfig
from shaken_cert_manager.files import read_json

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3
LOGGER = logging.getLogger(__name__)


class LiveLinksInvalidError(Exception):
    """Raised when active certificate live links are invalid."""


@dataclass
class StatusResult:
    """Status result for human, JSON, and Nagios output."""

    code: int
    summary: str
    fields: dict[str, Any]
    perfdata: list[str] = field(default_factory=list)

    def nagios_line(self) -> str:
        """Return Nagios plugin output.

        :return: Nagios line.
        :rtype: str
        """

        label = {
            OK: "OK",
            WARNING: "WARNING",
            CRITICAL: "CRITICAL",
            UNKNOWN: "UNKNOWN",
        }.get(self.code, "UNKNOWN")
        context = "; ".join(self.nagios_context())
        message = f"SHAKEN CERTIFICATE {label}: {self.summary}"
        if context:
            message = f"{message}; {context}"
        if self.perfdata:
            message = f"{message} | {' '.join(self.perfdata)}"
        return message

    def nagios_context(self) -> list[str]:
        """Return concise non-sensitive context for Nagios human output.

        :return: Human context fields.
        :rtype: list[str]
        """

        context = []
        generation_id = self.fields.get("generation_id")
        if generation_id not in {None, ""}:
            context.append(f"generation={generation_id}")
        not_after = self.fields.get("not_after")
        if not_after not in {None, ""}:
            context.append(f"expires={not_after}")
        pre_activate_hook_status = self.fields.get("pre_activate_hook_status")
        if pre_activate_hook_status not in {None, "", "success"}:
            context.append(f"pre_activate_hook={pre_activate_hook_status}")
        deploy_hook_status = self.fields.get("deploy_hook_status")
        if deploy_hook_status not in {None, "", "success"}:
            context.append(f"deploy_hook={deploy_hook_status}")
        last_attempt_result = self.fields.get("last_attempt_result")
        if last_attempt_result == "failed":
            context.append("last_attempt=failed")
        return context


class StatusChecker:
    """Check active SHAKEN certificate state."""

    def __init__(self, config: ManagerConfig) -> None:
        self.config: ManagerConfig = config
        self.certificates: ShakenCertificateManager = ShakenCertificateManager()
        self.inspector: CertificateInspector = CertificateInspector()

    def check(self) -> StatusResult:
        """Check active certificate status.

        :return: Status result.
        :rtype: StatusResult
        """

        base_fields = {
            "server_id": self.config.server_id,
            "peeringhub_environment": self.config.peeringhub_environment,
            "stipa_spc": self.config.stipa_spc,
        }
        LOGGER.debug(
            "Status check started: active_manifest_path=%s live_dir=%s enabled=%s",
            self.config.active_manifest_path,
            self.config.live_dir,
            self.config.enabled,
        )
        if not self.config.enabled:
            result = StatusResult(
                OK,
                "SHAKEN certificate management disabled",
                base_fields,
            )
            LOGGER.debug(
                "Status check completed: code=%s summary=%s",
                result.code,
                result.summary,
            )
            return result
        if not self.config.active_manifest_path.exists():
            result = StatusResult(
                CRITICAL,
                "no active certificate exists",
                base_fields,
            )
            LOGGER.debug(
                "Status check completed: code=%s summary=%s",
                result.code,
                result.summary,
            )
            return result
        manifest: dict[str, Any] = {}
        generation_id: str | None = None
        live_current_generation_id: str | None = None
        try:
            manifest = read_json(self.config.active_manifest_path)
            generation_id = str(manifest["generation_id"])
            certificate_path = Path(str(manifest["leaf_certificate_path"]))
            key_path = Path(str(manifest["certificate_private_key_path"]))
            LOGGER.debug(
                "Status check loading active material: generation_id=%s "
                + "certificate_path=%s key_path=%s",
                manifest.get("generation_id"),
                certificate_path,
                key_path,
            )
            certificate = self.certificates.parse_certificate(
                certificate_path.read_bytes()
            )
            private_key = self.certificates.load_certificate_key(key_path)
            self.certificates.require_certificate_private_key_match(
                certificate, private_key
            )
            inspection = self.inspector.inspect_certificate(certificate).as_dict()
            days_remaining = (certificate.not_valid_after_utc - datetime.now(UTC)).days
            live_current_generation_id = self.live_current_generation_id()
            fields = {
                **base_fields,
                "generation_id": generation_id,
                **self.certificate_status_fields(inspection),
                "days_remaining": days_remaining,
                "active_private_key_path": str(key_path),
                "leaf_certificate_path": str(certificate_path),
                "certificate_chain_path": manifest.get("certificate_chain_path"),
                "live_current_path": str(self.config.live_dir / "current"),
                "live_current_generation_id": live_current_generation_id,
                "live_certificate_chain_path": manifest.get(
                    "live_certificate_chain_path"
                ),
                "pre_activate_hook_status": manifest.get("pre_activate_hook_status"),
                "deploy_hook_status": manifest.get("deploy_hook_status"),
                "last_successful_activation": manifest.get("installed_at"),
                "last_attempt_result": self.last_attempt_result(),
                "renewal_threshold_days": self.config.renew_before_days,
            }
            self.require_live_links(generation_id, live_current_generation_id)
            if days_remaining <= self.config.minimum_certificate_lifetime_days:
                result = StatusResult(
                    CRITICAL,
                    f"certificate expires in {days_remaining} days",
                    fields,
                    perfdata=self.days_remaining_perfdata(days_remaining),
                )
                LOGGER.debug(
                    "Status check completed: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                return result
            if days_remaining <= self.config.warning_days:
                result = StatusResult(
                    WARNING,
                    f"certificate expires in {days_remaining} days",
                    fields,
                    perfdata=self.days_remaining_perfdata(days_remaining),
                )
                LOGGER.debug(
                    "Status check completed: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                return result
            if self.last_attempt_failed_and_due(days_remaining):
                result = StatusResult(
                    WARNING,
                    "last renewal attempt failed while renewal is due",
                    fields,
                    perfdata=self.days_remaining_perfdata(days_remaining),
                )
                LOGGER.debug(
                    "Status check completed: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                return result
            result = StatusResult(
                OK,
                f"certificate valid for {days_remaining} days",
                fields,
                perfdata=self.days_remaining_perfdata(days_remaining),
            )
            LOGGER.debug(
                "Status check completed: code=%s summary=%s days_remaining=%s",
                result.code,
                result.summary,
                days_remaining,
            )
            return result
        except LiveLinksInvalidError as exc:
            fields = {
                **base_fields,
                "generation_id": generation_id,
                "not_after": manifest.get("not_after"),
                "live_current_generation_id": live_current_generation_id,
            }
            result = StatusResult(
                CRITICAL,
                "active certificate live links are invalid",
                fields,
            )
            LOGGER.debug("Status live link validation failed: %s", exc, exc_info=True)
            LOGGER.debug(
                "Status check completed: code=%s summary=%s",
                result.code,
                result.summary,
            )
            return result
        except (
            KeyError,
            OSError,
            ValueError,
            ShakenValidationError,
        ) as exc:
            result = StatusResult(
                CRITICAL,
                "active certificate state is invalid",
                base_fields,
            )
            LOGGER.debug("Status check failed: %s", exc, exc_info=True)
            LOGGER.debug(
                "Status check completed: code=%s summary=%s",
                result.code,
                result.summary,
            )
            return result

    def certificate_status_fields(self, inspection: dict[str, Any]) -> dict[str, Any]:
        """Return status fields derived from the active certificate.

        :param inspection: Certificate inspection data.
        :type inspection: dict[str, Any]
        :return: Status fields.
        :rtype: dict[str, Any]
        """

        return {
            "serial_number": inspection.get("serial_number"),
            "subject": inspection.get("subject_rfc4514"),
            "issuer": inspection.get("issuer_rfc4514"),
            "not_before": inspection.get("not_before"),
            "not_after": inspection.get("not_after"),
            "fingerprint_sha256": inspection.get("fingerprint_sha256"),
            "public_key_fingerprint_sha256": inspection.get(
                "public_key_fingerprint_sha256"
            ),
            "subject_key_identifier": inspection.get("subject_key_identifier"),
            "authority_key_identifier": inspection.get("authority_key_identifier"),
            "certificate_policy_oids": inspection.get("certificate_policy_oids", []),
            "crl_distribution_points": inspection.get("crl_distribution_points", []),
            "tn_auth_list_spc": inspection.get("tn_auth_list_spc"),
        }

    def last_attempt_result(self) -> str | None:
        """Return the last attempt result.

        :return: Result or ``None``.
        :rtype: str | None
        """

        if not self.config.last_attempt_path.exists():
            return None
        try:
            return str(read_json(self.config.last_attempt_path).get("result"))
        except (OSError, ValueError, json.JSONDecodeError):
            return "unreadable"

    def days_remaining_perfdata(self, days_remaining: int) -> list[str]:
        """Return Nagios perfdata for active certificate lifetime.

        :param days_remaining: Active certificate days remaining.
        :type days_remaining: int
        :return: Perfdata fields.
        :rtype: list[str]
        """

        return [
            "days_remaining="
            + f"{days_remaining};{self.config.warning_days};"
            + f"{self.config.minimum_certificate_lifetime_days};0"
        ]

    def last_attempt_failed_and_due(self, days_remaining: int) -> bool:
        """Return whether a failed last attempt matters now.

        :param days_remaining: Active certificate days remaining.
        :type days_remaining: int
        :return: Whether warning is needed.
        :rtype: bool
        """

        return (
            self.last_attempt_result() == "failed"
            and days_remaining <= self.config.renew_before_days
        )

    def live_current_generation_id(self) -> str | None:
        """Return the current live generation target.

        :return: Generation ID or ``None``.
        :rtype: str | None
        """

        current_path = self.config.live_dir / "current"
        if not current_path.is_symlink():
            return None
        return current_path.readlink().name

    def require_live_links(
        self,
        generation_id: str,
        live_current_generation_id: str | None,
    ) -> None:
        """Require live/current and live certificate links to match active state.

        :param generation_id: Active generation ID from active manifest.
        :type generation_id: str
        :param live_current_generation_id: Live current generation ID.
        :type live_current_generation_id: str | None
        :return: None.
        :rtype: None
        :raises LiveLinksInvalidError: When live links are invalid.
        """

        current_path = self.config.live_dir / "current"
        if live_current_generation_id is None:
            raise LiveLinksInvalidError(f"live/current is missing: {current_path}")
        if live_current_generation_id != generation_id:
            raise LiveLinksInvalidError(
                "live/current generation mismatch: "
                + f"active={generation_id} live_current={live_current_generation_id}"
            )
        live_generation_dir = self.config.live_dir / generation_id
        if not live_generation_dir.is_dir():
            raise LiveLinksInvalidError(
                f"live generation directory is missing: {live_generation_dir}"
            )
        for artifact_name in ["leaf.pem", "certificate-chain.pem"]:
            artifact_path = live_generation_dir / artifact_name
            if not artifact_path.exists():
                raise LiveLinksInvalidError(
                    f"live certificate artifact is missing: {artifact_path}"
                )
            if not artifact_path.is_symlink():
                raise LiveLinksInvalidError(
                    f"live certificate artifact is not a symlink: {artifact_path}"
                )
