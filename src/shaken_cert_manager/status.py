"""Runtime status and Nagios output for SHAKEN certificates."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from stir_shaken_acme import ShakenCertificateManager
from stir_shaken_acme.errors import ShakenValidationError

from shaken_cert_manager.config import ManagerConfig
from shaken_cert_manager.files import read_json

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3
LOGGER = logging.getLogger(__name__)


@dataclass
class StatusResult:
    """Status result for human, JSON, and Nagios output."""

    code: int
    summary: str
    fields: dict[str, Any]

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
        details = " ".join(
            f"{key}={value}"
            for key, value in self.fields.items()
            if value not in {None, ""}
        )
        return f"SHAKEN CERTIFICATE {label}: {self.summary} | {details}"


class StatusChecker:
    """Check active SHAKEN certificate state."""

    def __init__(self, config: ManagerConfig) -> None:
        self.config = config
        self.certificates = ShakenCertificateManager()

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
        try:
            manifest = read_json(self.config.active_manifest_path)
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
            self.certificates.require_key_match(certificate, private_key)
            days_remaining = (certificate.not_valid_after_utc - datetime.now(UTC)).days
            fields = {
                **base_fields,
                "generation_id": manifest.get("generation_id"),
                "serial_number": manifest.get("serial_number"),
                "not_after": manifest.get("not_after"),
                "days_remaining": days_remaining,
                "active_private_key_path": str(key_path),
                "leaf_certificate_path": str(certificate_path),
                "certificate_chain_path": manifest.get("certificate_chain_path"),
                "live_current_path": str(self.config.live_dir / "current"),
                "live_current_generation_id": self.live_current_generation_id(),
                "live_certificate_chain_path": manifest.get(
                    "live_certificate_chain_path"
                ),
                "deploy_hook_status": manifest.get("deploy_hook_status"),
                "last_successful_renewal": manifest.get("installed_at"),
                "last_attempt_result": self.last_attempt_result(),
                "renewal_threshold_days": self.config.renew_before_days,
            }
            if days_remaining <= self.config.minimum_certificate_lifetime_days:
                result = StatusResult(
                    CRITICAL, f"certificate expires in {days_remaining} days", fields
                )
                LOGGER.debug(
                    "Status check completed: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                return result
            if days_remaining <= self.config.warning_days:
                result = StatusResult(
                    WARNING, f"certificate expires in {days_remaining} days", fields
                )
                LOGGER.debug(
                    "Status check completed: code=%s summary=%s",
                    result.code,
                    result.summary,
                )
                return result
            if self.last_attempt_failed_and_due(days_remaining):
                result = StatusResult(
                    WARNING, "last renewal attempt failed while renewal is due", fields
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
            )
            LOGGER.debug(
                "Status check completed: code=%s summary=%s days_remaining=%s",
                result.code,
                result.summary,
                days_remaining,
            )
            return result
        except (
            KeyError,
            OSError,
            ValueError,
            ShakenValidationError,
        ) as exc:
            result = StatusResult(CRITICAL, str(exc), base_fields)
            LOGGER.debug(
                "Status check completed: code=%s summary=%s",
                result.code,
                result.summary,
            )
            return result

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
