"""Configuration loading for the SHAKEN certificate manager."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import yaml
from stir_shaken_toolkit.providers.peeringhub import PeeringhubProfile

from shaken_cert_manager.errors import ConfigError

REDACTED_VALUE = "[redacted]"
ENVIRONMENT_OVERRIDES = {
    "peeringhub_environment": "PEERINGHUB_ENVIRONMENT",
    "server_id": "SHAKEN_SERVER_ID",
    "stipa_spc": "STIPA_SPC",
    "stipa_sp_id": "STIPA_SP_ID",
    "stipa_user_id": "STIPA_USER_ID",
    "stipa_password": "STIPA_PASSWORD",
    "shaken_subject_country": "SHAKEN_SUBJECT_COUNTRY",
    "shaken_subject_state": "SHAKEN_SUBJECT_STATE",
    "shaken_subject_locality": "SHAKEN_SUBJECT_LOCALITY",
    "shaken_subject_organization": "SHAKEN_SUBJECT_ORGANIZATION",
    "shaken_subject_organizational_unit": "SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT",
    "shaken_subject_common_name_template": "SHAKEN_SUBJECT_COMMON_NAME_TEMPLATE",
    "subject_strategy": "SHAKEN_SUBJECT_STRATEGY",
    "acme_base_url_override": "PEERINGHUB_ACME_BASE_URL_OVERRIDE",
    "acme_kid": "ACME_KID",
    "account_dir": "ACME_ACCOUNT_DIR",
    "acme_account_key_path": "ACME_ACCOUNT_KEY_PATH",
    "acme_account_state_path": "ACME_ACCOUNT_STATE_PATH",
    "stipa_base_url_override": "STIPA_BASE_URL_OVERRIDE",
    "stipa_crl_url_override": "STIPA_CRL_URL_OVERRIDE",
    "not_before": "SHAKEN_NOT_BEFORE",
    "not_after": "SHAKEN_NOT_AFTER",
    "minimum_certificate_lifetime_days": "SHAKEN_MINIMUM_CERTIFICATE_LIFETIME_DAYS",
}


@dataclass
class ManagerConfig:
    """Runtime configuration for SHAKEN certificate management."""

    enabled: bool
    peeringhub_environment: str
    server_id: str
    stipa_spc: str
    stipa_sp_id: str
    shaken_subject_country: str
    shaken_subject_state: str
    shaken_subject_locality: str
    shaken_subject_organization: str
    stipa_user_id: str
    stipa_password: str
    shaken_subject_organizational_unit: str
    subject_strategy: str
    shaken_subject_common_name_template: str
    acme_base_url_override: str | None
    acme_kid: str
    acme_account_key_path: Path
    acme_account_state_path: Path
    acme_timeout_seconds: int | None
    acme_poll_interval_seconds: int | None
    acme_poll_timeout_seconds: int | None
    acme_bad_nonce_retries: int | None
    stipa_base_url_override: str | None
    stipa_timeout_seconds: int | None
    stipa_crl_url_override: str | None
    not_before: str | None
    not_after: str | None
    renew_before_days: int
    warning_days: int
    minimum_certificate_lifetime_days: int
    retention_days_after_expiry: int
    pre_activate_hook: str
    pre_activate_hook_timeout_seconds: int
    deploy_hook: str
    deploy_hook_timeout_seconds: int
    retain_failed_transactions: bool
    max_failed_transactions_retained: int
    include_crl_distribution_points: bool
    state_dir: Path = Path("/var/lib/shaken")
    work_dir: Path = Path("/var/lib/shaken/work")
    archive_dir: Path = Path("/var/lib/shaken/archive")
    live_dir: Path = Path("/var/lib/shaken/live")
    failed_dir: Path = Path("/var/lib/shaken/failed")
    account_dir: Path = Path("/var/lib/shaken/account")
    active_manifest_path: Path = Path("/var/lib/shaken/active.json")
    last_attempt_path: Path = Path("/var/lib/shaken/last-attempt.json")
    lock_path: Path = Path("/var/lib/shaken/shaken-cert-manager.lock")
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> ManagerConfig:
        """Load configuration from a private YAML file.

        :param path: Configuration path.
        :type path: Path
        :return: Loaded configuration.
        :rtype: ManagerConfig
        :raises ConfigError: If configuration is invalid.
        """

        if not path.exists():
            raise ConfigError(f"Configuration file is missing: {path}")
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ConfigError(
                f"Configuration file must not be group/world accessible: {path}"
            )
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"Configuration YAML failed: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError("Configuration root must be a mapping")
        config = cls.from_mapping(data)
        config.validate()
        return config

    @classmethod
    def from_mapping(
        cls,
        data: dict[str, Any],
        env: Mapping[str, str] | None = None,
    ) -> ManagerConfig:
        """Build configuration from a mapping.

        :param data: Configuration mapping.
        :type data: dict[str, Any]
        :param env: Optional environment mapping.
        :type env: Mapping[str, str] | None
        :return: Loaded configuration.
        :rtype: ManagerConfig
        """

        resolver = ConfigValueResolver(data, os.environ if env is None else env)
        server_id = resolver.string("server_id", "")
        peeringhub_environment = resolver.string("peeringhub_environment", "production")
        stipa_spc = resolver.string("stipa_spc", "")
        state_dir = Path(string_value(data, "state_dir", "/var/lib/shaken"))
        account_dir = resolver.path("account_dir", str(state_dir / "account"))
        return cls(
            enabled=bool(data.get("enabled", True)),
            peeringhub_environment=peeringhub_environment,
            server_id=server_id,
            stipa_spc=stipa_spc,
            stipa_sp_id=resolver.string("stipa_sp_id", stipa_spc),
            shaken_subject_country=resolver.string("shaken_subject_country", "US"),
            shaken_subject_state=resolver.string("shaken_subject_state", ""),
            shaken_subject_locality=resolver.string("shaken_subject_locality", ""),
            shaken_subject_organization=resolver.string(
                "shaken_subject_organization", ""
            ),
            stipa_user_id=resolver.string("stipa_user_id", ""),
            stipa_password=resolver.string("stipa_password", ""),
            shaken_subject_organizational_unit=resolver.string(
                "shaken_subject_organizational_unit", "VoIP"
            ),
            subject_strategy=resolver.string(
                "subject_strategy", "unique_per_generation"
            ),
            shaken_subject_common_name_template=resolver.string(
                "shaken_subject_common_name_template", ""
            ),
            acme_base_url_override=resolver.optional_string("acme_base_url_override"),
            acme_kid=resolver.string("acme_kid", ""),
            acme_account_key_path=Path(
                resolver.string(
                    "acme_account_key_path",
                    str(account_dir / "account.key"),
                )
            ),
            acme_account_state_path=Path(
                resolver.string(
                    "acme_account_state_path",
                    str(account_dir / "account.json"),
                )
            ),
            acme_timeout_seconds=resolver.optional_integer("acme_timeout_seconds"),
            acme_poll_interval_seconds=resolver.optional_integer(
                "acme_poll_interval_seconds"
            ),
            acme_poll_timeout_seconds=resolver.optional_integer(
                "acme_poll_timeout_seconds"
            ),
            acme_bad_nonce_retries=resolver.optional_integer("acme_bad_nonce_retries"),
            stipa_base_url_override=resolver.optional_string("stipa_base_url_override"),
            stipa_timeout_seconds=resolver.optional_integer("stipa_timeout_seconds"),
            stipa_crl_url_override=resolver.optional_string("stipa_crl_url_override"),
            not_before=resolver.optional_string("not_before"),
            not_after=resolver.optional_string("not_after"),
            renew_before_days=int(data.get("renew_before_days", 45)),
            warning_days=int(data.get("warning_days", 52)),
            minimum_certificate_lifetime_days=resolver.integer(
                "minimum_certificate_lifetime_days", 21
            ),
            retention_days_after_expiry=int(
                data.get("retention_days_after_expiry", 30)
            ),
            pre_activate_hook=string_value(data, "pre_activate_hook", ""),
            pre_activate_hook_timeout_seconds=int(
                data.get("pre_activate_hook_timeout_seconds", 60)
            ),
            deploy_hook=string_value(data, "deploy_hook", ""),
            deploy_hook_timeout_seconds=int(
                data.get("deploy_hook_timeout_seconds", 60)
            ),
            retain_failed_transactions=bool(
                data.get("retain_failed_transactions", True)
            ),
            max_failed_transactions_retained=int(
                data.get("max_failed_transactions_retained", 10)
            ),
            include_crl_distribution_points=bool(
                data.get("include_crl_distribution_points", False)
            ),
            state_dir=state_dir,
            work_dir=Path(string_value(data, "work_dir", str(state_dir / "work"))),
            archive_dir=Path(
                string_value(data, "archive_dir", str(state_dir / "archive"))
            ),
            live_dir=Path(string_value(data, "live_dir", str(state_dir / "live"))),
            failed_dir=Path(
                string_value(data, "failed_dir", str(state_dir / "failed"))
            ),
            account_dir=account_dir,
            active_manifest_path=Path(
                string_value(
                    data, "active_manifest_path", str(state_dir / "active.json")
                )
            ),
            last_attempt_path=Path(
                string_value(
                    data, "last_attempt_path", str(state_dir / "last-attempt.json")
                )
            ),
            lock_path=Path(
                string_value(
                    data, "lock_path", str(state_dir / "shaken-cert-manager.lock")
                )
            ),
            raw=data,
        )

    def validate(self) -> None:
        """Validate configuration values.

        :return: None.
        :rtype: None
        :raises ConfigError: If required values are invalid.
        """

        if self.peeringhub_environment not in {"staging", "production"}:
            raise ConfigError("peeringhub_environment must be staging or production")
        if not self.server_id:
            raise ConfigError("server_id is required")
        if self.shaken_subject_country != "US":
            raise ConfigError("shaken_subject_country must be US for Peeringhub")
        if self.subject_strategy not in {"unique_per_generation", "stable_common_name"}:
            raise ConfigError(
                "subject_strategy must be unique_per_generation or stable_common_name"
            )
        if self.enabled:
            required_fields = {
                "stipa_spc": self.stipa_spc,
                "stipa_sp_id": self.stipa_sp_id,
                "shaken_subject_state": self.shaken_subject_state,
                "shaken_subject_locality": self.shaken_subject_locality,
                "shaken_subject_organization": self.shaken_subject_organization,
                "stipa_user_id": self.stipa_user_id,
                "stipa_password": self.stipa_password,
                "acme_kid": self.acme_kid,
            }
            missing = [name for name, value in required_fields.items() if not value]
            if missing:
                raise ConfigError(
                    f"Missing required enabled configuration fields: {', '.join(missing)}"
                )

    def sanitized_summary(self) -> dict[str, Any]:
        """Return a log-safe configuration summary.

        :return: Sanitized configuration values.
        :rtype: dict[str, Any]
        """

        return {
            "enabled": self.enabled,
            "peeringhub_environment": self.peeringhub_environment,
            "server_id": self.server_id,
            "stipa_spc": self.stipa_spc,
            "stipa_sp_id": self.stipa_sp_id,
            "stipa_user_id_configured": bool(self.stipa_user_id),
            "stipa_password": REDACTED_VALUE if self.stipa_password else "",
            "acme_kid_configured": bool(self.acme_kid),
            "acme_account_key_path": str(self.acme_account_key_path),
            "acme_account_state_path": str(self.acme_account_state_path),
            "acme_base_url": self.acme_url(),
            "stipa_base_url": self.stipa_url(),
            "stipa_crl_url": self.expected_crl_url(),
            "acme_timeout_seconds": self.acme_timeout_seconds,
            "acme_poll_interval_seconds": self.acme_poll_interval_seconds,
            "acme_poll_timeout_seconds": self.acme_poll_timeout_seconds,
            "acme_bad_nonce_retries": self.acme_bad_nonce_retries,
            "stipa_timeout_seconds": self.stipa_timeout_seconds,
            "subject_strategy": self.subject_strategy,
            "renew_before_days": self.renew_before_days,
            "warning_days": self.warning_days,
            "minimum_certificate_lifetime_days": (
                self.minimum_certificate_lifetime_days
            ),
            "retention_days_after_expiry": self.retention_days_after_expiry,
            "pre_activate_hook_configured": bool(self.pre_activate_hook),
            "pre_activate_hook_timeout_seconds": (
                self.pre_activate_hook_timeout_seconds
            ),
            "deploy_hook_configured": bool(self.deploy_hook),
            "deploy_hook_timeout_seconds": self.deploy_hook_timeout_seconds,
            "retain_failed_transactions": self.retain_failed_transactions,
            "max_failed_transactions_retained": (self.max_failed_transactions_retained),
            "include_crl_distribution_points": self.include_crl_distribution_points,
            "state_dir": str(self.state_dir),
            "work_dir": str(self.work_dir),
            "archive_dir": str(self.archive_dir),
            "live_dir": str(self.live_dir),
            "failed_dir": str(self.failed_dir),
            "account_dir": str(self.account_dir),
            "active_manifest_path": str(self.active_manifest_path),
            "last_attempt_path": str(self.last_attempt_path),
            "lock_path": str(self.lock_path),
        }

    def peeringhub_profile(self) -> PeeringhubProfile:
        """Return the configured Peeringhub provider profile.

        :return: Peeringhub provider profile.
        :rtype: PeeringhubProfile
        """

        defaults = PeeringhubProfile.for_environment(self.peeringhub_environment)
        return PeeringhubProfile(
            environment=defaults.environment,
            acme_base_url=self.acme_base_url_override or defaults.acme_base_url,
            stipa_base_url=self.stipa_base_url_override or defaults.stipa_base_url,
            stipa_crl_url=self.stipa_crl_url_override or defaults.stipa_crl_url,
            tn_auth_list_encoding=defaults.tn_auth_list_encoding,
        )

    def acme_url(self) -> str:
        """Return the configured ACME URL for this Peeringhub environment.

        :return: ACME URL.
        :rtype: str
        """

        return self.peeringhub_profile().acme_base_url

    def stipa_url(self) -> str:
        """Return the configured STI-PA URL for this Peeringhub environment.

        :return: STI-PA URL.
        :rtype: str
        """

        return self.peeringhub_profile().stipa_base_url

    def expected_crl_url(self) -> str:
        """Return the configured STI-PA CRL URL for this Peeringhub environment.

        :return: CRL URL.
        :rtype: str
        """

        return self.peeringhub_profile().stipa_crl_url


def string_value(data: dict[str, Any], key: str, default: str) -> str:
    """Return a string config value.

    :param data: Config mapping.
    :type data: dict[str, Any]
    :param key: Config key.
    :type key: str
    :param default: Default value.
    :type default: str
    :return: Config value.
    :rtype: str
    """

    value = data.get(key, default)
    return "" if value is None else str(value)


class ConfigValueResolver:
    """Resolve manager values from environment, config, and built-in defaults."""

    def __init__(self, data: dict[str, Any], env: Mapping[str, str]) -> None:
        """Initialize the resolver.

        :param data: Config mapping.
        :type data: dict[str, Any]
        :param env: Environment mapping.
        :type env: Mapping[str, str]
        """

        self.data: dict[str, Any] = data
        self.env: Mapping[str, str] = env

    def value(self, key: str, default: object = None) -> object:
        """Resolve one value.

        :param key: Config key.
        :type key: str
        :param default: Default value.
        :type default: object
        :return: Resolved value.
        :rtype: object
        """

        env_name = ENVIRONMENT_OVERRIDES.get(key)
        if env_name is not None and self.env.get(env_name, "") != "":
            return self.env[env_name]
        if key in self.data and not self.is_blank(self.data[key]):
            return self.data[key]
        return default

    def string(self, key: str, default: str) -> str:
        """Resolve one string value.

        :param key: Config key.
        :type key: str
        :param default: Default value.
        :type default: str
        :return: Resolved string.
        :rtype: str
        """

        value = self.value(key, default)
        return "" if value is None else str(value)

    def optional_string(self, key: str) -> str | None:
        """Resolve one optional string value.

        :param key: Config key.
        :type key: str
        :return: Resolved string or ``None``.
        :rtype: str | None
        """

        value = self.value(key)
        return None if self.is_blank(value) else str(value)

    def integer(self, key: str, default: int) -> int:
        """Resolve one integer value.

        :param key: Config key.
        :type key: str
        :param default: Default value.
        :type default: int
        :return: Resolved integer.
        :rtype: int
        :raises ConfigError: If the value is not an integer.
        """

        value = self.value(key, default)
        try:
            return int(cast(Any, value))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{key} must be an integer") from exc

    def optional_integer(self, key: str) -> int | None:
        """Resolve one optional integer value.

        :param key: Config key.
        :type key: str
        :return: Resolved integer or ``None``.
        :rtype: int | None
        :raises ConfigError: If the value is not an integer.
        """

        value = self.value(key)
        if self.is_blank(value):
            return None
        try:
            return int(cast(Any, value))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{key} must be an integer") from exc

    def path(self, key: str, default: str) -> Path:
        """Resolve one path value.

        :param key: Config key.
        :type key: str
        :param default: Default path.
        :type default: str
        :return: Resolved path.
        :rtype: Path
        """

        return Path(self.string(key, default))

    def is_blank(self, value: object) -> bool:
        """Return whether a value should be treated as unset.

        :param value: Candidate value.
        :type value: object
        :return: Whether the value is unset.
        :rtype: bool
        """

        return value is None or value == ""
