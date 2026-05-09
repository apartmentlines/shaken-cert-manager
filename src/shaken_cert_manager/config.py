"""Configuration loading for the SHAKEN certificate manager."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from shaken_cert_manager.errors import ConfigError

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
    "shaken_subject_organization_template": "SHAKEN_SUBJECT_ORGANIZATION_TEMPLATE",
    "subject_strategy": "SHAKEN_SUBJECT_STRATEGY",
    "acme_kid": "ACME_KID",
    "account_dir": "ACME_ACCOUNT_DIR",
    "acme_account_key_path": "ACME_ACCOUNT_KEY_PATH",
    "acme_account_state_path": "ACME_ACCOUNT_STATE_PATH",
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
    shaken_subject_organization_template: str
    acme_base_url: dict[str, str]
    acme_kid: str
    acme_account_key_path: Path
    acme_account_state_path: Path
    acme_timeout_seconds: int
    acme_poll_interval_seconds: int
    acme_poll_timeout_seconds: int
    acme_bad_nonce_retries: int
    stipa_base_url: dict[str, str]
    stipa_timeout_seconds: int
    stipa_crl_url: dict[str, str]
    stipa_ca: bool
    certificate_lifetime_mode: str
    not_before: str | None
    not_after: str | None
    renew_before_days: int
    warning_days: int
    minimum_certificate_lifetime_days: int
    retention_days_after_expiry: int
    timer_randomized_delay_seconds: int
    initial_issue_on_highstate: bool
    fail_highstate_if_no_valid_cert: bool
    deploy_hook: str
    deploy_hook_timeout_seconds: int
    write_debug_artifacts: bool
    retain_failed_transactions: bool
    max_failed_transactions_retained: int
    include_crl_distribution_points: bool
    allow_production_force_renew: bool
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
        """Load configuration from a root-only YAML file.

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
            raise ConfigError(f"Configuration file must be root-only: {path}")
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
        peeringhub_environment = resolver.string("peeringhub_environment", "staging")
        stipa_spc = resolver.string("stipa_spc", "")
        account_dir = resolver.path("account_dir", "/var/lib/shaken/account")
        return cls(
            enabled=bool(data.get("enabled", False)),
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
            shaken_subject_organization_template=resolver.string(
                "shaken_subject_organization_template", ""
            ),
            acme_base_url=mapping_value(
                data,
                "acme_base_url",
                {
                    "production": "https://stica.peeringhub.io/acme",
                    "staging": "https://stica-dev.peeringhub.io/acme",
                },
            ),
            acme_kid=resolver.string(
                "acme_kid", f"{server_id}-{peeringhub_environment}"
            ),
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
            acme_timeout_seconds=int(data.get("acme_timeout_seconds", 30)),
            acme_poll_interval_seconds=int(data.get("acme_poll_interval_seconds", 5)),
            acme_poll_timeout_seconds=int(data.get("acme_poll_timeout_seconds", 180)),
            acme_bad_nonce_retries=int(data.get("acme_bad_nonce_retries", 2)),
            stipa_base_url=mapping_value(
                data,
                "stipa_base_url",
                {
                    "production": "https://authenticate-api.iconectiv.com",
                    "staging": "https://authenticate-api-stg.iconectiv.com",
                },
            ),
            stipa_timeout_seconds=int(data.get("stipa_timeout_seconds", 30)),
            stipa_crl_url=mapping_value(
                data,
                "stipa_crl_url",
                {
                    "production": "https://authenticate-api.iconectiv.com/download/v1/crl",
                    "staging": "https://authenticate-api-stg.iconectiv.com/download/v1/crl",
                },
            ),
            stipa_ca=bool(data.get("stipa_ca", False)),
            certificate_lifetime_mode=string_value(
                data, "certificate_lifetime_mode", "peeringhub_default"
            ),
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
            timer_randomized_delay_seconds=int(
                data.get("timer_randomized_delay_seconds", 21600)
            ),
            initial_issue_on_highstate=bool(
                data.get("initial_issue_on_highstate", True)
            ),
            fail_highstate_if_no_valid_cert=bool(
                data.get("fail_highstate_if_no_valid_cert", True)
            ),
            deploy_hook=string_value(data, "deploy_hook", ""),
            deploy_hook_timeout_seconds=int(
                data.get("deploy_hook_timeout_seconds", 60)
            ),
            write_debug_artifacts=bool(data.get("write_debug_artifacts", False)),
            retain_failed_transactions=bool(
                data.get("retain_failed_transactions", True)
            ),
            max_failed_transactions_retained=int(
                data.get("max_failed_transactions_retained", 10)
            ),
            include_crl_distribution_points=bool(
                data.get("include_crl_distribution_points", False)
            ),
            allow_production_force_renew=bool(
                data.get("allow_production_force_renew", False)
            ),
            state_dir=Path(string_value(data, "state_dir", "/var/lib/shaken")),
            work_dir=Path(string_value(data, "work_dir", "/var/lib/shaken/work")),
            archive_dir=Path(
                string_value(data, "archive_dir", "/var/lib/shaken/archive")
            ),
            live_dir=Path(string_value(data, "live_dir", "/var/lib/shaken/live")),
            failed_dir=Path(
                string_value(data, "failed_dir", "/var/lib/shaken/failed")
            ),
            account_dir=account_dir,
            active_manifest_path=Path(
                string_value(
                    data, "active_manifest_path", "/var/lib/shaken/active.json"
                )
            ),
            last_attempt_path=Path(
                string_value(
                    data, "last_attempt_path", "/var/lib/shaken/last-attempt.json"
                )
            ),
            lock_path=Path(
                string_value(
                    data, "lock_path", "/var/lib/shaken/shaken-cert-manager.lock"
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
            raise ConfigError("shaken_subject_country must be US")
        if self.enabled:
            required_fields = {
                "stipa_spc": self.stipa_spc,
                "stipa_sp_id": self.stipa_sp_id,
                "shaken_subject_state": self.shaken_subject_state,
                "shaken_subject_locality": self.shaken_subject_locality,
                "shaken_subject_organization": self.shaken_subject_organization,
                "stipa_user_id": self.stipa_user_id,
                "stipa_password": self.stipa_password,
            }
            missing = [name for name, value in required_fields.items() if not value]
            if missing:
                raise ConfigError(
                    f"Missing required enabled configuration fields: {', '.join(missing)}"
                )
        for url_map_name, url_map in {
            "acme_base_url": self.acme_base_url,
            "stipa_base_url": self.stipa_base_url,
            "stipa_crl_url": self.stipa_crl_url,
        }.items():
            if self.peeringhub_environment not in url_map:
                raise ConfigError(
                    f"{url_map_name} missing {self.peeringhub_environment}"
                )

    def acme_url(self) -> str:
        """Return the configured ACME URL for this Peeringhub environment.

        :return: ACME URL.
        :rtype: str
        """

        return self.acme_base_url[self.peeringhub_environment]

    def stipa_url(self) -> str:
        """Return the configured STI-PA URL for this Peeringhub environment.

        :return: STI-PA URL.
        :rtype: str
        """

        return self.stipa_base_url[self.peeringhub_environment]

    def expected_crl_url(self) -> str:
        """Return the configured STI-PA CRL URL for this Peeringhub environment.

        :return: CRL URL.
        :rtype: str
        """

        return self.stipa_crl_url[self.peeringhub_environment]


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

        self.data = data
        self.env = env

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
            return int(value)
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


def mapping_value(
    data: dict[str, Any], key: str, default: dict[str, str]
) -> dict[str, str]:
    """Return a string mapping config value.

    :param data: Config mapping.
    :type data: dict[str, Any]
    :param key: Config key.
    :type key: str
    :param default: Default mapping.
    :type default: dict[str, str]
    :return: Config mapping.
    :rtype: dict[str, str]
    """

    value = data.get(key, default)
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a mapping")
    return {str(map_key): str(map_value) for map_key, map_value in value.items()}
