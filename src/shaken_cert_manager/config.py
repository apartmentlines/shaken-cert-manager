"""Configuration loading for the SHAKEN certificate manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shaken_cert_manager.errors import ConfigError


@dataclass
class ManagerConfig:
    """Runtime configuration for SHAKEN certificate management."""

    enabled: bool
    environment: str
    server_id: str
    spc: str
    sp_id: str
    subject_country: str
    subject_state: str
    subject_locality: str
    subject_organization_legal_name: str
    stipa_user_id: str
    stipa_password: str
    subject_organizational_unit: str
    subject_strategy: str
    subject_cn_template: str
    subject_o_template: str
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
    csr_include_crl_distribution_points: bool
    allow_production_force_renew: bool
    state_dir: Path = Path("/var/lib/shaken")
    work_dir: Path = Path("/var/lib/shaken/work")
    archive_dir: Path = Path("/var/lib/shaken/archive")
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
    def from_mapping(cls, data: dict[str, Any]) -> ManagerConfig:
        """Build configuration from a mapping.

        :param data: Configuration mapping.
        :type data: dict[str, Any]
        :return: Loaded configuration.
        :rtype: ManagerConfig
        """

        server_id = string_value(data, "server_id", "")
        environment = string_value(data, "environment", "staging")
        return cls(
            enabled=bool(data.get("enabled", False)),
            environment=environment,
            server_id=server_id,
            spc=string_value(data, "spc", ""),
            sp_id=string_value(data, "sp_id", string_value(data, "spc", "")),
            subject_country=string_value(data, "subject_country", "US"),
            subject_state=string_value(data, "subject_state", ""),
            subject_locality=string_value(data, "subject_locality", ""),
            subject_organization_legal_name=string_value(
                data, "subject_organization_legal_name", ""
            ),
            stipa_user_id=string_value(data, "stipa_user_id", ""),
            stipa_password=string_value(data, "stipa_password", ""),
            subject_organizational_unit=string_value(
                data, "subject_organizational_unit", "VoIP"
            ),
            subject_strategy=string_value(
                data, "subject_strategy", "unique_per_generation"
            ),
            subject_cn_template=string_value(data, "subject_cn_template", ""),
            subject_o_template=string_value(data, "subject_o_template", ""),
            acme_base_url=mapping_value(
                data,
                "acme_base_url",
                {
                    "production": "https://stica.peeringhub.io/acme",
                    "staging": "https://stica-dev.peeringhub.io/acme",
                },
            ),
            acme_kid=string_value(data, "acme_kid", f"{server_id}-{environment}"),
            acme_account_key_path=Path(
                string_value(
                    data,
                    "acme_account_key_path",
                    "/var/lib/shaken/account/account.key",
                )
            ),
            acme_account_state_path=Path(
                string_value(
                    data,
                    "acme_account_state_path",
                    "/var/lib/shaken/account/account.json",
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
            not_before=optional_string_value(data, "not_before"),
            not_after=optional_string_value(data, "not_after"),
            renew_before_days=int(data.get("renew_before_days", 45)),
            warning_days=int(data.get("warning_days", 52)),
            minimum_certificate_lifetime_days=int(
                data.get("minimum_certificate_lifetime_days", 21)
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
            csr_include_crl_distribution_points=bool(
                data.get("csr_include_crl_distribution_points", False)
            ),
            allow_production_force_renew=bool(
                data.get("allow_production_force_renew", False)
            ),
            raw=data,
        )

    def validate(self) -> None:
        """Validate configuration values.

        :return: None.
        :rtype: None
        :raises ConfigError: If required values are invalid.
        """

        if self.environment not in {"staging", "production"}:
            raise ConfigError("environment must be staging or production")
        if not self.server_id:
            raise ConfigError("server_id is required")
        if self.subject_country != "US":
            raise ConfigError("subject_country must be US")
        if self.enabled:
            required_fields = {
                "spc": self.spc,
                "sp_id": self.sp_id,
                "subject_state": self.subject_state,
                "subject_locality": self.subject_locality,
                "subject_organization_legal_name": self.subject_organization_legal_name,
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
            if self.environment not in url_map:
                raise ConfigError(f"{url_map_name} missing {self.environment}")

    def acme_url(self) -> str:
        """Return the configured ACME URL for this environment.

        :return: ACME URL.
        :rtype: str
        """

        return self.acme_base_url[self.environment]

    def stipa_url(self) -> str:
        """Return the configured STI-PA URL for this environment.

        :return: STI-PA URL.
        :rtype: str
        """

        return self.stipa_base_url[self.environment]

    def expected_crl_url(self) -> str:
        """Return the configured STI-PA CRL URL for this environment.

        :return: CRL URL.
        :rtype: str
        """

        return self.stipa_crl_url[self.environment]


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


def optional_string_value(data: dict[str, Any], key: str) -> str | None:
    """Return an optional string config value.

    :param data: Config mapping.
    :type data: dict[str, Any]
    :param key: Config key.
    :type key: str
    :return: Config value or ``None``.
    :rtype: str | None
    """

    value = data.get(key)
    return None if value in {None, ""} else str(value)


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
