# Configuration

`shaken-cert-manager` reads one private YAML config file and selected
environment variable overrides.

Use `--config` before the subcommand:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status
```

The config file must not be group- or world-readable because it can contain
sensitive credentials.

```bash
chmod 600 shaken-cert-manager.yaml
```

For a full commented starting point, use
[`shaken-cert-manager.example.yaml`](../shaken-cert-manager.example.yaml).

## Value Sources

Most settings are read from YAML. The manager also accepts environment
overrides for deployment-specific values such as STI-PA credentials, Peeringhub
environment, subject fields, and ACME account paths.

Environment values override YAML when the environment variable is non-empty.
Blank YAML values are treated as unset for required values and defaults.

## Required Enabled Settings

When `enabled: true`, the manager requires:

- `server_id`
- `stipa_spc`
- `stipa_sp_id`, defaulting to `stipa_spc`
- `stipa_user_id`
- `stipa_password`
- `acme_kid`
- `shaken_subject_state`
- `shaken_subject_locality`
- `shaken_subject_organization`

When `enabled: false`, state-changing commands skip issuance and cleanup work.
`status` reports that SHAKEN certificate management is disabled.

## Common Settings

Identity and environment:

| Config key | Environment variable | Notes |
| --- | --- | --- |
| `enabled` | | Enables or disables manager work. |
| `server_id` | `SHAKEN_SERVER_ID` | Identifies this manager instance in manifests, hooks, status, and logs. |
| `peeringhub_environment` | `PEERINGHUB_ENVIRONMENT` | `staging` or `production`. |
| `stipa_spc` | `STIPA_SPC` | Service provider code in TNAuthList. |
| `stipa_sp_id` | `STIPA_SP_ID` | STI-PA `STI Participant ID` value; defaults to `stipa_spc`. |
| `stipa_user_id` | `STIPA_USER_ID` | STI-PA login user ID. |
| `stipa_password` | `STIPA_PASSWORD` | STI-PA login password. |

Subject fields:

| Config key | Environment variable |
| --- | --- |
| `shaken_subject_country` | `SHAKEN_SUBJECT_COUNTRY` |
| `shaken_subject_state` | `SHAKEN_SUBJECT_STATE` |
| `shaken_subject_locality` | `SHAKEN_SUBJECT_LOCALITY` |
| `shaken_subject_organization` | `SHAKEN_SUBJECT_ORGANIZATION` |
| `shaken_subject_organizational_unit` | `SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT` |
| `subject_strategy` | `SHAKEN_SUBJECT_STRATEGY` |
| `shaken_subject_common_name_template` | `SHAKEN_SUBJECT_COMMON_NAME_TEMPLATE` |

See [Subject Templates](subject-templates.md) before overriding the generated
common name.

Peeringhub and ACME:

| Config key | Environment variable | Notes |
| --- | --- | --- |
| `acme_kid` | `ACME_KID` | Peeringhub-provided account identifier. |
| `account_dir` | `ACME_ACCOUNT_DIR` | Defaults under `state_dir`. |
| `acme_account_key_path` | `ACME_ACCOUNT_KEY_PATH` | Durable private key; must exist before issuance. |
| `acme_account_state_path` | `ACME_ACCOUNT_STATE_PATH` | Recoverable account cache. |
| `acme_base_url_override` | `PEERINGHUB_ACME_BASE_URL_OVERRIDE` | Rare endpoint override. |
| `stipa_base_url_override` | `STIPA_BASE_URL_OVERRIDE` | Rare endpoint override. |
| `stipa_crl_url_override` | `STIPA_CRL_URL_OVERRIDE` | Rare CRL expectation override. |

Operational policy:

| Config key | Default | Notes |
| --- | --- | --- |
| `renew_before_days` | `45` | `renew` issues a replacement at or inside this window. |
| `warning_days` | `52` | `status` reports WARNING at or inside this window. |
| `minimum_certificate_lifetime_days` | `21` | Status CRITICAL threshold. |
| `retention_days_after_expiry` | `30` | Cleanup retention for expired inactive archives. |

State paths:

| Config key | Default |
| --- | --- |
| `state_dir` | `/var/lib/shaken` |
| `work_dir` | `[state_dir]/work` |
| `archive_dir` | `[state_dir]/archive` |
| `live_dir` | `[state_dir]/live` |
| `failed_dir` | `[state_dir]/failed` |
| `active_manifest_path` | `[state_dir]/active.json` |
| `last_attempt_path` | `[state_dir]/last-attempt.json` |
| `lock_path` | `[state_dir]/shaken-cert-manager.lock` |

Hooks and diagnostics:

| Config key | Default | Notes |
| --- | --- | --- |
| `pre_activate_hook` | | Must succeed before activation. |
| `pre_activate_hook_timeout_seconds` | `60` | Timeout for pre-activation hook. |
| `deploy_hook` | | Runs after activation; failures do not roll back. |
| `deploy_hook_timeout_seconds` | `60` | Timeout for deploy hook. |
| `retain_failed_transactions` | `true` | Keep failure diagnostics under `failed/`. |
| `max_failed_transactions_retained` | `10` | Failed transaction retention count. |
| `write_debug_artifacts` | `false` | Keep extra diagnostics where supported. |

See [Lifecycle Hooks](hooks.md) for hook timing and environment variables.

Advanced issuance controls:

| Config key | Notes |
| --- | --- |
| `certificate_lifetime_mode` | Use Peeringhub defaults unless explicit dates are required. |
| `not_before` | Requested certificate start when explicit lifetime mode is used. |
| `not_after` | Requested certificate end when explicit lifetime mode is used. |
| `acme_timeout_seconds` | Optional ACME HTTP timeout. |
| `acme_poll_interval_seconds` | Optional ACME order polling interval. |
| `acme_poll_timeout_seconds` | Optional ACME order polling timeout. |
| `acme_bad_nonce_retries` | Optional ACME badNonce retry count. |
| `stipa_timeout_seconds` | Optional STI-PA HTTP timeout. |
| `include_crl_distribution_points` | Leave disabled unless your CA workflow requires CSR CRL distribution points. |

## Account Key Requirement

`acme_account_key_path` must point to the durable Peeringhub ACME account private
key. Create or verify it with `stir-shaken-toolkit`:

```bash
stir-shaken-toolkit peeringhub-account-setup --account-dir /var/lib/shaken/account
```

If `acme_account_state_path` is missing, the manager refreshes it from
Peeringhub before issuance. If the private key is missing, issuance stops.

## Example Minimal Config

```yaml
enabled: true
peeringhub_environment: production
server_id: voice1

stipa_spc: 818H
stipa_sp_id: 818H
stipa_user_id: sti-pa-user
stipa_password: sti-pa-password
acme_kid: peeringhub-kid

shaken_subject_state: TX
shaken_subject_locality: Irving
shaken_subject_organization: Example Telecom

state_dir: /var/lib/shaken
pre_activate_hook: /usr/local/sbin/shaken-pre-activate
deploy_hook: /usr/local/sbin/shaken-deploy
```
