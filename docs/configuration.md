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
overrides for deployment-specific values such as STI-PA credentials, PeeringHub
environment, subject fields, and ACME account paths.

Environment values override YAML when the environment variable is non-empty.
Blank YAML values are treated as unset for required values and defaults.

## Required Settings

The manager always requires:

- `server_id`

When `enabled: true`, the manager also requires:

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

| Config key | Environment variable | Notes |
| --- | --- | --- |
| `shaken_subject_country` | `SHAKEN_SUBJECT_COUNTRY` | Certificate subject country; PeeringHub requires `US`. |
| `shaken_subject_state` | `SHAKEN_SUBJECT_STATE` | Certificate subject state. |
| `shaken_subject_locality` | `SHAKEN_SUBJECT_LOCALITY` | Certificate subject city/locality. |
| `shaken_subject_organization` | `SHAKEN_SUBJECT_ORGANIZATION` | Certificate subject organization. |
| `shaken_subject_organizational_unit` | `SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT` | Certificate subject OU; defaults to `VoIP`. |
| `subject_strategy` | `SHAKEN_SUBJECT_STRATEGY` | Generated CN style when no CN template is set: `unique_per_generation` or `stable_common_name`. |
| `shaken_subject_common_name_template` | `SHAKEN_SUBJECT_COMMON_NAME_TEMPLATE` | Optional CN template; overrides `subject_strategy`. |

See [Subject Templates](subject-templates.md) before overriding the generated
common name.

PeeringHub and ACME:

| Config key | Environment variable | Notes |
| --- | --- | --- |
| `acme_kid` | `ACME_KID` | PeeringHub-provided account identifier. |
| `account_dir` | `ACME_ACCOUNT_DIR` | Defaults under `state_dir`. |
| `acme_account_key_path` | `ACME_ACCOUNT_KEY_PATH` | Durable private key; must exist before issuance. |
| `acme_account_state_path` | `ACME_ACCOUNT_STATE_PATH` | Recoverable account cache. |
| `acme_base_url_override` | `PEERINGHUB_ACME_BASE_URL_OVERRIDE` | Developer override for ACME endpoint tests. |
| `stipa_base_url_override` | `STIPA_BASE_URL_OVERRIDE` | Developer override for STI-PA endpoint tests. |
| `stipa_crl_url_override` | `STIPA_CRL_URL_OVERRIDE` | Developer override for expected STI-PA CRL URL. |

Operational policy:

| Config key | Default | Notes |
| --- | --- | --- |
| `renew_before_days` | `45` | `renew` issues a replacement at or inside this window. |
| `warning_days` | `30` | `status` reports WARNING at or inside this window. |
| `minimum_certificate_lifetime_days` | `14` | Issuance validation floor and status CRITICAL threshold. |
| `retention_days_after_expiry` | `30` | Cleanup retention for expired inactive archives. |

State paths:

These are manager-owned paths. Change them mainly for packaging, containers, or
migration.

| Config key | Default | Notes |
| --- | --- | --- |
| `state_dir` | `/var/lib/shaken` | Base directory for manager state. |
| `work_dir` | `[state_dir]/work` | Temporary issuance transactions. |
| `archive_dir` | `[state_dir]/archive` | Completed certificate generations. |
| `live_dir` | `[state_dir]/live` | Live symlinks, including `current`. |
| `failed_dir` | `[state_dir]/failed` | Retained failed issuance diagnostics. |
| `active_manifest_path` | `[state_dir]/active.json` | Active generation manifest file. |
| `last_attempt_path` | `[state_dir]/last-attempt.json` | Last command result file. |
| `lock_path` | `[state_dir]/shaken-cert-manager.lock` | Lock file for serializing commands. |

Hooks and diagnostics:

| Config key | Default | Notes |
| --- | --- | --- |
| `pre_activate_hook` | | Must succeed before activation. |
| `pre_activate_hook_timeout_seconds` | `60` | Timeout for pre-activation hook. |
| `deploy_hook` | | Runs after activation; failures do not roll back. |
| `deploy_hook_timeout_seconds` | `60` | Timeout for deploy hook. |
| `retain_failed_transactions` | `true` | Keep failure diagnostics under `failed/`. |
| `max_failed_transactions_retained` | `10` | Failed transaction retention count. |

See [Lifecycle Hooks](hooks.md) for hook timing and environment variables.

Advanced issuance controls:

| Config key | Notes |
| --- | --- |
| `not_before` | Optional requested certificate start timestamp. |
| `not_after` | Optional requested certificate end timestamp. |
| `acme_timeout_seconds` | Developer tuning for ACME HTTP timeout. |
| `acme_poll_interval_seconds` | Developer tuning for ACME order polling interval. |
| `acme_poll_timeout_seconds` | Developer tuning for ACME order polling and token lifetime checks. |
| `acme_bad_nonce_retries` | Developer tuning for ACME badNonce retries. |
| `stipa_timeout_seconds` | Developer tuning for STI-PA HTTP timeout. |
| `include_crl_distribution_points` | Leave disabled unless your CA workflow requires CSR CRL distribution points. |

## Custom Certificate Length

Leave `not_before` and `not_after` unset to use the PeeringHub/toolkit default
certificate validity. To request a short-lived certificate, set `not_after` to
the desired RFC 3339 expiration timestamp accepted by PeeringHub ACME.

Here's how to create a short-lived certificate that expires at midnight UTC
after May 12, 2026.

```yaml
# Assuming today was 2026-05-12...
not_after: 2026-05-13T00:00:00Z
# The default renewal window is for normal long-lived certificates. For
# short-lived certificates, set renewal and monitoring windows explicitly.
renew_before_days: 0
warning_days: 0
# minimum_certificate_lifetime_days does not request the certificate length; it
# is the manager's threshold to accept the newly created certificate as valid,
# so it still needs to be lower than the length of the certificate being
# created. For a one-day certificate, use 0.
minimum_certificate_lifetime_days: 0
```

`days_remaining` is whole-day based, so a certificate with less than 24 hours
remaining reports `0` days remaining and is inside any `0`-day renewal,
warning, or critical window. For one-day or shorter certificate lifetimes,
run `force-renew` deliberately instead of scheduling repeated `renew` runs.

See the advanced issuance controls above for other optional issuance settings.

## Account Key Requirement

`acme_account_key_path` must point to the durable PeeringHub ACME account private
key. Create or verify it with `stir-shaken-toolkit`:

```bash
stir-shaken-toolkit peeringhub-account-setup --account-dir /var/lib/shaken/account
```

If `acme_account_state_path` is missing, the manager refreshes it from
PeeringHub before issuance. If the private key is missing, issuance stops.

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
