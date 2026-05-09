# Lifecycle Hooks

`shaken-cert-manager` supports two optional lifecycle hooks. Both hooks receive
`SHAKEN_*` environment variables describing the certificate generation, but they
run at different points in the activation flow.

Hooks are shell commands configured in `shaken-cert-manager.yaml`. They run with
a clean manager-provided environment and a timeout. Use absolute paths for hook
commands in production deployments.

The hook scripts must be executable and self-runnable (e.g shebang line for interpreter).

## Pre-Activation Hook

`pre_activate_hook` runs after the issued certificate has been archived and
linked under `live/<generation_id>`, but before `live/current` and `active.json`
are updated.

Use this hook for checks or local preparation that must succeed before the new
certificate becomes active. If this hook exits non-zero or times out, the manager
removes the new `live/<generation_id>` links and fails the issuance.

The pre-activation hook receives generation-specific paths such as
`SHAKEN_LIVE_GENERATION_DIR`, `SHAKEN_LIVE_LEAF_CERT_PATH`, and
`SHAKEN_LIVE_CHAIN_CERT_PATH`. It does not receive `live/current` variables,
because `live/current` still points at the previous active generation while this
hook is running.

## Deploy Hook

`deploy_hook` runs after `live/current` and `active.json` have been updated.

Use this hook for notification, service reloads, cache refreshes, or other
post-activation work. If this hook exits non-zero or times out, the failure is
logged and recorded in the manifest, but the certificate activation is not rolled
back.

The deploy hook receives the same generation-specific variables as the
pre-activation hook, plus current-link variables such as
`SHAKEN_LIVE_CURRENT_DIR`, `SHAKEN_LIVE_CURRENT_LEAF_CERT_PATH`, and
`SHAKEN_LIVE_CURRENT_CHAIN_CERT_PATH`.

## Hook Results

Hook result is recorded in the generation manifest and status output:

- `success`: hook exited with code `0`.
- `failed`: hook exited non-zero.
- `timed_out`: hook exceeded its configured timeout.
- `not_configured`: no hook command was configured.

Pre-activation hook failures fail the issuance and keep the previous active
certificate active. Deploy hook failures are logged and recorded, but activation
remains successful.

## Common Environment Values

Common hook variables include:

- `SHAKEN_GENERATION_ID`
- `SHAKEN_ENVIRONMENT`
- `SHAKEN_SERVER_ID`
- `SHAKEN_SPC`
- `SHAKEN_PRIVATE_KEY_PATH`
- `SHAKEN_ARCHIVE_DIR`
- `SHAKEN_LIVE_DIR`
- `SHAKEN_LIVE_GENERATION_DIR`
- `SHAKEN_LIVE_LEAF_CERT_PATH`
- `SHAKEN_LIVE_CHAIN_CERT_PATH`
- `SHAKEN_MANIFEST_PATH`
- `SHAKEN_LEAF_CERT_PATH`
- `SHAKEN_CHAIN_CERT_PATH`
- `SHAKEN_CSR_PEM_PATH`
- `SHAKEN_CSR_DER_PATH`
- `SHAKEN_NOT_BEFORE`
- `SHAKEN_NOT_AFTER`
- `SHAKEN_FINGERPRINT_SHA256`
- `SHAKEN_PREVIOUS_GENERATION_ID`
- `SHAKEN_SUBJECT`
- `SHAKEN_SUBJECT_COMMON_NAME`
- `SHAKEN_SUBJECT_COUNTRY`
- `SHAKEN_SUBJECT_STATE`
- `SHAKEN_SUBJECT_LOCALITY`
- `SHAKEN_SUBJECT_ORGANIZATION`
- `SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT`
