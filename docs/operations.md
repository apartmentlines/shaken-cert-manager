# Operations

`shaken-cert-manager` is designed to run safely from scheduled automation while
also giving operators clear manual commands for inspection and recovery.

## First Issuance

Before the first certificate, create the Peeringhub ACME account key:

```bash
stir-shaken-toolkit peeringhub-account-setup --account-dir /var/lib/shaken/account
```

Then run:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml issue-initial
```

`issue-initial` issues only when there is no active usable certificate. If an
active certificate already exists, the command exits successfully without
issuing a replacement.

## Scheduled Renewal

Run `renew` from your scheduler:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml renew
```

`renew` checks status first. It issues a replacement when the active certificate
is at or inside `renew_before_days`, or when active state is critical and needs
replacement. Outside the renewal window it records a skipped attempt and exits
successfully.

Use `force-renew` for deliberate manual replacement:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml force-renew
```

For non-interactive use:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml force-renew --skip-confirm
```

## Activation Flow

Each issuance creates a unique generation ID such as:

```text
20260509T194831Z-888b6a872c
```

The manager:

1. Issues and validates a certificate through Peeringhub.
2. Archives generation artifacts under `archive/<generation_id>/`.
3. Creates `live/<generation_id>/` symlinks to the archived certificate files.
4. Runs `pre_activate_hook`, when configured.
5. Atomically updates `live/current` and `active.json`.
6. Runs `deploy_hook`, when configured.
7. Writes `last-attempt.json`.

If the pre-activation hook fails or times out, the new live generation links are
removed and the previous active certificate remains active. If the deploy hook
fails or times out, activation remains successful and the hook status is
recorded.

## State Directory

The default state directory is `/var/lib/shaken`.

```text
/var/lib/shaken/
  account/
    account.key
    account.json
  archive/
    <generation_id>/
      csr.pem
      csr.der
      leaf.pem
      certificate-chain.pem
      manifest.json
  live/
    <generation_id>/
      leaf.pem -> ../../archive/<generation_id>/leaf.pem
      certificate-chain.pem -> ../../archive/<generation_id>/certificate-chain.pem
    current -> <generation_id>
  failed/
    <generation_id>/
  active.json
  last-attempt.json
```

`archive/` is the durable certificate history. `live/` is the runtime-facing
link tree. `active.json` is the active manifest used by status and renewal
decisions.

Your signing service should use the private key at `account/account.key`. Your
public certificate URL should serve `live/current/certificate-chain.pem` or the most current `live/<generation_id>/certificate-chain.pem`, depending on your setup. Do not
publish `account.key`.

## Inspecting State

Show manager status:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status
```

Inspect the active live target:

```bash
readlink /var/lib/shaken/live/current
ls -l /var/lib/shaken/live/current
```

Inspect the active manifest:

```bash
python -m json.tool /var/lib/shaken/active.json
```

Inspect the active certificate contents:

```bash
stir-shaken-toolkit inspect --certificate /var/lib/shaken/live/current/leaf.pem
stir-shaken-toolkit inspect --certificate /var/lib/shaken/live/current/certificate-chain.pem --json
```

## Cleanup

Run cleanup periodically:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml cleanup
```

Cleanup removes:

- Expired inactive archives older than `retention_days_after_expiry`.
- Stale or expired live generation links.
- Old failed transaction archives beyond `max_failed_transactions_retained`.

Cleanup never removes the active generation archive.

## Disabled Mode

When `enabled: false`, issuance, renewal, force-renewal, and cleanup commands
skip state-changing work and record a disabled attempt. `status` reports that
SHAKEN certificate management is disabled.
