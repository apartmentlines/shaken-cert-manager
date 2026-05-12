# SHAKEN Cert Manager - Certbot for SHAKEN Certs

`shaken-cert-manager` is an operator-focused lifecycle manager for
STIR/SHAKEN certificates. It issues certificates through `stir-shaken-toolkit`,
keeps durable archive state, exposes the active certificate through stable live
links, runs lifecycle hooks, reports monitoring status, and cleans up old
material.

It currently supports integration with the [Peeringhub.io](https://www.peeringhub.io) STI-CA SHAKEN certificate provider -- an active Peeringhub account is required for valid issuance of certificates.

It does not replace your signing service. Your signing service still needs to
read the private key, publish the active certificate chain at the URL used in
PASSporT `x5u`, insert the `Identity` header into outbound calls, etc.

## Install

From the repository root:

```bash
python -m pip install -e .
```

`shaken-cert-manager` depends on Peeringhub issuance support from
`stir-shaken-toolkit`. Install that package in the same environment.

## Quick Start

Create a manager config from the example:

```bash
cp shaken-cert-manager.example.yaml shaken-cert-manager.yaml
chmod 600 shaken-cert-manager.yaml
```

Fill in the Peeringhub, STI-PA, certificate subject, account, state, and hook
settings needed for the deployment.

See the [minimal config example](docs/configuration.md#example-minimal-config)
for the smallest useful shape.

Prepare or provision the Peeringhub ACME account key before issuing:

```bash
stir-shaken-toolkit peeringhub-account-setup --account-dir /var/lib/shaken/account
```

Issue the first certificate:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml issue-initial
```

Check status:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status
shaken-cert-manager --config shaken-cert-manager.yaml status --nagios
```

Run renewal from your scheduler:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml renew
```

Run cleanup periodically:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml cleanup
```

## Short-Lived Certificates

See [Custom Certificate Length](docs/configuration.md#custom-certificate-length)
for an example and related issuance settings.

## Commands

- `issue-initial`: issue a certificate only when no active usable certificate
  exists.
- `renew`: issue a replacement only when status and renewal policy require it.
- `force-renew`: issue a replacement immediately; use `--skip-confirm` for
  non-interactive runs.
- `status`: print active certificate health as text, JSON, or Nagios plugin
  output.
- `cleanup`: remove expired inactive archives, stale live links, and old failed
  transaction archives.

Use `--debug` before the subcommand for detailed logs with configured secrets
redacted:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml --debug status
```

## State Model

The manager owns a state directory, usually `/var/lib/shaken`:

- `account/account.key`: durable Peeringhub ACME account private key.
- `account/account.json`: recoverable Peeringhub ACME account state cache.
- `archive/<generation_id>/`: durable certificate generation artifacts.
- `live/<generation_id>/`: symlink tree exposing an unexpired generation.
- `live/current`: symlink to the active live generation.
- `active.json`: active generation manifest.
- `last-attempt.json`: result of the last manager command that records state.
- `failed/<generation_id>/`: retained failed transaction diagnostics.

Publish `live/current/certificate-chain.pem` from your HTTPS certificate URL and
configure your signing service to use `account/account.key` as the private key.
Do not publish `account.key`.

## More Documentation

- [Configuration](docs/configuration.md): config keys, environment overrides,
  defaults, and example setup guidance.
- [Operations](docs/operations.md): issuance, renewal, activation, cleanup, and
  state inspection workflows.
- [Automation](docs/automation.md): cron and systemd timer examples for
  unattended renewal.
- [Monitoring](docs/monitoring.md): text, JSON, and Nagios status output.
- [Lifecycle Hooks](docs/hooks.md): pre-activation and deploy hook behavior.
- [Subject Templates](docs/subject-templates.md): advanced subject common name
  customization.
- [Shell Completion](docs/shell-completion.md): generated completion through
  `argcomplete`.
