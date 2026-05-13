# Monitoring

`shaken-cert-manager status` reports active certificate health for humans,
automation, and Nagios-compatible monitoring.

## Text Status

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status
```

Text output starts with the summary, followed by fields useful for local
inspection. It may include paths because this mode is intended for operators on
the host.

## JSON Status

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status --json
```

JSON output contains:

- `code`: Nagios-style status code.
- `summary`: short status message.
- `fields`: structured status fields.

Use JSON for local automation that needs exact values such as `generation_id`,
`not_after`, `days_remaining`, hook statuses, `last_attempt_result`, parsed
certificate policies, CRL distribution points, key identifiers, and the
TNAuthList SPC found in the active certificate.

## Nagios Status

```bash
shaken-cert-manager --config shaken-cert-manager.yaml status --nagios
```

Nagios output is intentionally short and avoids sensitive local paths:

```text
SHAKEN CERTIFICATE OK: certificate valid for 364 days; generation=20260509T194831Z-888b6a872c; expires=2027-05-09T19:48:39Z | days_remaining=364;52;21;0
```

The `days_remaining` perfdata is:

```text
days_remaining=<value>;<warning_days>;<minimum_certificate_lifetime_days>;0
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | OK |
| `1` | WARNING |
| `2` | CRITICAL |
| `3` | UNKNOWN |

## Warning And Critical Conditions

Status reports WARNING when:

- The active certificate is at or inside `warning_days`.
- The last renewal attempt failed and the certificate is now inside the renewal
  window.

Status reports CRITICAL when:

- The active certificate is at or below `minimum_certificate_lifetime_days`.
- Active certificate state is invalid.
- The active certificate key does not match the certificate.
- `active.json`, archived certificate material, or `live/current` links are
  missing or inconsistent.

Use `--debug` for detailed local diagnostics:

```bash
shaken-cert-manager --config shaken-cert-manager.yaml --debug status --nagios
```

Debug logs can include local filesystem paths and exception details. Monitoring
systems should normally collect the standard Nagios line, not debug logs.
