# SHAKEN Subject Templates

`shaken-cert-manager` normally generates a unique SHAKEN certificate subject
common name (`CN`) for each issued certificate. The common name template setting
lets you override how that `CN` value is generated while keeping the rest of the
issuance workflow unchanged.

This is an advanced setting. The default `unique_per_generation` behavior is the
recommended operator path because it avoids repeated issuance with the same
subject name.

`subject_strategy: stable_common_name` uses `SHAKEN {stipa_spc}` as the common
name when no explicit template is configured.

## Settings

```yaml
shaken_subject_common_name_template:
```

This setting is optional. When it is unset, `shaken-cert-manager` uses its
built-in common name generation.

## Available Fields

Templates use Python format-string syntax with named fields:

| Field | Meaning |
| --- | --- |
| `server_id` | The configured `server_id` for this manager instance. |
| `generation_id` | The unique certificate generation ID for the current issuance run. |
| `stipa_spc` | The configured STI-PA service provider code. |
| `organization` | The configured `shaken_subject_organization` value. |

Unknown fields are rejected during issuance.

## Common Name Template

`shaken_subject_common_name_template` controls the subject `CN` value.

Peeringhub requires the common name to contain a `SHAKEN <SPC>` string. For
example, if your SPC is `818H`, the rendered common name must include
`SHAKEN 818H`.

Default pattern:

```yaml
shaken_subject_common_name_template: "SHAKEN {stipa_spc} {generation_id}"
```

This keeps the Peeringhub-required prefix and also makes each certificate
subject unique without adding instance identity to the X.509 common name.

Stable common name pattern:

```yaml
shaken_subject_common_name_template: "SHAKEN {stipa_spc}"
```

Use a stable common name only if your CA and operational workflow allow
reissuing certificates with the same subject name. Peeringhub may reject a new
certificate when another active certificate already uses the same subject.

## Example

```yaml
server_id: example-server
stipa_spc: 818H
shaken_subject_organization: Example Company

shaken_subject_common_name_template: "SHAKEN {stipa_spc} {server_id} {generation_id}"
```

For a generation ID of `20260509T153000Z-a1b2c3d4e5`, this
renders roughly as:

```text
CN=SHAKEN 818H example-server 20260509T153000Z-a1b2c3d4e5
O=Example Company
```

The exact generation ID is created by `shaken-cert-manager` during issuance.

**IMPORTANT NOTE:** The CN field of a certification has a maximum value of 64 characters.
