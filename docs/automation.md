# Automation

`shaken-cert-manager` is intended to be run by an external scheduler. The
scheduled command should normally be `renew`, not `force-renew`; renewal policy
is controlled by the manager config, especially `renew_before_days`.

Monitoring is a separate job. Use `status --nagios` or `status --json` from
your monitoring system instead of treating the scheduler output as the primary
alert signal.

## Cron

The simplest unattended setup is cron:

```cron
0 0,12 * * * root /usr/local/bin/shaken-cert-manager --config /etc/shaken-cert-manager.yaml renew
```

See [examples/cron/shaken-cert-manager.cron](../examples/cron/shaken-cert-manager.cron).

Cron is portable and easy to audit, but it does not provide built-in jitter,
persistent catch-up after missed runs, or structured service logs. If many
hosts are managed at once, add scheduler-level jitter or use a systemd timer.

## Systemd Timer

For systemd-based hosts, use a oneshot service plus timer:

```bash
cp examples/systemd/shaken-cert-manager.service /etc/systemd/system/
cp examples/systemd/shaken-cert-manager.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now shaken-cert-manager.timer
```

The timer example runs twice daily, spreading starts across the interval
with `RandomizedDelaySec`, and catching up missed runs with `Persistent=true`.

The service example grants write access to `/var/lib/shaken`, which is the
default `state_dir` and also contains the default `account_dir`. If your config
stores state, account material, or hook output somewhere else, adjust
`StateDirectory=` and `ReadWritePaths=` in the unit or in a drop-in.

See:

- [examples/systemd/shaken-cert-manager.service](../examples/systemd/shaken-cert-manager.service)
- [examples/systemd/shaken-cert-manager.timer](../examples/systemd/shaken-cert-manager.timer)

Use a systemd drop-in to customize paths or environment without editing the
reference unit:

```bash
systemctl edit shaken-cert-manager.service
```

For example:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/shaken-cert-manager --config /etc/shaken/manager.yaml renew
StateDirectory=
ReadWritePaths=
ReadWritePaths=/etc/shaken/state
```

Lifecycle hooks should remain in `shaken-cert-manager.yaml`. The scheduler's
job is only to run `renew` regularly.

`ReadWritePaths=` is the important setting when your configured `state_dir` or
`account_dir` is outside `/var/lib/shaken`. Clear and replace it with every path
the manager or its hooks must write. Clear `StateDirectory=` when you no longer
want systemd to create `/var/lib/shaken`; otherwise you may leave it in place.
