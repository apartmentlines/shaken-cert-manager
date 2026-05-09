# Shell Completion

The CLI supports generated shell completion through `argcomplete`.

For bash, enable completion for the current shell with:

```sh
eval "$(register-python-argcomplete shaken-cert-manager)"
```

To make completion persistent, add that line to your shell startup file after
the `shaken-cert-manager` virtualenv is active.
