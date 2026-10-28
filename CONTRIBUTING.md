# Contributing

## Prerequisites

- [Zelos CLI](https://docs.zeloscloud.io/cli)
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- [just](https://github.com/casey/just)

## Commands

| Command                  | Description                                      |
| ------------------------ | ------------------------------------------------ |
| `just install`           | Install dependencies and pre-commit hooks        |
| `just dev`               | Run the extension locally in app-config mode     |
| `just demo`              | Replay the bundled demo capture once             |
| `just demo-pcap`         | Regenerate the bundled demo capture              |
| `just interfaces`        | List capturable NICs                             |
| `just check-permissions` | Probe capture rights and print the fix           |
| `just format`            | Format code with ruff                            |
| `just check`             | Lint with ruff                                   |
| `just test`              | Run tests with pytest                            |
| `just package`           | Package for the Zelos marketplace                |
| `just package-list`      | List what the package would ship                 |
| `just release VERSION`   | Bump version, check, test, commit, and tag       |
| `just clean`             | Remove build artifacts                           |

## The decoder

Capture and GOOSE decode are `zelos-packet`'s. This extension only builds the
keyword arguments (`zelos_extension_goose/decode.py`) and refuses, naming the
version it needs, on a release without the decoder. Tests stub that seam;
decode correctness is tested with the decoder, not here.

## Configuration

`config.schema.json` drives the configuration UI in the Zelos desktop app;
`config.json` is the shipped default. The interface picker uses a `ui:widget`
hint rather than an enum, because a static schema cannot enumerate a machine's
NICs. See the [configuration docs](https://docs.zeloscloud.io/sdk/how-to/develop-extensions/#configuration)
for the widget reference.

## Actions

`list_interfaces`, `auto_config`, `convert_pcap` and `demo_capture_path` are
declared `standalone=True`, so they run with the extension stopped.
`zelos extensions package` inventories them into `actions.json` and ships it
inside the archive. It is generated, never committed.

## Packaging

```bash
just package
```

The archive lands next to `extension.toml` as `goose-{version}.tar.gz`.

## Releasing

```bash
just release 0.1.0
git push
git push origin v0.1.0   # the tag on its own: pushed together with the branch, Actions can miss it
```

The tag drives `.github/workflows/release.yml`, which re-verifies the version
against both manifests, packages, checks that `actions.json` made it into the
archive, and attaches the result to a GitHub release.

## License

MIT - see [LICENSE](LICENSE)
