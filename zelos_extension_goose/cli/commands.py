"""Explicit subcommands: the app's settings as flags, no config.json."""

from __future__ import annotations

import logging
from pathlib import Path

import rich_click as click

from .. import pkg
from ..capture import (
    CaptureDeniedError,
    ConfigError,
    InterfaceConfig,
    parse_interfaces,
    probe_permissions,
)
from ..capture import (
    list_interfaces as _list_interfaces,
)
from ..constants import DEFAULT_PREFIX, RESERVED_NAMES, name_error
from ..converter import capture_stem, convert_pcap, resolve_output
from ..decode import GooseConfig, parse_goose
from .app import init_sdk, resolve_output_file, run_replay, run_sessions

logger = logging.getLogger(__name__)


_scl_option = click.option(
    "--scl",
    type=click.Path(path_type=Path),
    default=None,
    help="SCD/CID file to name and type dataset members by.",
)


def _goose(scl: Path | None) -> GooseConfig:
    try:
        return parse_goose({"scl": str(scl) if scl else ""})
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc


_file_option = click.option(
    "--file",
    type=click.Path(path_type=Path),
    default=None,
    is_flag=False,
    flag_value=".",
    help="Record trace to .trz (defaults to a UTC-stamped name). Under `capture`, rows "
    "stream to the agent and the file holds only the extension's own log.",
)


def _prefix(_ctx: click.Context, _param: click.Parameter, value: str) -> str:
    """App mode's prefix check, so `--prefix` refuses what `advanced.prefix` does."""
    if error := name_error(value.strip(), "Prefix", RESERVED_NAMES, required=True):
        raise click.ClickException(error)
    return value.strip()


_prefix_option = click.option(
    "--prefix",
    default=DEFAULT_PREFIX,
    show_default=True,
    callback=_prefix,
    help="Trace source for per-frame rows. Control blocks are always under GOOSE.",
)


def _run(configs: list[InterfaceConfig], prefix: str, file: Path | None) -> None:
    import zelos_sdk

    init_sdk(prefix)
    output_file = resolve_output_file(file)
    try:
        if output_file:
            logger.info("Recording trace to: %s", output_file)
            with zelos_sdk.TraceWriter(str(output_file)):
                run_sessions(configs, prefix)
        else:
            run_sessions(configs, prefix)
    except CaptureDeniedError as exc:
        raise click.ClickException(f"{exc}\n\n{exc.remediation}") from exc
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


@click.command("interfaces")
def interfaces_cmd() -> None:
    """List capturable network interfaces."""
    if not pkg.available():
        raise click.ClickException(pkg.skip_reason())
    for iface in _list_interfaces():
        flags = [f for f, on in (("up", iface["is_up"]), ("loopback", iface["is_loopback"])) if on]
        addresses = ", ".join(str(a) for a in iface["addresses"]) or "-"
        click.echo(f"{iface['name']:<16} {'/'.join(flags) or '-':<14} {addresses}")


@click.command("check")
@click.option("--interface", default="", help="Interface to probe (default: first non-loopback).")
def check_cmd(interface: str) -> None:
    """Probe whether live capture is permitted, and print how to fix it."""
    result = probe_permissions(interface.strip() or None)
    if result.get("can_capture"):
        click.echo(f"Capture is permitted on {result.get('interface')}.")
        return
    click.echo(result.get("reason") or "Capture is not permitted.")
    if result.get("remediation"):
        click.echo("")
        click.echo(result["remediation"])
    raise SystemExit(1)


@click.command("capture")
@click.argument("interface", nargs=-1, required=True)
@_scl_option
@_prefix_option
@_file_option
def capture_cmd(
    interface: tuple[str, ...],
    scl: Path | None,
    prefix: str,
    file: Path | None,
) -> None:
    """Subscribe on one or more INTERFACEs without app configuration.

    Rows stream from the capture helper straight to the agent, as in the
    Packet extension: `--file` records only this extension's own log.

    Examples:

      zelos-extension-goose capture eth0

      zelos-extension-goose capture eth0 eth1 --scl station.scd --file
    """
    try:
        configs = parse_interfaces(
            {
                "interfaces": [
                    {
                        "interface": name,
                        "scl": str(scl) if scl else "",
                    }
                    for name in interface
                ]
            }
        )
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    _run(configs, prefix, file)


@click.command("replay")
@click.argument("pcap", type=click.Path(exists=True, path_type=Path))
@click.option("--name", default="", help="Names this branch in the tree (default: the file stem).")
@_scl_option
@_prefix_option
@_file_option
def replay_cmd(
    pcap: Path,
    name: str,
    scl: Path | None,
    prefix: str,
    file: Path | None,
) -> None:
    """Stream a PCAP's GOOSE traffic to the agent once, paced, stamped from now. No privileges."""
    goose = _goose(scl)
    if error := name_error(name.strip(), "Name", RESERVED_NAMES):
        raise click.ClickException(error)
    init_sdk(prefix)
    try:
        run_replay(
            pcap,
            name=name.strip() or capture_stem(pcap),
            prefix=prefix,
            goose=goose,
            output_file=resolve_output_file(file),
        )
    except (ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


@click.command("convert")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), default=None, help="Output .trz.")
@click.option("-f", "--force", is_flag=True, help="Overwrite an output that already exists.")
@_scl_option
@_prefix_option
def convert_cmd(
    input_file: Path,
    output: Path | None,
    force: bool,
    scl: Path | None,
    prefix: str,
) -> None:
    """Convert a PCAP's GOOSE traffic to a Zelos trace (.trz).

    Needs no capture privileges and no agent: nothing is published, the trace
    is written straight to disk. Inputs may be gzip or zstd compressed.
    """
    goose = _goose(scl)
    try:
        destination = resolve_output(input_file, output, overwrite=force)
        result = convert_pcap(input_file, destination, goose=goose, prefix=prefix)
    except (ValueError, FileExistsError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{result['input_file']} -> {result['output_file']} ({result['packets']:,} packets)")
