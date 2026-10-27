"""Free-floating GOOSE actions registered under ``GOOSE/<name>``.

Same shape as the Packet extension: free functions (so ``choices=`` can
reference a module-level callable), a shared registry populated by ``cli/app.py``
at startup, and one global namespace rather than per-interface action paths.

Every action is read-only. GOOSE is subscribe-only here: nothing is ever
published onto the bus.
"""

from __future__ import annotations

import inspect
import logging
import platform
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from zelos_sdk.actions import ActionsRegistry, action

from . import capture as capture_mod
from . import decode, pkg
from .demo import DEMO_PCAP

if TYPE_CHECKING:
    from .capture import CaptureSession

logger = logging.getLogger(__name__)

#: Live capture sessions, keyed by interface name. Populated by `cli/app.py`.
CAPTURES: dict[str, CaptureSession] = {}


def _available_captures(*_args: Any) -> list[str]:
    """`choices=` provider; evaluated at form-render time."""
    return sorted(CAPTURES.keys())


def _sessions(name: str) -> tuple[list[CaptureSession], dict[str, Any] | None]:
    """The named session, or every running one; an error dict on a bad name."""
    if name:
        session = CAPTURES.get(name)
        if session is None:
            return [], {
                "status": "error",
                "message": f"Unknown interface {name!r}. Running: {_available_captures()}",
            }
        return [session], None
    sessions = [CAPTURES[key] for key in _available_captures()]
    if not sessions:
        return [], {
            "status": "warning",
            "message": "No live captures are running. Configure an interface and start "
            "the extension.",
        }
    return sessions, None


def _interface_choice(iface: dict[str, Any]) -> dict[str, str]:
    detail = []
    if isinstance(iface.get("is_up"), bool):
        detail.append("up" if iface["is_up"] else "down")
    if iface.get("is_loopback") is True:
        detail.append("loopback")
    addresses = iface.get("addresses") or []
    if addresses and isinstance(addresses[0], str):
        detail.append(addresses[0])
    return {"value": iface["name"], "detail": " · ".join(detail)}


def _interface_rank(iface: dict[str, Any]) -> tuple[int, str]:
    """Up non-loopback first, then up loopback, then down; names break ties."""
    up = iface.get("is_up") is True
    loopback = iface.get("is_loopback") is True
    return (0 if up and not loopback else 1 if up else 2, iface["name"])


def _scan_interfaces(build: Callable[[list[dict[str, Any]]], dict[str, Any]]) -> dict[str, Any]:
    try:
        return build(sorted(capture_mod.list_interfaces(), key=_interface_rank))
    except pkg.PacketPackageUnavailable as exc:
        return {"status": "error", "message": str(exc)}
    except Exception as exc:
        logger.exception("Failed to enumerate interfaces")
        return {"status": "error", "message": f"{type(exc).__name__}: {exc}"}


def _auto_config(interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    picked = [
        i["name"] for i in interfaces if i.get("is_up") is True and i.get("is_loopback") is not True
    ]
    if not picked:
        return {"status": "error", "message": "No interface on this host is up and not loopback."}
    return {
        "status": "success",
        "config": {"interfaces": [{"interface": n} for n in picked]},
    }


@action(
    "Auto-configure",
    "A configuration that subscribes on every interface that is up and not loopback, "
    "for the config form's Auto-configure button. Review it, then save and start.",
    standalone=True,
    hidden=True,
    read_only=True,
)
def auto_config() -> dict[str, Any]:
    return _scan_interfaces(_auto_config)


@action(
    "List Interfaces",
    "Network interfaces on the machine running the agent, as choices for the "
    "config's 'Interface' field, which also accepts a name typed by hand.",
    standalone=True,
    hidden=True,
    read_only=True,
)
def list_interfaces() -> dict[str, Any]:
    return _scan_interfaces(
        lambda interfaces: {
            "status": "success",
            "choices": [_interface_choice(i) for i in interfaces],
        }
    )


@action(
    "Check Permissions",
    "Probe whether live capture is possible on this machine and, if not, return "
    "the exact command to fix it. Run this before the first Start.",
    read_only=True,
)
@action.text(
    "interface",
    title="Interface",
    description="Optional. Defaults to the first interface that is up and not loopback.",
    required=False,
    default="",
    placeholder="eth0",
)
def check_permissions(interface: str = "") -> dict[str, Any]:
    result = capture_mod.probe_permissions(interface.strip() or None)
    result["status"] = "success" if result.get("can_capture") else "error"
    result["python"] = sys.executable
    result.setdefault("platform", platform.system())
    return result


@action(
    "List Control Blocks",
    "Every GOOSE control block seen on the running interfaces: goID, gocbRef, "
    "APPID, publisher MAC, current stNum/sqNum and when it was last heard. The "
    "names the other actions and the trace use.",
    read_only=True,
)
@action.select(
    "interface",
    title="Interface",
    description="Leave empty for every running interface.",
    required=False,
    default="",
    choices=_available_captures,
)
def list_gocbs(interface: str = "") -> dict[str, Any]:
    sessions, err = _sessions(interface)
    if err:
        return {**err, "control_blocks": []}
    blocks = [{"interface": s.name, **b} for s in sessions for b in s.control_blocks()]
    return {"status": "success", "control_blocks": blocks, "count": len(blocks)}


@action(
    "Get Status",
    "Per-interface read-loop counters (packets_read, kernel_drops, decode_stall_ms) "
    "and GOOSE decoder counters (goose_messages, goose_gocbs, goose_malformed, "
    "goose_stnum_gaps, goose_sqnum_gaps, goose_tal_expired). kernel_drops climbing "
    "means the kernel buffer is too small; goose_tal_expired climbing with no gaps "
    "means a publisher is late, not lost.",
    read_only=True,
)
@action.select(
    "interface",
    title="Interface",
    description="Leave empty for every running interface.",
    required=False,
    default="",
    choices=_available_captures,
)
def get_status(interface: str = "") -> dict[str, Any]:
    sessions, err = _sessions(interface)
    if err:
        return {**err, "interfaces": []}
    return {"status": "success", "interfaces": [s.status() for s in sessions]}


@action(
    "Get Snapshot",
    "Last-seen header and dataset values of every control block on an interface, "
    "straight from the decoder's cache: no bus I/O.",
    read_only=True,
)
@action.select(
    "interface",
    title="Interface",
    description="Leave empty for every running interface.",
    required=False,
    default="",
    choices=_available_captures,
)
def get_snapshot(interface: str = "") -> dict[str, Any]:
    sessions, err = _sessions(interface)
    if err:
        return {**err, "control_blocks": []}
    captured_at_unix_ms = int(time.time() * 1000)
    blocks = [{"interface": s.name, **b} for s in sessions for b in s.control_blocks()]
    return {
        "status": "success",
        "captured_at_unix_ms": captured_at_unix_ms,
        "control_blocks": blocks,
    }


@action(
    "Convert Pcap",
    "Convert a .pcap/.pcapng file, optionally gzip or zstd compressed, to a Zelos "
    "trace (.trz) of its GOOSE traffic. Runs without the extension running: no "
    "capture handle, no interface, no privileges, and no agent.",
    timeout=1800.0,
    standalone=True,
    read_only=True,
)
@action.text(
    "input_file",
    title="Capture file",
    description="Source .pcap or .pcapng, optionally gzip or zstd compressed",
    widget="file_path_picker",
)
@action.text(
    "output_file",
    title="Output (.trz)",
    description="Defaults to the input's name with a .trz suffix",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.text(
    "scl",
    title="SCL file",
    description="SCD or CID file to name and type dataset members by",
    required=False,
    default="",
    widget="file_path_picker",
)
@action.boolean(
    "force", title="Overwrite existing output", required=False, default=False, widget="toggle"
)
def convert_pcap(
    input_file: str, output_file: str = "", scl: str = "", force: bool = False
) -> dict[str, Any]:
    """Shares `converter.convert_pcap` with the `convert` CLI command. Failures
    raise: a standalone action's exit status is how the caller learns it failed."""
    from .converter import convert_pcap as _convert
    from .converter import resolve_output

    source = Path(input_file).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    goose = decode.parse_goose({"scl": scl})
    destination = resolve_output(
        source, Path(output_file).expanduser() if output_file.strip() else None, overwrite=force
    )
    return _convert(source, destination, goose=goose)


@action(
    "Demo Capture Path",
    "Where the bundled demo capture is on the machine running the agent. Paste it "
    "into Advanced > Replay PCAP File to try the extension without hardware.",
    standalone=True,
    read_only=True,
)
def demo_capture_path() -> dict[str, Any]:
    return {"status": "success", "path": str(DEMO_PCAP)}


def register_actions(registry: ActionsRegistry) -> list[str]:
    """Register every ``@action``-decorated free function by its bare name.

    The ``GOOSE/`` prefix consumers see comes from
    ``zelos_sdk.init(name="GOOSE", actions=True)``.
    """
    module = sys.modules[__name__]
    registered: list[str] = []
    for name, obj in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        if inspect.isfunction(obj) and hasattr(obj, "_action"):
            registry.register(obj, name=name)
            registered.append(name)
    logger.info("Registered %d GOOSE actions", len(registered))
    return registered
