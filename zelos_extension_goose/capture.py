"""Per-interface subscription lifecycle, config parsing, and permission remediation.

One :class:`CaptureSession` per live interface, each backed by a
``zelos_packet.PacketCapture`` running in the ``zelos-packet-helper`` process:
the helper holds whatever privilege the open needs, drops it before it reads a
byte, and streams decoded rows straight to the agent over its own SDK
connection. Nothing passes through this process.

Per-frame rows follow the prefix rule (``<prefix>/<interface>/goose``, or the
interface's own source when the prefix is cleared). Decoded control blocks are
global to the station bus and always sit under the fixed ``GOOSE`` signal
source as ``GOOSE/<goID>``, whatever the prefix.
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import decode, pkg
from .constants import BUFFER_SIZE, DEFAULT_PREFIX, GOOSE_BPF, SNAPLEN, name_error
from .decode import ConfigError, GooseConfig

logger = logging.getLogger(__name__)

#: Catalog path separators, as a fallback for `zelos_packet.sanitize_name`:
#: a VLAN interface is literally named `eth0.100`.
_PATH_SEPARATORS = re.compile(r"[.:@/\s]+")

#: `zelos_packet.CaptureStats` getters reported by `get_status`.
STATS_FIELDS = (
    "packets_read",
    "bytes_read",
    "packets_truncated",
    "kernel_drops",
    "decode_stall_ms",
    "read_errors",
)


class CaptureDeniedError(RuntimeError):
    """The OS refused a capture handle. Carries copy-pasteable remediation."""

    def __init__(self, message: str, remediation: str) -> None:
        super().__init__(message)
        self.remediation = remediation


@dataclass(frozen=True)
class InterfaceConfig:
    """One live `interfaces[]` entry, with every default already applied."""

    interface: str
    name: str
    goose: GooseConfig = GooseConfig()


def sanitize_capture_name(raw: str) -> str:
    """Make `raw` safe as an event-name prefix, by the package's own rule."""
    native = pkg.sanitize_name(raw)
    if native is not None:
        return native
    cleaned = _PATH_SEPARATORS.sub("_", raw.strip()).strip("_")
    return cleaned or "capture"


def parse_interfaces(config: dict) -> list[InterfaceConfig]:
    """Turn the `interfaces` array into :class:`InterfaceConfig` values.

    Defaults are applied here as well as in the JSON Schema, so CLI callers,
    which never go through `load_config`, get identical behaviour.

    Raises:
        ConfigError: on a missing interface, a bad name, or a duplicate name.
        Duplicates are a hard error rather than a silent rename: the sessions
        share one trace source, and event registration there is strict-create.
    """
    entries = config.get("interfaces") or []
    if not isinstance(entries, list):
        raise ConfigError("'interfaces' must be a list")

    parsed: list[InterfaceConfig] = []
    seen: dict[str, str] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"interfaces[{index}] must be an object")
        interface = str(entry.get("interface") or "").strip()
        if not interface:
            raise ConfigError(
                f"interfaces[{index}] is missing 'interface'. Run the 'List interfaces' "
                "action to see the interfaces on the machine running the agent."
            )

        raw_name = str(entry.get("name") or "").strip()
        if error := name_error(raw_name, "interface Name", ("log",)):
            raise ConfigError(error)
        name = sanitize_capture_name(raw_name or interface)
        if name in seen:
            raise ConfigError(
                f"Duplicate interface name {name!r} (interfaces {seen[name]!r} and "
                f"{interface!r}). Give each entry a unique 'name'."
            )
        seen[name] = interface

        parsed.append(
            InterfaceConfig(
                interface=interface,
                name=name,
                goose=decode.parse_goose(entry),
            )
        )
    return parsed


# ─── Permission remediation ─────────────────────────────────────────────────

_REPLAY_HINT = (
    "No capture rights on this machine? Set 'Replay PCAP File' in the extension\n"
    "config to decode a .pcap/.pcapng instead; that path opens no capture handle\n"
    "and needs no privileges. The 'Demo Capture Path' action names a bundled one."
)


def builtin_grant_instructions(*, system: str | None = None, executable: str | None = None) -> str:
    """Capture-privilege instructions per platform, usable even when the
    package cannot be imported. `executable` is named outright: the grant runs
    `zelos_packet`, so it must be the interpreter this extension runs under."""
    system = system or platform.system()
    executable = executable or sys.executable or "python3"
    if system in ("Linux", "Darwin"):
        body = f"""
Live capture needs a one-time grant on this machine:

    sudo {executable} -m zelos_packet install-helper

Then log out and back in, and restart the agent: a session's groups are fixed
at login. Check the grant with:

    {executable} -m zelos_packet status
"""
    else:
        # Platform support is zelos-packet's call (`capture_supported()`); when a
        # Windows backend ships there, this branch and the README line go away.
        body = f"""
The installed zelos-packet has no live capture backend for {system!r}; today it
captures on Linux (AF_PACKET) and macOS (/dev/bpf).
"""
    return f"{body.strip()}\n\n{_REPLAY_HINT}"


def capture_grant_instructions(*, system: str | None = None) -> str:
    """Prefers ``zelos_packet.permission_remediation()``: that package opens the
    handle, so its text is authoritative. Falls back to the built-in text."""
    if (system or platform.system()) == platform.system():
        native = pkg.permission_remediation().strip()
        if native:
            return f"{native}\n\n{_REPLAY_HINT}"
    return builtin_grant_instructions(system=system)


def remediation_text(interface: str) -> str:
    return (
        f"Permission denied opening a capture handle on {interface!r}.\n\n"
        + capture_grant_instructions()
    )


def _diagnosis(exc: BaseException) -> str:
    """The native error's first paragraph: what went wrong, not how to fix it."""
    return str(exc).split("\n\n", 1)[0].strip()


# ─── Trace sources ──────────────────────────────────────────────────────────

#: The live namespace's shared source, built on first use: ONE object, not one
#: per session. Two `TraceSource`s under one name both register, and the query
#: layer then keeps only the newest, silently hiding the other's rows.
_live_sources: dict[str, Any] = {}


def make_trace_source(source_name: str, namespace: Any = None, *, cached: bool = True) -> Any:
    """The source every subscription in this process writes into, by name.

    `namespace` of None is the global namespace `zelos_sdk.init()` set up. A
    conversion passes its own namespace and gets its own source. `cached`
    picks `TraceSourceCache` (live: last-value navigation) over a plain
    `TraceSource` (conversion: the only type the native sink batch-emits to).
    """
    import zelos_sdk

    factory = zelos_sdk.TraceSourceCache if cached else zelos_sdk.TraceSource
    if namespace is not None:
        return factory(source_name, namespace=namespace)
    if source_name not in _live_sources:
        _live_sources[source_name] = factory(source_name, namespace=None)
    return _live_sources[source_name]


# ─── Capture session ────────────────────────────────────────────────────────


@dataclass
class CaptureSession:
    """Lifecycle wrapper around one ``zelos_packet.PacketCapture``."""

    config: InterfaceConfig
    source_name: str
    _capture: Any = field(default=None, init=False, repr=False)

    @property
    def name(self) -> str:
        return self.config.name

    def capture_kwargs(self) -> dict[str, Any]:
        """Arguments handed to ``PacketCapture``. Split out so tests can assert
        them without constructing anything.

        Promiscuous is always on: GOOSE is multicast to 01-0C-CD-01-xx-xx, and
        a NIC not in promiscuous mode drops every frame. The BPF keeps the
        rest of the station bus (Sampled Values, IP) out of the trace, and it
        is also why no agent-traffic exclusion is configured: nothing the agent
        sends is EtherType 0x88B8.
        """
        return {
            "interface": self.config.interface,
            "name": self.config.name,
            "source_name": self.source_name,
            "snaplen": SNAPLEN,
            "promiscuous": True,
            "buffer_bytes": BUFFER_SIZE,
            "filter": GOOSE_BPF,
            "exclude_agent_addrs": [],
            **self.config.goose.kwargs(),
        }

    def start(self) -> None:
        """Construct the capture and begin emitting. `zelos_sdk.init()` must
        already have run. A privilege failure surfaces here with remediation."""
        decode.require()
        try:
            self._capture = pkg.module().PacketCapture(**self.capture_kwargs())
            self._capture.start()
        except Exception as exc:
            self._capture = None
            if pkg.is_permission_error(exc):
                raise CaptureDeniedError(
                    f"Capture on {self.config.interface!r} was denied: {_diagnosis(exc)}",
                    remediation_text(self.config.interface),
                ) from exc
            raise
        logger.info(
            "Subscribed to GOOSE on %s into %s.%s (promiscuous, scl=%s)",
            self.config.interface,
            self.source_name,
            self.config.name,
            list(self.config.goose.scl) or "-",
        )

    def status(self) -> dict[str, Any]:
        """Read-loop counters plus the GOOSE counters, or a not-started marker."""
        cap = self._capture
        if cap is None:
            return {"interface": self.config.interface, "name": self.name, "running": False}
        stats = cap.stats()
        return {
            "interface": self.config.interface,
            "name": self.name,
            "running": True,
            **{f: getattr(stats, f, None) for f in STATS_FIELDS},
            **decode.counters(cap.metrics()),
        }

    def control_blocks(self) -> list[dict[str, Any]]:
        return decode.control_blocks(self._capture) if self._capture is not None else []

    def stop(self) -> None:
        """``PacketCapture.stop()`` is bounded (~3s): it signals the helper,
        which drains and hands everything to the agent, then reaps it."""
        if self._capture is None:
            return
        try:
            self._capture.stop()
        except Exception:
            logger.exception("Error stopping capture on %s", self.config.interface)
        self._capture = None
        logger.info("Stopped capture on %s", self.config.interface)


# ─── Interfaces, replay, permission probe ───────────────────────────────────


def list_interfaces() -> list[dict[str, Any]]:
    """Enumerate NICs on the machine running the agent."""
    return [
        {
            "name": getattr(iface, "name", str(iface)),
            "is_up": getattr(iface, "is_up", None),
            "is_loopback": getattr(iface, "is_loopback", None),
            "addresses": list(getattr(iface, "addresses", []) or []),
        }
        for iface in pkg.module().list_interfaces()
    ]


def make_decoder(
    name: str,
    source_name: str,
    *,
    namespace: Any = None,
    cached: bool = True,
    goose: GooseConfig = GooseConfig(),
) -> Any:
    """A ``PacketDecoder`` emitting into `namespace` under a sanitized `name`.

    Shared by replay (global namespace, streaming to an agent) and conversion
    (its own namespace, writing a file), so the two cannot drift on naming or
    constructor keywords.
    """
    decode.require()
    # Control blocks always land on the fixed `GOOSE` source, in the same
    # namespace as the rows: left to its default, zelos-packet would make one
    # in the global namespace, which a conversion's writer never sees.
    return pkg.module().PacketDecoder(
        name=sanitize_capture_name(name),
        source=make_trace_source(source_name, namespace, cached=cached),
        goose_source=make_trace_source(DEFAULT_PREFIX, namespace, cached=cached),
        **goose.kwargs(),
    )


def replay_pcap(
    path: str | Path,
    *,
    name: str,
    source_name: str,
    goose: GooseConfig = GooseConfig(),
) -> dict[str, Any]:
    """Decode a pcap/pcapng into the *live* trace namespace. No privileges required.

    Paced at the capture's own rate and shifted so the first frame lands at
    now. Every frame in the file gets a `packets` row, as the Packet extension
    records; only GOOSE frames get `goose` rows and control block events.
    """
    pcap = Path(path).expanduser()
    if not pcap.exists():
        raise ConfigError(f"Capture file not found: {pcap}")
    logger.info("Replaying %s into %s.%s", pcap, source_name, sanitize_capture_name(name))
    decoder = make_decoder(name, source_name, goose=goose)
    count = decoder.convert_file(str(pcap), realtime=True)
    decoder.flush()
    logger.info("Replay of %s complete: %d packets", pcap.name, count)
    return {"file": str(pcap), "packets": count}


def probe_permissions(interface: str | None = None) -> dict[str, Any]:
    """Report whether live capture would work, from `zelos_packet status`,
    without opening a handle. Every failure carries remediation."""
    system = platform.system()
    supported = pkg.capture_supported() if pkg.available() else system in ("Linux", "Darwin")

    def denied(reason: str, target: str | None = None, remediation: str | None = None) -> dict:
        return {
            "supported": supported,
            "can_capture": False,
            "platform": system,
            "interface": target or "",
            "reason": reason,
            "remediation": remediation if remediation is not None else capture_grant_instructions(),
        }

    if not pkg.available():
        return denied(pkg.skip_reason(), interface)
    if not decode.supported():
        try:
            decode.require()
        except RuntimeError as exc:
            return denied(str(exc), interface, remediation="")

    target = interface
    if not target:
        candidates = list_interfaces()
        pool = [i for i in candidates if i["is_up"] and not i["is_loopback"]] or candidates
        if not pool:
            return denied("No network interfaces were reported by zelos-packet")
        target = str(pool[0]["name"])

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "zelos_packet", "status"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as exc:
        return denied(f"{type(exc).__name__}: {exc}", target)
    if proc.returncode != 0:
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        return denied(
            lines[-1] if lines else "zelos_packet status reported no capture privilege",
            target,
            remediation=remediation_text(target),
        )
    return {
        "supported": True,
        "can_capture": True,
        "platform": system,
        "interface": target,
        "reason": "",
        "remediation": "",
    }
