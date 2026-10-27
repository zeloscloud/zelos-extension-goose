"""The one seam onto zelos-packet's GOOSE decoder.

The decoder lives in `zelos_packet`, beside the SOME/IP and DoIP dissectors, and
is switched on the same way: keyword arguments on ``PacketCapture`` and
``PacketDecoder``. This module builds those keywords, says whether the installed
package has them, and names the counters the decoder reports. Nothing else in
the extension spells a GOOSE keyword.

Until a zelos-packet release carries the decoder, `require()` refuses with the
version it needs, and the tests stub `pkg.module()`.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

from . import pkg

#: First zelos-packet release with the GOOSE decoder.
MIN_PACKET_VERSION = "0.0.5"

#: `zelos_packet.Metrics` counters the GOOSE decoder adds, in the `someip_*` shape.
COUNTERS = (
    "goose_frames",
    "goose_messages",
    "goose_gocbs",
    "goose_malformed",
    "goose_unknown_members",
    "goose_stnum_gaps",
    "goose_sqnum_gaps",
    "goose_tal_expired",
)


class ConfigError(ValueError):
    """The configuration cannot be turned into a subscription."""


@dataclass(frozen=True)
class GooseConfig:
    """What the decoder is told: the SCL to name members by. Every control block
    on the segment is decoded. Shared by capture, replay and conversion."""

    scl: tuple[str, ...] = ()

    def kwargs(self) -> dict[str, Any]:
        """The native keyword arguments, `PacketCapture` and `PacketDecoder` alike."""
        return {
            "goose": True,
            "scl": list(self.scl) or None,
        }


def resolve_scl(raw: str | Path) -> Path:
    """An SCL path, `~` expanded and relative to the working directory.

    Raises:
        ConfigError: the file does not exist.
    """
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise ConfigError(f"SCL file not found: {path}")
    return path


def parse_goose(entry: dict) -> GooseConfig:
    """One `interfaces[]` entry's `scl` as a :class:`GooseConfig`."""
    scl = str(entry.get("scl") or "").strip()
    return GooseConfig(scl=(str(resolve_scl(scl)),) if scl else ())


def installed_version() -> str:
    try:
        return metadata.version("zelos-packet")
    except metadata.PackageNotFoundError:
        return "none"


def _documents(cls: Any, word: str) -> bool:
    return word in (getattr(cls, "__doc__", None) or "").lower()


def supported() -> bool:
    """Whether the installed zelos-packet decodes GOOSE and takes a BPF filter.

    Both announce themselves in the native docstrings, the way the ARXML path
    does; a version compare would miss a local build. The filter matters as
    much as the decoder: without it every frame on the station bus is a row.
    """
    if not pkg.available():
        return False
    mod = pkg.module()
    return _documents(mod.PacketDecoder, "goose") and _documents(mod.PacketCapture, "filter")


def require() -> None:
    """Raise unless the installed zelos-packet decodes GOOSE."""
    if not pkg.available():
        raise RuntimeError(pkg.skip_reason())
    if not supported():
        raise RuntimeError(
            f"GOOSE decode needs zelos-packet>={MIN_PACKET_VERSION}; "
            f"installed {installed_version()}"
        )


def counters(metrics: Any) -> dict[str, int]:
    """The GOOSE counters off a `zelos_packet.Metrics`; absent ones read 0."""
    return {name: int(getattr(metrics, name, 0) or 0) for name in COUNTERS}


def control_blocks(capture: Any) -> list[dict[str, Any]]:
    """Every control block a running capture has seen, as plain dicts.

    `PacketCapture.goose_control_blocks()` serves them from the helper's status
    stream, the way `stats()` serves the read-loop counters. Empty on a package
    without it.
    """
    fn = getattr(capture, "goose_control_blocks", None)
    if fn is None:
        return []
    return [dict(block) if isinstance(block, dict) else vars(block) for block in fn()]
