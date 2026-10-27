"""Shared constants: trace naming, which names are usable, and the wire facts."""

from collections.abc import Collection

import zelos_sdk

#: Default leading trace-source name (`advanced.prefix`).
DEFAULT_PREFIX = "GOOSE"

#: Source the extension's logs take when the prefix is cleared; with a prefix
#: they land in it as `<prefix>/log`. Both names are reserved as interface names.
LOG_SOURCE_NAME = "goose_log"
RESERVED_NAMES = ("log", LOG_SOURCE_NAME)

#: IEC 61850-8-1 GOOSE EtherType.
GOOSE_ETHERTYPE = 0x88B8
#: Only GOOSE reaches the decoder, tagged (802.1Q) or not. A station bus also
#: carries Sampled Values at thousands of frames a second; without this every
#: one of them would be a row.
GOOSE_BPF = "ether proto 0x88b8 or (vlan and ether proto 0x88b8)"
#: A full Ethernet frame: a GOOSE PDU may use every byte of it.
SNAPLEN = 1518
BUFFER_SIZE = 8 * 1024 * 1024


def trace_layout(prefix: str, interface: str) -> tuple[str, str | None]:
    """The one trace-naming rule: (source name, event prefix) for an interface.

    With a prefix, one shared source carries every interface's per-frame rows,
    `<prefix>/<interface>/goose`. Cleared, each interface owns its source.
    Decoded control blocks are global to the station bus and always live under
    the fixed `GOOSE` signal source, whatever the prefix.
    """
    if prefix:
        return prefix, interface
    return interface, None


def name_error(value: str, label: str, reserved: Collection[str] = ()) -> str | None:
    """Why user-typed `value` is not a legal trace name, or None if it is.

    Names become trace path segments, so a separator (`/ . @ :`) would silently
    re-nest the tree. Anything the SDK sanitizer rewrites is rejected, not renamed.
    """
    if not value:
        return None
    if value in reserved:
        return f"Invalid {label} {value!r}: reserved for the extension's own logs."
    clean = zelos_sdk.sanitize_name(value, kind="source")
    if clean == value:
        return None
    offender = next((c for c, ok in zip(value, clean, strict=False) if c != ok), value[-1])
    return (
        f"Invalid {label} {value!r}: {offender!r} is not allowed. "
        "Use letters, digits, space, '_' or '-'."
    )
