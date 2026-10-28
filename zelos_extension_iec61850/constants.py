"""Shared constants: trace naming, which names are usable, and the wire facts."""

from collections.abc import Collection

import zelos_sdk

#: Default trace source (`advanced.prefix`). Per-frame rows land at
#: `<prefix>/<name>/goose`; control blocks always sit under the fixed `GOOSE`
#: source as `GOOSE/<goID>`, whatever the prefix.
DEFAULT_PREFIX = "GOOSE"

#: The extension's logs land at `<prefix>/log`, so no name may be `log`.
RESERVED_NAMES = ("log",)

#: Only GOOSE reaches the decoder, tagged (802.1Q) or not. A station bus also
#: carries Sampled Values at thousands of frames a second; without this every
#: one of them would be a row.
GOOSE_BPF = "ether proto 0x88b8 or (vlan and ether proto 0x88b8)"
#: A full Ethernet frame: a GOOSE PDU may use every byte of it.
SNAPLEN = 1518
BUFFER_SIZE = 8 * 1024 * 1024


def name_error(
    value: str, label: str, reserved: Collection[str] = (), *, required: bool = False
) -> str | None:
    """Why user-typed `value` is not a legal trace name, or None if it is.

    Names become trace path segments, so a separator (`/ . @ :`) would silently
    re-nest the tree. Anything the SDK sanitizer rewrites is rejected, not renamed.
    Empty is legal (the caller's default applies) unless `required`.
    """
    if not value:
        return f"Invalid {label}: it must not be empty." if required else None
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
