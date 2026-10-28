"""Zelos GOOSE extension.

IEC 61850 GOOSE subscriber: live capture (Linux AF_PACKET, macOS /dev/bpf) and
pcap replay, decoded by the Rust-cored `zelos-packet` package.
"""

from .capture import (
    CaptureDeniedError,
    CaptureSession,
    ConfigError,
    InterfaceConfig,
    parse_interfaces,
    replay_pcap,
)

#: The namespace actions are addressed under. One definition for both the live
#: registration (`zelos_sdk.init(name=ACTION_PREFIX, actions=True)`) and the
#: at-rest inventory the packaging step dumps from `main.py`, which re-exports
#: it. A mismatch silently produces two unrelated action trees.
#:
#: Matches `name` in `extension.toml` and the default `advanced.prefix`, so the
#: address a user reads in the app is the one they type.
ACTION_PREFIX = "GOOSE"

__all__ = [
    "ACTION_PREFIX",
    "CaptureDeniedError",
    "CaptureSession",
    "ConfigError",
    "InterfaceConfig",
    "parse_interfaces",
    "replay_pcap",
]
