"""Shared fixtures: a stand-in `zelos_packet` with the GOOSE keywords this
extension expects, so the wiring is exercised without a release that has them.

Decode correctness is not tested here; it lives with the decoder in zelos-packet.
Tests that need the real wheel (keyword binding) use ``needs_real_packet``.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from zelos_extension_goose import pkg
from zelos_extension_goose.demo import DEMO_PCAP, generate

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "config.schema.json"


class FakeCapture:
    """Records the kwargs it was constructed with; never touches a socket.

    The real ``PacketCapture`` signature plus the proposed GOOSE keywords,
    spelled out rather than ``**kwargs``, so a keyword drifting out of
    `capture_kwargs()` fails here.
    """

    instances: list[FakeCapture] = []

    def __init__(
        self,
        interface,
        snaplen=0,
        promiscuous=False,
        buffer_bytes=2 * 1024 * 1024,
        exclude_outgoing=False,
        source_name="Packet",
        log_frames=True,
        stored_frame_bytes=256,
        stats_interval=1.0,
        exclude_agent_addrs=None,
        exclude_agent_port=None,
        source=None,
        name=None,
        agent_url=None,
        someip_sd_port=None,
        someip_ports=None,
        doip_port=None,
        arxml=None,
        filter=None,
        goose=False,
        scl=None,
    ):
        self.kwargs = {k: v for k, v in locals().items() if k != "self"}
        self.started = self.stopped = False
        FakeCapture.instances.append(self)

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def stats(self) -> SimpleNamespace:
        return SimpleNamespace(
            packets_read=12, bytes_read=1024, packets_truncated=0, kernel_drops=0,
            decode_stall_ms=0.0, read_errors=0,
        )  # fmt: skip

    def metrics(self) -> SimpleNamespace:
        return SimpleNamespace(
            goose_frames=12, goose_messages=12, goose_gocbs=2, goose_malformed=0,
            goose_unknown_members=0, goose_stnum_gaps=1, goose_sqnum_gaps=0, goose_tal_expired=0,
        )  # fmt: skip

    def goose_control_blocks(self) -> list[dict]:
        return [
            {
                "go_id": "P1Q1BCU_Trip",
                "gocb_ref": "P1Q1BCU/LLN0$GO$gcbTrip",
                "appid": 0x1000,
                "src_mac": "02:00:00:00:00:a1",
                "st_num": 2,
                "sq_num": 6,
                "last_seen_ns": 1_700_000_005_060_000_000,
                "values": {"d00": True, "d01": 0},
            }
        ]


class FakeDecoder:
    """Counts the records in a pcap so replay tests assert something real."""

    instances: list[FakeDecoder] = []

    def __init__(self, name="capture", source_name="Packet", source=None, **kwargs):
        self.kwargs = {"name": name, "source_name": source_name, "source": source, **kwargs}
        self.flushed = False
        self.realtime = self.path = None
        FakeDecoder.instances.append(self)

    def convert_file(self, path: str, *, realtime: bool = False) -> int:
        self.realtime, self.path = realtime, path
        data = Path(path).read_bytes()
        assert struct.unpack("<I", data[:4])[0] == generate.PCAP_MAGIC
        offset, packets = 24, 0
        while offset + 16 <= len(data):
            incl = struct.unpack("<IIII", data[offset : offset + 16])[2]
            offset += 16 + incl
            packets += 1
        return packets

    def flush(self) -> None:
        self.flushed = True


FakeDecoder.__doc__ = (FakeDecoder.__doc__ or "") + "\n\n    goose (bool): decode GOOSE."


class FakeCapturePermissionError(PermissionError):
    """Stands in for `zelos_packet.CapturePermissionError`."""


class FakeTraceSource:
    def __init__(self, source_name, namespace=None, *, cached: bool = True) -> None:
        self.name = source_name
        self.namespace = namespace
        self.cached = cached


FAKE_REMEDIATION = "fake native remediation: do the thing"


def make_fake_module(*, capture_cls=FakeCapture) -> SimpleNamespace:
    return SimpleNamespace(
        PacketCapture=capture_cls,
        PacketDecoder=FakeDecoder,
        CapturePermissionError=FakeCapturePermissionError,
        list_interfaces=lambda: [
            SimpleNamespace(name="lo0", is_up=True, is_loopback=True, addresses=["127.0.0.1"]),
            SimpleNamespace(name="en0", is_up=True, is_loopback=False, addresses=["10.0.0.5"]),
        ],
        capture_supported=lambda: True,
        permission_remediation=lambda: FAKE_REMEDIATION,
        sanitize_name=lambda raw: (
            __import__("re").sub(r"[.:@/\s]+", "_", raw.strip()).strip("_") or "capture"
        ),
    )


def install_fake(monkeypatch, *, capture_cls=FakeCapture) -> SimpleNamespace:
    """A stand-in `zelos_packet` (and trace source) for one test."""
    from zelos_extension_goose import capture as capture_mod

    FakeCapture.instances.clear()
    FakeDecoder.instances.clear()
    module = make_fake_module(capture_cls=capture_cls)
    monkeypatch.setattr(pkg, "module", lambda: module)
    monkeypatch.setattr(pkg, "available", lambda: True)
    monkeypatch.setattr(capture_mod, "make_trace_source", FakeTraceSource)
    return module


@pytest.fixture
def fake_packet(monkeypatch) -> SimpleNamespace:
    return install_fake(monkeypatch)


@pytest.fixture
def demo_pcap(tmp_path: Path) -> Path:
    """A copy of the bundled capture, so outputs land in `tmp_path`."""
    return Path(shutil.copy(DEMO_PCAP, tmp_path / DEMO_PCAP.name))


needs_real_packet = pytest.mark.skipif(
    not pkg.available(), reason=pkg.skip_reason() or "zelos-packet unavailable"
)
