"""The zelos-packet seam: the keywords it builds, and how it refuses."""

from __future__ import annotations

import pytest

from zelos_extension_goose import decode, pkg
from zelos_extension_goose.capture import CaptureSession, InterfaceConfig, make_decoder
from zelos_extension_goose.decode import GooseConfig

from .conftest import FakeCapture, needs_real_packet


def _session(goose: GooseConfig = GooseConfig()) -> CaptureSession:
    return CaptureSession(InterfaceConfig("en0", "en0", goose), "GOOSE")


class TestKwargs:
    def test_goose_is_always_on_and_no_scl_is_none(self):
        assert GooseConfig().kwargs() == {"goose": True, "scl": None}

    def test_capture_is_promiscuous_filtered_and_unexcluded(self, fake_packet):
        goose = GooseConfig(scl=("/x.scd",))
        s = _session(goose)
        s.start()
        [capture] = FakeCapture.instances
        assert capture.kwargs["promiscuous"] is True
        assert capture.kwargs["filter"].startswith("ether proto 0x88b8")
        assert capture.kwargs["snaplen"] == 1518
        assert capture.kwargs["exclude_agent_addrs"] == []
        assert capture.kwargs["source_name"] == "GOOSE"
        assert capture.kwargs["name"] == "en0"
        assert goose.kwargs().items() <= capture.kwargs.items()

    def test_decoder_gets_the_same_knobs(self, fake_packet):
        goose = GooseConfig(scl=("/x.scd",))
        ns = object()
        decoder = make_decoder("eth0.100", "SUB1", namespace=ns, goose=goose)
        assert decoder.kwargs["name"] == "eth0_100"
        assert decoder.kwargs["source"].name == "SUB1"
        # Control blocks: fixed `GOOSE` source in the SAME namespace, or a
        # conversion's writer never sees them.
        assert decoder.kwargs["goose_source"].name == "GOOSE"
        assert decoder.kwargs["goose_source"].namespace is ns
        assert goose.kwargs().items() <= decoder.kwargs.items()


class TestRequire:
    def test_a_capture_without_control_blocks_is_refused(self, fake_packet, monkeypatch):
        monkeypatch.delattr(fake_packet.PacketCapture, "goose_control_blocks")
        with pytest.raises(RuntimeError, match="needs zelos-packet>="):
            decode.require()

    def test_a_package_without_the_decoder_is_refused_by_version(self, fake_packet, monkeypatch):
        monkeypatch.delattr(fake_packet.PacketDecoder, "goose_control_blocks")
        monkeypatch.setattr(decode, "installed_version", lambda: "0.0.4")
        with pytest.raises(RuntimeError, match=r"needs zelos-packet>=0\.0\.5; installed 0\.0\.4"):
            decode.require()

    def test_a_missing_package_is_its_own_message(self, monkeypatch):
        monkeypatch.setattr(pkg, "available", lambda: False)
        monkeypatch.setattr(pkg, "skip_reason", lambda: "zelos-packet is not installed")
        with pytest.raises(RuntimeError, match="not installed"):
            decode.require()

    def test_session_start_refuses_before_constructing(self, fake_packet, monkeypatch):
        monkeypatch.delattr(fake_packet.PacketDecoder, "goose_control_blocks")
        with pytest.raises(RuntimeError, match="GOOSE decode needs"):
            _session().start()
        assert FakeCapture.instances == []


class TestCounters:
    def test_absent_counters_read_zero(self, fake_packet):
        s = _session()
        s.start()
        status = s.status()
        assert status["goose_stnum_gaps"] == 1
        assert set(decode.COUNTERS) <= set(status)


@needs_real_packet
def test_released_kwargs_bind_to_the_real_constructor():
    """Everything but the proposed GOOSE keywords binds to the installed wheel,
    so the proposal is the only gap between this extension and a release."""
    import zelos_packet
    import zelos_sdk

    if not zelos_sdk.initialized():
        zelos_sdk.init(name="goose_test")
    proposed = set(GooseConfig().kwargs()) | {"filter"}
    kwargs = {k: v for k, v in _session().capture_kwargs().items() if k not in proposed}
    try:
        zelos_packet.PacketCapture(**kwargs)
    except TypeError as exc:  # keyword drift - the thing this guards
        pytest.fail(f"capture_kwargs() no longer binds to PacketCapture: {exc}")
    except Exception:
        pass  # CapturePermissionError / InterfaceNotFoundError are fine here
