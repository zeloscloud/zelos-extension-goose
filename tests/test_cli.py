"""CLI and app-mode wiring: the bundled demo, replay/convert through the seam,
and the entry module."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from zelos_extension_iec61850.cli import app
from zelos_extension_iec61850.converter import convert_pcap, resolve_output
from zelos_extension_iec61850.demo import DEMO_PCAP, generate

from .conftest import FakeCapture, FakeDecoder


class TestDemoCapture:
    def test_committed_bytes_match_the_generator(self):
        """Drift guard: after changing the generator, run `just demo-pcap`."""
        assert DEMO_PCAP.read_bytes() == generate.demo_pcap_bytes()

    def test_is_a_small_minute_of_goose_from_two_publishers_one_tagged(self):
        assert len(DEMO_PCAP.read_bytes()) < 50_000
        frames = generate.demo_frames()
        assert 55_000_000 < frames[-1][0] <= generate.DURATION_US
        for _, frame in frames:
            assert frame[:6] == generate.GOOSE_MULTICAST
            tagged = frame[12:14] == b"\x81\x00"
            assert frame[16:18] == b"\x88\xb8" if tagged else frame[12:14] == b"\x88\xb8"
        assert any(frame[12:14] == b"\x81\x00" for _, frame in frames), "one publisher is tagged"


@pytest.fixture
def app_config(fake_packet, monkeypatch) -> dict:
    """`run_app_mode` reads this dict as its config; no agent, no signal handlers."""
    config: dict = {}
    monkeypatch.setattr(app, "load_config", lambda: config)
    monkeypatch.setattr(app, "init_sdk", lambda _prefix: None)
    monkeypatch.setattr(app, "_install_replay_shutdown", lambda: None)
    return config


class TestAppMode:
    def test_demo_flag_replays_the_bundled_capture_once_and_exits(self, app_config):
        import main

        result = CliRunner().invoke(main.cli, ["--demo"])
        assert result.exit_code == 0, result.output
        [decoder] = FakeDecoder.instances
        assert decoder.path == str(DEMO_PCAP)
        assert decoder.realtime is True and decoder.flushed
        assert (decoder.kwargs["name"], decoder.kwargs["source"].name) == ("goose-demo", "GOOSE")

    def test_replay_ignores_interfaces_and_takes_replay_scl(self, app_config, tmp_path: Path):
        scl = tmp_path / "station.scd"
        scl.write_text("<SCL/>")
        app_config["interfaces"] = [{"interface": "en0"}]
        app_config["advanced"] = {"replay_pcap": str(DEMO_PCAP), "replay_scl": str(scl)}
        app.run_app_mode(False, None)
        assert FakeCapture.instances == []
        [decoder] = FakeDecoder.instances
        assert decoder.kwargs["scl"] == [str(scl.resolve())]

    def test_nothing_configured_fails_with_one_line(self, app_config, caplog):
        with pytest.raises(SystemExit, match="1"):
            app.run_app_mode(False, None)
        assert "Nothing to do" in caplog.text
        assert FakeDecoder.instances == []

    def test_a_replay_that_fails_mid_run_fails_with_one_line(self, app_config, monkeypatch, caplog):
        app_config["advanced"] = {"replay_pcap": str(DEMO_PCAP)}
        monkeypatch.setattr(
            FakeDecoder, "convert_file", lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
        )
        with pytest.raises(SystemExit, match="1"):
            app.run_app_mode(False, None)
        assert f"Replay of {DEMO_PCAP} failed: boom" in caplog.text


class TestConvert:
    def test_convert_never_calls_sdk_init(self, fake_packet, demo_pcap: Path, monkeypatch):
        import zelos_sdk

        monkeypatch.setattr(
            zelos_sdk, "init", lambda *a, **k: pytest.fail("convert must not call init()")
        )
        result = convert_pcap(demo_pcap, resolve_output(demo_pcap))
        assert result["packets"] == len(generate.demo_frames())
        assert Path(result["output_file"]).exists()

    def test_output_defaults_and_overwrite(self, tmp_path: Path):
        assert resolve_output(Path("/c/run1.pcapng.gz")) == Path("/c/run1.trz")
        existing = tmp_path / "run1.trz"
        existing.touch()
        with pytest.raises(FileExistsError):
            resolve_output(tmp_path / "run1.pcap")
        assert resolve_output(tmp_path / "run1.pcap", overwrite=True) == existing


class TestEntry:
    def test_group_lists_every_subcommand(self):
        import main

        result = CliRunner().invoke(main.cli, ["--help"])
        assert result.exit_code == 0
        for cmd in ("interfaces", "check", "capture", "replay", "convert"):
            assert cmd in result.output

    def test_an_empty_prefix_is_refused_before_capture(self, fake_packet):
        import main

        result = CliRunner().invoke(main.cli, ["capture", "en0", "--prefix", ""])
        assert result.exit_code != 0
        assert "must not be empty" in result.output
        assert FakeCapture.instances == []

    def test_convert_command_refuses_a_missing_scl_legibly(self, fake_packet, demo_pcap: Path):
        import main

        result = CliRunner().invoke(main.cli, ["convert", str(demo_pcap), "--scl", "/nope.scd"])
        assert result.exit_code != 0
        assert "SCL file not found" in result.output
