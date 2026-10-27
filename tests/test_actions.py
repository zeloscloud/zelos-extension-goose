"""The action surface: names, flags, and the read-only trio over a fake capture."""

from __future__ import annotations

from zelos_sdk.actions import ActionsRegistry

from zelos_extension_goose import actions
from zelos_extension_goose.capture import CaptureSession, InterfaceConfig
from zelos_extension_goose.demo import DEMO_PCAP


def test_actions_register_under_their_bare_names_and_flags_are_pinned():
    registered = actions.register_actions(ActionsRegistry())
    flags = {
        name: (getattr(actions, name)._action.read_only, getattr(actions, name)._action.hidden)
        for name in registered
    }
    # Every action is read-only: GOOSE is subscribe-only here.
    assert flags == {
        "auto_config": (True, True),
        "list_interfaces": (True, True),
        "check_permissions": (True, False),
        "list_gocbs": (True, False),
        "get_status": (True, False),
        "convert_pcap": (True, False),
        "demo_capture_path": (True, False),
    }
    assert actions.demo_capture_path()["path"] == str(DEMO_PCAP)
    assert DEMO_PCAP.is_file()


def test_trio_reports_nothing_running():
    actions.CAPTURES.clear()
    assert actions.list_gocbs()["status"] == "warning"
    assert actions.get_status()["status"] == "warning"


def test_blocks_and_status_over_a_running_capture(fake_packet):
    session = CaptureSession(InterfaceConfig("en0", "en0"), "GOOSE")
    session.start()
    actions.CAPTURES.clear()
    actions.CAPTURES["en0"] = session
    try:
        [block] = actions.list_gocbs()["control_blocks"]
        assert (block["interface"], block["goID"], block["alive"]) == ("en0", "P1Q1BCU_Trip", True)
        assert [m["name"] for m in block["members"]] == ["d00", "d01"]
        [status] = actions.get_status("en0")["interfaces"]
        assert status["running"] and status["goose_gocbs"] == 2
    finally:
        actions.CAPTURES.clear()
        session.stop()


def test_list_interfaces_and_auto_config_follow_the_form_contracts(fake_packet):
    assert actions.list_interfaces()["choices"] == [
        {"value": "en0", "detail": "up · 10.0.0.5"},
        {"value": "lo0", "detail": "up · loopback · 127.0.0.1"},
    ]
    assert actions.auto_config()["config"] == {"interfaces": [{"interface": "en0"}]}


def test_check_permissions_without_the_package_still_carries_remediation(monkeypatch):
    from zelos_extension_goose import pkg

    monkeypatch.setattr(pkg, "available", lambda: False)
    result = actions.check_permissions()
    assert result["status"] == "error"
    assert "Replay PCAP File" in result["remediation"]
