"""Config: schema defaults, `parse_interfaces`, and the two agreeing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from zelos_sdk.extensions import load_config

from zelos_extension_goose.capture import ConfigError, parse_interfaces
from zelos_extension_goose.decode import GooseConfig

from .conftest import REPO_ROOT, SCHEMA_PATH


def load(tmp_path: Path, raw: dict) -> dict:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(raw))
    return load_config(config_path=config_file, schema_path=SCHEMA_PATH)


class TestSchema:
    def test_empty_config_gets_the_defaults(self, tmp_path: Path):
        config = load(tmp_path, {})
        assert config["interfaces"] == []
        assert config["advanced"] == {"prefix": "GOOSE", "log_level": "INFO"}

    def test_shipped_config_json_validates(self, tmp_path: Path):
        shipped = json.loads((REPO_ROOT / "config.json").read_text())
        assert load(tmp_path, shipped)["advanced"]["prefix"] == "GOOSE"

    def test_promiscuous_is_not_a_setting(self, tmp_path: Path):
        with pytest.raises(Exception, match="promiscuous"):
            load(tmp_path, {"advanced": {"promiscuous": False}})

    def test_an_empty_prefix_is_refused(self, tmp_path: Path):
        with pytest.raises(Exception, match="prefix: '' should be non-empty"):
            load(tmp_path, {"advanced": {"prefix": ""}})


class TestParseInterfaces:
    def test_defaults(self):
        [cfg] = parse_interfaces({"interfaces": [{"interface": "eth0"}]})
        assert (cfg.interface, cfg.name) == ("eth0", "eth0")
        assert cfg.goose == GooseConfig()

    def test_vlan_interface_name_is_sanitized(self):
        [cfg] = parse_interfaces({"interfaces": [{"interface": "eth0.100"}]})
        assert (cfg.interface, cfg.name) == ("eth0.100", "eth0_100")

    def test_scl_resolves(self, tmp_path: Path):
        scl = tmp_path / "station.scd"
        scl.write_text("<SCL/>")
        [cfg] = parse_interfaces({"interfaces": [{"interface": "eth0", "scl": str(scl)}]})
        assert cfg.goose == GooseConfig(scl=(str(scl.resolve()),))

    def test_missing_scl_is_a_config_error(self, tmp_path: Path):
        with pytest.raises(ConfigError, match="SCL file not found"):
            parse_interfaces({"interfaces": [{"interface": "eth0", "scl": str(tmp_path / "x")}]})

    @pytest.mark.parametrize(
        ("entry", "match"),
        [
            ({}, "missing 'interface'"),
            ({"interface": "eth0", "name": "a/b"}, "not allowed"),
            ({"interface": "eth0", "name": "log"}, "reserved"),
        ],
    )
    def test_bad_entries_name_the_field(self, entry: dict, match: str):
        with pytest.raises(ConfigError, match=match):
            parse_interfaces({"interfaces": [entry]})

    def test_duplicate_names_are_a_hard_error(self):
        with pytest.raises(ConfigError, match="Duplicate interface name"):
            parse_interfaces({"interfaces": [{"interface": "eth0.1"}, {"interface": "eth0:1"}]})
