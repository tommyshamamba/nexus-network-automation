from __future__ import annotations

from pathlib import Path

import pytest

from nexus.inventory import InventoryError, expand_env, load_inventory, parse_inventory
from tests.conftest import EXAMPLES


def test_example_inventory_loads() -> None:
    inv = load_inventory(EXAMPLES / "inventory.yaml", env={})
    assert [d.name for d in inv] == ["access-sw1", "core-sw1", "edge-rtr1", "lab-sw-offline"]
    core = inv.get("core-sw1")
    assert core.platform == "arista_eos"
    assert core.host == "127.0.0.1"  # ${NEXUS_LAB_HOST:-127.0.0.1} default
    assert core.username == "netops"
    assert core.groups == ("core",)
    assert inv.get("lab-sw-offline").timeout == 2


def test_env_expansion_and_defaults() -> None:
    inv = load_inventory(EXAMPLES / "inventory.yaml", env={"NEXUS_LAB_HOST": "devices"})
    assert {d.host for d in inv} == {"devices"}
    assert expand_env({"a": ["${X}", "${Y:-d}"]}, {"X": "1"}) == {"a": ["1", "d"]}
    with pytest.raises(KeyError):
        expand_env("${MISSING}", {})


def test_group_settings_merge_and_device_overrides() -> None:
    inv = parse_inventory(
        {
            "defaults": {"platform": "cisco_ios", "port": 22},
            "groups": {"dc": {"platform": "arista_eos", "port": 830}},
            "devices": [
                {"name": "a", "host": "10.0.0.1", "groups": ["dc"]},
                {"name": "b", "host": "10.0.0.2", "groups": ["dc"], "port": 2222},
                {"name": "c", "host": "sw-c.example.net"},
            ],
        },
        env={},
    )
    assert inv.get("a").platform == "arista_eos" and inv.get("a").port == 830
    assert inv.get("b").port == 2222
    assert inv.get("c").platform == "cisco_ios"


def test_select_by_name_group_and_tag() -> None:
    inv = load_inventory(EXAMPLES / "inventory.yaml", env={})
    assert [d.name for d in inv.select(["core-sw1"])] == ["core-sw1"]
    assert [d.name for d in inv.select(["access"])] == ["access-sw1", "lab-sw-offline"]
    assert [d.name for d in inv.select(["role=edge"])] == ["edge-rtr1"]
    assert len(inv.select([])) == 4
    assert inv.select(["nope"]) == []


def test_all_problems_reported_at_once() -> None:
    with pytest.raises(InventoryError) as ei:
        parse_inventory(
            {
                "devices": [
                    {"name": "dup", "host": "10.0.0.1", "platform": "cisco_ios"},
                    {"name": "dup", "host": "10.0.0.2", "platform": "cisco_ios"},
                    {"name": "x", "host": "not a host!", "platform": "cisco_ios"},
                    {"name": "y", "host": "10.0.0.3", "platform": "vyos"},
                    {"name": "z", "host": "10.0.0.4", "platform": "cisco_ios", "port": 70000},
                    {"name": "p", "host": "10.0.0.5", "platform": "cisco_ios", "password": "s"},
                    {"name": "g", "host": "10.0.0.6", "platform": "cisco_ios", "groups": ["no"]},
                    {"name": "k", "host": "10.0.0.7", "platform": "cisco_ios", "colour": "red"},
                ]
            },
            env={},
        )
    text = str(ei.value)
    for needle in (
        "duplicate device name",
        "not a valid IP/hostname",
        "platform 'vyos'",
        "'port' must be",
        "plaintext 'password'",
        "unknown group",
        "unknown keys",
    ):
        assert needle in text
    assert len(ei.value.problems) == 7


@pytest.mark.parametrize(
    "data",
    [None, [], {"devices": []}, {"devices": "x"}, {"defaults": [], "devices": [{"name": "a"}]}],
)
def test_structural_errors(data: object) -> None:
    with pytest.raises(InventoryError):
        parse_inventory(data, env={})


def test_missing_env_var_is_an_error() -> None:
    with pytest.raises(InventoryError, match="NEXUS_NOPE"):
        parse_inventory(
            {"devices": [{"name": "a", "host": "${NEXUS_NOPE}", "platform": "cisco_ios"}]}, env={}
        )


def test_file_errors(tmp_path: Path) -> None:
    with pytest.raises(InventoryError, match="not found"):
        load_inventory(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("devices: [\n")
    with pytest.raises(InventoryError, match="YAML parse error"):
        load_inventory(bad)


def test_password_comes_from_env_only(monkeypatch: pytest.MonkeyPatch) -> None:
    inv = load_inventory(EXAMPLES / "inventory.yaml", env={})
    d = inv.get("core-sw1")
    monkeypatch.delenv("NEXUS_PASSWORD", raising=False)
    assert d.password() is None
    monkeypatch.setenv("NEXUS_PASSWORD", "from-env")
    assert d.password() == "from-env"
    assert "from-env" not in repr(d.public_dict())
    assert d.public_dict()["auth"] == "password"
