from __future__ import annotations

from pathlib import Path

import pytest

from nexus.compliance import (
    PolicyError,
    build_report,
    defined_vlans,
    evaluate_device,
    expand_vlan_list,
    load_policies,
    parse_policy,
    sections,
    should_fail,
    worst_failure,
)
from nexus.platforms import PLATFORMS
from tests.conftest import FIXTURES, POLICIES


def cfg(device: str, cmd: str) -> str:
    from nexus.transport import command_slug

    raw = (FIXTURES / device / f"{command_slug(cmd)}.txt").read_text()
    return raw


def evaluate(device: str, platform: str):  # type: ignore[no-untyped-def]
    rules = load_policies([POLICIES])
    text = PLATFORMS[platform].normalize_config(cfg(device, PLATFORMS[platform].config_command))
    return {r.rule_id: r for r in evaluate_device(device, platform, text, rules).results}


def test_example_policies_load() -> None:
    rules = load_policies([POLICIES])
    assert len(rules) == 15
    assert {r.policy for r in rules} == {"baseline", "security", "vlans"}


def test_access_switch_findings_match_the_fixture() -> None:
    r = evaluate("access-sw1", "cisco_ios")
    failing = sorted(k for k, v in r.items() if v.status == "fail")
    assert failing == ["NTP-001", "PASS-001", "TELNET-001", "VLAN-001", "VTY-001"]
    assert r["NTP-001"].message == "1 matching line(s), expected min=2"
    assert r["TELNET-001"].evidence == ["48:  transport input ssh telnet"]
    assert "line vty 5 15" in r["VTY-001"].evidence
    assert r["VLAN-001"].message == "missing VLAN(s): 99"
    assert r["NTP-002"].status == "skip"  # Junos-only rule
    assert r["SSH-001"].status == "pass"


def test_eos_and_junos_fixtures_are_compliant() -> None:
    for dev, plat in (("core-sw1", "arista_eos"), ("edge-rtr1", "juniper_junos")):
        r = evaluate(dev, plat)
        assert [k for k, v in r.items() if v.status == "fail"] == [], dev


def test_vlan_parsing() -> None:
    assert expand_vlan_list("10,20-22, 99") == {10, 20, 21, 22, 99}
    assert expand_vlan_list("0,4095,30-29") == set()
    lines = ["vlan 10", "vlan 20-21,30", "vlan internal order ascending", "vlan 4094"]
    assert defined_vlans(lines, "arista_eos") == {10, 20, 21, 30, 4094}
    assert defined_vlans(["set vlans MGMT vlan-id 99"], "juniper_junos") == {99}


def test_sections() -> None:
    lines = [
        "line con 0",
        " exec-timeout 0",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "interface x",
        " shutdown",
    ]
    import re

    secs = sections(lines, re.compile(r"^line "))
    assert secs == [("line con 0", ["exec-timeout 0"]), ("line vty 0 4", ["transport input ssh"])]


RULE = {"id": "R1", "type": "must_match", "pattern": "^x$"}


@pytest.mark.parametrize(
    ("data", "msg"),
    [
        ({}, "expected a mapping"),
        ({"rules": [{"type": "must_match", "pattern": "x"}]}, "missing 'id'"),
        ({"rules": [{**RULE, "type": "nope"}]}, "unknown type"),
        ({"rules": [{**RULE, "severity": "urgent"}]}, "severity must be"),
        ({"rules": [{**RULE, "pattern": "("}]}, "invalid regex"),
        ({"rules": [{**RULE, "platforms": ["vyos"]}]}, "unknown platforms"),
        ({"rules": [{"id": "C", "type": "count", "pattern": "x"}]}, "needs 'min'"),
        (
            {"rules": [{"id": "C", "type": "count", "pattern": "x", "min": 3, "max": 1}]},
            "min > max",
        ),
        ({"rules": [{"id": "V", "type": "vlans_present", "vlans": [0]}]}, "list of IDs"),
        ({"rules": [RULE, RULE]}, "duplicate rule ids"),
        ({"rules": [{"id": "S", "type": "section_must_contain", "pattern": "x"}]}, "'section'"),
    ],
)
def test_policy_validation(data: dict[str, object], msg: str) -> None:
    with pytest.raises(PolicyError, match=msg):
        parse_policy(data)


def test_policy_files_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policies([tmp_path / "x.yaml"])
    with pytest.raises(PolicyError, match="no policy files"):
        load_policies([tmp_path])
    (tmp_path / "a.yaml").write_text("rules: [{id: X, type: must_match, pattern: a}]")
    (tmp_path / "b.yaml").write_text("rules: [{id: X, type: must_match, pattern: b}]")
    with pytest.raises(PolicyError, match="across policy files"):
        load_policies([tmp_path])


def test_rule_types_and_report_thresholds() -> None:
    rules = parse_policy(
        {
            "policy": "t",
            "rules": [
                {"id": "M", "type": "must_match", "pattern": "^hostname ", "severity": "low"},
                {
                    "id": "N",
                    "type": "must_not_match",
                    "pattern": "^snmp-server community public",
                    "severity": "critical",
                },
                {
                    "id": "C",
                    "type": "count",
                    "pattern": "^logging host",
                    "max": 1,
                    "severity": "medium",
                },
                {"id": "A", "type": "vlans_absent", "vlans": [1002], "severity": "low"},
                {
                    "id": "S",
                    "type": "section_must_contain",
                    "section": "^router bgp",
                    "pattern": "^bgp log-neighbor-changes$",
                    "severity": "high",
                },
            ],
        }
    )
    text = "hostname a\nlogging host 1\nlogging host 2\nvlan 1002\nrouter bgp 1\n neighbor x\n"
    dc = evaluate_device("a", "cisco_ios", text, rules)
    st = {r.rule_id: r.status for r in dc.results}
    assert st == {"M": "pass", "N": "pass", "C": "fail", "A": "fail", "S": "fail"}
    assert dc.score == 40.0
    rep = build_report([dc], rules, source="test")
    assert rep["summary"]["failures_by_severity"] == {
        "low": 1,
        "medium": 1,
        "high": 1,
        "critical": 0,
    }
    assert worst_failure(rep) == "high"
    assert should_fail(rep, "high") and should_fail(rep, "low")
    assert not should_fail(rep, "critical") and not should_fail(rep, "never")


def test_section_rule_with_no_matching_section_fails() -> None:
    rules = parse_policy(
        {
            "rules": [
                {
                    "id": "S",
                    "type": "section_must_contain",
                    "section": "^line vty",
                    "pattern": "access-class",
                }
            ]
        }
    )
    dc = evaluate_device("a", "cisco_ios", "hostname a\n", rules)
    assert dc.results[0].status == "fail"
    assert "no section matches" in dc.results[0].message
