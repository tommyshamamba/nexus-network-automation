from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.cli import main
from nexus.pcapgen import write_sample
from tests.conftest import EXAMPLES, FIXTURES, POLICIES

INV = str(EXAMPLES / "inventory.yaml")


def test_inventory_list_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inventory", "-i", INV]) == 0
    assert "4 device(s)" in capsys.readouterr().out
    assert main(["inventory", "-i", INV, "--json", "-l", "core"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["name"] for r in rows] == ["core-sw1"]
    assert all(r["auth"] == "password" and "password" not in r for r in rows)


def test_inventory_probe_reports_unreachable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inventory", "-i", INV, "--probe", "-l", "lab-sw-offline"]) == 1
    assert "unreachable" in capsys.readouterr().out


def test_comply_from_fixtures_writes_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    j, h = tmp_path / "r.json", tmp_path / "r.html"
    rc = main(
        [
            "comply",
            "-i",
            INV,
            "-p",
            str(POLICIES),
            "--fixtures",
            str(FIXTURES),
            "--retries",
            "0",
            "--json-out",
            str(j),
            "--html-out",
            str(h),
        ]
    )
    assert rc == 1
    rep = json.loads(j.read_text())
    assert rep["summary"]["devices"] == 4 and rep["summary"]["devices_with_errors"] == 1
    assert rep["summary"]["failures_by_severity"]["critical"] == 2
    assert "access-sw1" in h.read_text()
    out = capsys.readouterr().out
    assert "2/4 devices compliant" in out


def test_comply_thresholds(capsys: pytest.CaptureFixture[str]) -> None:
    base = ["comply", "-i", INV, "-p", str(POLICIES), "--fixtures", str(FIXTURES), "--retries", "0"]
    assert main([*base, "-l", "core-sw1,edge-rtr1"]) == 0
    assert main([*base, "-l", "access-sw1", "--fail-on", "never"]) == 0
    assert main([*base, "--fail-on", "never", "--allow-unreachable"]) == 0
    assert main([*base, "--fail-on", "never"]) == 1  # unreachable device still fails the run


def test_usage_errors_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inventory", "-i", str(tmp_path / "nope.yaml")]) == 2
    assert main(["comply", "-i", INV, "-p", str(tmp_path / "x.yaml")]) == 2
    assert main(["backup", "-i", INV, "--concurrency", "0"]) == 2
    assert main(["inventory", "-i", INV, "-l", "nothing-matches"]) == 2
    assert main(["health", "--expect-mtu", "eth0"]) == 2
    assert main(["pcap", str(tmp_path / "missing.pcap")]) == 2
    assert "nexus:" in capsys.readouterr().err


def test_pcap_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "s.pcap"
    write_sample(p)
    assert main(["pcap", str(p), "--top", "3"]) == 0
    out = capsys.readouterr().out
    assert "packets 204" in out and "10.0.10.5:51514" in out
    assert main(["pcap", str(p), "--json", "--engine", "python"]) == 0
    assert json.loads(capsys.readouterr().out)["stats"]["packets"] == 204


def test_health_command_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["health", "--interval", "0.1", "--json", "--fail-on", "never"])
    assert rc == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["status"] in ("ok", "warning", "critical")


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert "nexus 0.1.0" in capsys.readouterr().out
