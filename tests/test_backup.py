from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.backup import load_backups, unified_diff, write_backups
from nexus.collector import DeviceResult
from nexus.inventory import Device
from nexus.platforms import PLATFORMS

IOS = Device(name="sw1", host="10.0.0.1", platform="cisco_ios")
JUN = Device(name="r1", host="10.0.0.2", platform="juniper_junos")
DEVICES = {"sw1": IOS, "r1": JUN}
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def ok(dev: Device, cfg: str) -> DeviceResult:
    return DeviceResult(dev.name, True, {PLATFORMS[dev.platform].config_command: cfg}, attempts=1)


def fail(dev: Device) -> DeviceResult:
    return DeviceResult(device=dev.name, ok=False, error="connect refused", error_kind="connect")


def test_normalize_strips_volatile_lines() -> None:
    raw = (
        "Building configuration...\r\n\r\nCurrent configuration : 123 bytes\r\n"
        "! Last configuration change at 10:00:00 UTC\r\nhostname sw1   \r\n"
        "ntp clock-period 17179\r\nend\r\n\r\n"
    )
    assert PLATFORMS["cisco_ios"].normalize_config(raw) == "hostname sw1\nend\n"
    assert (
        PLATFORMS["juniper_junos"].normalize_config(
            "## Last commit: 2026-10-20 by x\nset system host-name r1\n"
        )
        == "set system host-name r1\n"
    )


def test_unified_diff_is_git_style() -> None:
    diff, added, removed = unified_diff("a\nb\nc\n", "a\nB\nc\nd\n", "sw1.cfg")
    assert diff.startswith("--- a/sw1.cfg\n+++ b/sw1.cfg\n@@")
    assert (added, removed) == (2, 1)
    assert unified_diff("x\n", "x\n", "f")[0] == ""


def test_first_second_and_changed_runs(tmp_path: Path) -> None:
    run1 = write_backups(
        [ok(IOS, "hostname sw1\nntp server 1.1.1.1\n")], DEVICES, tmp_path, now=NOW
    )
    assert run1.counts == {"new": 1, "changed": 0, "unchanged": 0, "failed": 0}
    # a volatile-only change must not register as a change
    run2 = write_backups(
        [ok(IOS, "! Last configuration change at 11:00\nhostname sw1\nntp server 1.1.1.1\n")],
        DEVICES,
        tmp_path,
        now=NOW,
    )
    assert run2.entries[0].status == "unchanged"
    run3 = write_backups(
        [ok(IOS, "hostname sw1\nntp server 1.1.1.1\nntp server 2.2.2.2\n")], DEVICES, tmp_path
    )
    e = run3.entries[0]
    assert e.status == "changed" and (e.added, e.removed) == (1, 0)
    assert "+ntp server 2.2.2.2" in e.diff
    assert load_backups(tmp_path)["sw1"].endswith("ntp server 2.2.2.2\n")
    meta = json.loads((tmp_path / ".nexus" / "last_backup.json").read_text())
    assert meta["counts"]["changed"] == 1


def test_failed_and_empty_outputs_do_not_overwrite(tmp_path: Path) -> None:
    write_backups([ok(IOS, "hostname sw1\n")], DEVICES, tmp_path)
    run = write_backups(
        [DeviceResult("sw1", False, error="timeout", error_kind="timeout"), ok(JUN, "  \n")],
        DEVICES,
        tmp_path,
    )
    assert [e.status for e in run.entries] == ["failed", "failed"]
    assert run.entries[1].error == "empty configuration output"
    assert (tmp_path / "sw1.cfg").read_text() == "hostname sw1\n"
    assert not (tmp_path / "r1.cfg").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_history(tmp_path: Path) -> None:
    r1 = write_backups([ok(IOS, "hostname sw1\n")], DEVICES, tmp_path, use_git=True, now=NOW)
    assert r1.commit
    r2 = write_backups([ok(IOS, "hostname sw1\n")], DEVICES, tmp_path, use_git=True, now=NOW)
    assert r2.commit is None  # nothing changed -> no empty commit
    r3 = write_backups([ok(IOS, "hostname sw1-new\n")], DEVICES, tmp_path, use_git=True, now=NOW)
    assert r3.commit and r3.commit != r1.commit
    log = subprocess.run(
        ["git", "-C", str(tmp_path), "log", "--oneline"], capture_output=True, text=True, check=True
    ).stdout
    assert len(log.strip().splitlines()) == 2
    assert "1 changed" in log


def test_git_with_no_successful_devices_does_not_crash(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    run = write_backups([fail(IOS)], DEVICES, tmp_path, use_git=True, now=NOW)
    assert run.counts["failed"] == 1 and run.commit is None and run.git_error is None


def test_git_failure_keeps_backups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from nexus import backup

    def boom(dest: Path, run: object) -> str:
        raise subprocess.CalledProcessError(128, ["git"], stderr="fatal: simulated")

    monkeypatch.setattr(backup, "_git_commit", boom)
    run = write_backups([ok(IOS, "hostname sw1\n")], DEVICES, tmp_path, use_git=True, now=NOW)
    assert run.git_error == "fatal: simulated"
    assert (tmp_path / "sw1.cfg").read_text().startswith("hostname sw1")
