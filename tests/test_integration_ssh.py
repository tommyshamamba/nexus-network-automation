"""End-to-end over real SSH against the in-process fake devices."""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

from nexus.cli import main
from nexus.collector import RetryPolicy, collect
from nexus.inventory import Device, load_inventory
from nexus.mockdev import MockDevice, MockLab
from nexus.platforms import PLATFORMS
from nexus.transport import SSHTransport
from tests.conftest import EXAMPLES, FIXTURES, LAB_PASSWORD, POLICIES, lab_inventory

pytestmark = pytest.mark.integration
FAST = RetryPolicy(retries=1, backoff_s=0.01, jitter=False)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


async def test_collect_over_ssh(mock_lab: MockLab, tmp_path: Path) -> None:
    inv = load_inventory(lab_inventory(mock_lab, tmp_path / "inv.yaml"))
    res = await collect(
        list(inv),
        lambda d: [PLATFORMS[d.platform].config_command, "show version"],
        SSHTransport(),
        concurrency=2,
        policy=FAST,
    )
    assert [r.ok for r in res] == [True, True, True], [r.error for r in res]
    by = {r.device: r for r in res}
    assert "hostname core-sw1" in by["core-sw1"].outputs["show running-config"]
    assert (
        "set system host-name edge-rtr1"
        in by["edge-rtr1"].outputs["show configuration | display set"]
    )
    assert all(r.attempts == 1 for r in res)


async def test_wrong_password_is_auth_error_without_retry(
    mock_lab: MockLab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inv = load_inventory(lab_inventory(mock_lab, tmp_path / "inv.yaml"))
    monkeypatch.setenv("NEXUS_PASSWORD", "wrong")
    [r] = await collect(
        [inv.get("core-sw1")], lambda d: ["show version"], SSHTransport(), policy=FAST
    )
    assert not r.ok and r.error_kind == "auth" and r.attempts == 1


async def test_unknown_command_is_command_error(mock_lab: MockLab, tmp_path: Path) -> None:
    inv = load_inventory(lab_inventory(mock_lab, tmp_path / "inv.yaml"))
    [r] = await collect(
        [inv.get("core-sw1")], lambda d: ["show bogus"], SSHTransport(), policy=FAST
    )
    assert r.error_kind == "command" and "Invalid input" in (r.error or "")
    assert r.attempts == 1


async def test_refused_port_is_retried_then_reported() -> None:
    d = Device(
        name="dead",
        host="127.0.0.1",
        port=free_port(),
        platform="cisco_ios",
        username="u",
        password_env="NEXUS_PASSWORD",
        timeout=2,
        strict_host_key=False,
    )
    [r] = await collect([d], lambda d: ["x"], SSHTransport(), policy=FAST)
    assert not r.ok and r.error_kind == "connect" and r.attempts == 2


async def test_slow_device_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_PASSWORD", LAB_PASSWORD)
    slow = MockDevice("slow", FIXTURES / "core-sw1", delay_s=5)
    async with MockLab([slow], LAB_PASSWORD):
        d = Device(
            name="slow",
            host="127.0.0.1",
            port=slow.port,
            platform="arista_eos",
            username="u",
            password_env="NEXUS_PASSWORD",
            timeout=0.5,
            strict_host_key=False,
        )
        [r] = await collect(
            [d], lambda d: ["show version"], SSHTransport(), policy=RetryPolicy(retries=0)
        )
    assert not r.ok and r.error_kind == "timeout" and "timed out" in (r.error or "")


async def test_strict_host_key_rejects_unknown_host(mock_lab: MockLab, tmp_path: Path) -> None:
    kh = tmp_path / "known_hosts"
    kh.write_text("")
    dev = mock_lab.devices[0]
    d = Device(
        name=dev.name,
        host="127.0.0.1",
        port=dev.port,
        platform="cisco_ios",
        username="u",
        password_env="NEXUS_PASSWORD",
        timeout=3,
        strict_host_key=True,
        known_hosts=str(kh),
    )
    [r] = await collect([d], lambda d: ["show version"], SSHTransport(), policy=FAST)
    assert not r.ok and r.error_kind == "host_key" and r.attempts == 1


def _cli_lab_inventory(lab: MockLab, path: Path) -> str:
    return str(lab_inventory(lab, path))


async def _run_cli(*argv: str) -> int:
    # The CLI calls asyncio.run(); run it in a worker thread so the fake
    # devices keep serving on this test's event loop.
    import asyncio

    return await asyncio.to_thread(main, list(argv))


async def test_cli_backup_change_and_comply(
    mock_lab: MockLab, lab_fixtures: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inv = _cli_lab_inventory(mock_lab, tmp_path / "inv.yaml")
    out = tmp_path / "backups"
    assert await _run_cli("backup", "-i", inv, "-o", str(out), "--git") == 0
    assert "3 new, 0 changed" in capsys.readouterr().out

    # someone fixes access-sw1 on the "device"
    shutil.copy(
        EXAMPLES / "changes" / "access-sw1" / "show_running-config.txt",
        lab_fixtures / "access-sw1" / "show_running-config.txt",
    )
    assert await _run_cli("backup", "-i", inv, "-o", str(out), "--git", "--show-diff") == 0
    text = capsys.readouterr().out
    assert "access-sw1     changed" in text
    assert "- transport input ssh telnet" in text and "+ntp server 10.0.0.11" in text
    assert "Last configuration change" not in text  # volatile line filtered
    assert "0 new, 1 changed, 2 unchanged" in text

    rc = await _run_cli(
        "comply",
        "-i",
        inv,
        "-p",
        str(POLICIES),
        "--from-backup",
        str(out),
        "--json-out",
        str(tmp_path / "r.json"),
        "--html-out",
        str(tmp_path / "r.html"),
    )
    text = capsys.readouterr().out
    assert rc == 1  # PASS-001 (critical) still fails on access-sw1
    assert "PASS-001" in text and "TELNET-001" not in text
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")


async def test_cli_live_comply(
    mock_lab: MockLab, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inv = _cli_lab_inventory(mock_lab, tmp_path / "inv.yaml")
    rc = await _run_cli("comply", "-i", inv, "-p", str(POLICIES), "--limit", "core-sw1,edge-rtr1")
    assert rc == 0
    assert "2/2 devices compliant" in capsys.readouterr().out
