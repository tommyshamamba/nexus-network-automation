from __future__ import annotations

import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest

from nexus.health import (
    Snapshot,
    Thresholds,
    analyze,
    parse_ethtool_stats,
    parse_proc_net_dev,
    run_health,
    subprocess_runner,
    to_text,
)
from tests.conftest import DATA

H = DATA / "health"


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def fixture_runner(round_: list[int]) -> object:
    def run(argv: Sequence[str]) -> str | None:
        if list(argv[:2]) == ["ip", "-j"] and "link" in argv:
            return (H / "ip_link.json").read_text()
        if list(argv[:3]) == ["ip", "-j", "route"]:
            return (H / "ip_route.json").read_text()
        if argv[0] == "ethtool" and argv[2] == "eth0":
            return (H / f"ethtool_eth0.{round_[0]}").read_text()
        return None  # ethtool unsupported on other ports

    return run


@pytest.fixture
def host(tmp_path: Path) -> tuple[Path, Path]:
    proc = tmp_path / "net_dev"
    shutil.copy(H / "proc_net_dev.1", proc)
    sysnet = tmp_path / "sys"
    for phys in ("eth0", "eth1", "eth2", "eth3"):
        (sysnet / phys / "device").mkdir(parents=True)
    return proc, sysnet


def run_fixture(host: tuple[Path, Path], **kw: object):  # type: ignore[no-untyped-def]
    proc, sysnet = host
    round_ = [1]
    clock = Clock()

    def sleep(s: float) -> None:
        shutil.copy(H / "proc_net_dev.2", proc)
        round_[0] = 2
        clock.t += s

    return run_health(
        interval=2.0,
        proc_net_dev=proc,
        sys_class_net=sysnet,
        runner=fixture_runner(round_),
        sleep=sleep,
        clock=clock,  # type: ignore[arg-type]
        host="testhost",
        **kw,
    )  # type: ignore[arg-type]


def test_parse_proc_net_dev() -> None:
    c = parse_proc_net_dev((H / "proc_net_dev.1").read_text())
    assert set(c) == {"lo", "eth0", "eth1", "eth2", "bond0", "docker0", "eth3"}
    assert c["eth0"]["rx_bytes"] == 500_000_000 and c["eth0"]["rx_drop"] == 10
    assert c["docker0"]["tx_drop"] == 2
    assert parse_proc_net_dev("garbage\n eth9: 1 2 3\n") == {}


def test_parse_ethtool() -> None:
    s = parse_ethtool_stats((H / "ethtool_eth0.1").read_text())
    assert s["rx_missed_errors"] == 4 and "NIC statistics" not in s


def test_findings_from_fixture(host: tuple[Path, Path]) -> None:
    rep = run_fixture(host, thresholds=Thresholds(expect_mtu={"eth0": 9000, "bond0": 1500}))
    got = {(f.check, f.interface, f.severity) for f in rep.findings}
    assert ("link_down", "eth1", "critical") in got
    assert ("errors_increasing", "eth2", "critical") in got
    assert ("drops_increasing", "eth0", "warning") in got
    assert ("mtu_member_mismatch", "eth2", "warning") in got
    assert ("mtu_mismatch", "bond0", "warning") in got
    assert ("nic_counters_increasing", "eth0", "warning") in got
    assert ("route_via_down_link", "eth1", "warning") in got
    # idle docker bridge is informational, not a failure
    assert ("bridge_no_ports", "docker0", "info") in got
    assert ("route_via_down_link", "docker0", "info") in got
    # admin-down port and loopback are not flagged
    assert not any(f.interface in ("eth3", "lo") for f in rep.findings)
    assert not any(f.check == "mtu_mismatch" and f.interface == "eth0" for f in rep.findings)
    assert rep.status == "critical" and rep.default_route
    eth0 = next(i for i in rep.interfaces if i.name == "eth0")
    assert eth0.rx_pps == 10000.0 and eth0.new_drops == 50
    assert eth0.rx_bps == 100_000_000.0
    assert rep.sources == {"proc_net_dev": True, "ip_link": True, "ip_route": True, "ethtool": True}
    text = to_text(rep)
    assert "CRITICAL" in text and "eth0" in text and "100.0Mbps" in text


def test_iface_filter_and_missing_iface(host: tuple[Path, Path]) -> None:
    rep = run_fixture(host, only=["eth0", "wan9"])
    assert [i.name for i in rep.interfaces] == ["eth0"]
    assert any(f.check == "interface_missing" and f.interface == "wan9" for f in rep.findings)


def test_counter_reset_is_not_misreported() -> None:
    a = Snapshot(0.0, parse_proc_net_dev((H / "proc_net_dev.2").read_text()))
    b = Snapshot(1.0, parse_proc_net_dev((H / "proc_net_dev.1").read_text()))
    rep = analyze(a, b, [], [], Thresholds())
    assert any(f.check == "counter_reset" for f in rep.findings)
    assert not any(f.check in ("drops_increasing", "errors_increasing") for f in rep.findings)


def test_no_default_route_and_single_snapshot() -> None:
    snap = Snapshot(
        0.0,
        parse_proc_net_dev((H / "proc_net_dev.1").read_text()),
        {"eth0": {"rx_missed_errors": 4, "rx_packets": 9}},
    )
    rep = analyze(snap, None, [], [{"dst": "10.0.0.0/24", "dev": "eth0"}], Thresholds())
    checks = {f.check for f in rep.findings}
    assert "no_default_route" in checks and "nic_counters_nonzero" in checks
    assert all(i.rx_pps is None for i in rep.interfaces)


def test_degrades_without_iproute2_or_ethtool(host: tuple[Path, Path]) -> None:
    proc, sysnet = host
    rep = run_health(
        interval=0, proc_net_dev=proc, sys_class_net=sysnet, runner=lambda argv: None, host="bare"
    )
    assert rep.sources["ip_link"] is False and rep.sources["ethtool"] is False
    assert len(rep.interfaces) == 7
    assert "unavailable data sources" in to_text(rep)


def test_subprocess_runner_handles_missing_binary() -> None:
    assert subprocess_runner(["definitely-not-a-binary-nexus"]) is None


@pytest.mark.skipif(not Path("/proc/net/dev").exists(), reason="needs Linux /proc")
def test_live_host_smoke() -> None:
    rep = run_health(interval=0.2)
    assert any(i.name == "lo" for i in rep.interfaces)
    assert rep.status in ("ok", "warning", "critical")
