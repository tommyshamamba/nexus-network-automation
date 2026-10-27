"""Linux host network-health check.

Data sources (all read-only, no root needed except where ethtool requires it):

* ``/proc/net/dev``          per-interface byte/packet/error/drop counters
* ``ip -j link show``        admin/oper state, MTU, bond/bridge membership
* ``ip -j route show``       IPv4 routes (default route present, routes via down links)
* ``ethtool -S <iface>``     NIC driver statistics, when the binary and driver support it

Counters are sampled twice ``interval`` seconds apart so drops and errors are
reported as *new* events during the window, not lifetime totals.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

PROC_NET_DEV_FIELDS = (
    "rx_bytes",
    "rx_packets",
    "rx_errs",
    "rx_drop",
    "rx_fifo",
    "rx_frame",
    "rx_compressed",
    "rx_multicast",
    "tx_bytes",
    "tx_packets",
    "tx_errs",
    "tx_drop",
    "tx_fifo",
    "tx_colls",
    "tx_carrier",
    "tx_compressed",
)

_ETHTOOL_BAD = re.compile(r"(drop|discard|err|miss|fifo|crc|timeout|over|no_buf|nobuf)", re.I)

Counters = dict[str, int]


class Runner(Protocol):
    def __call__(self, argv: Sequence[str]) -> str | None: ...


def subprocess_runner(argv: Sequence[str]) -> str | None:
    """Run a command, returning stdout, or None if unavailable or it failed."""
    if shutil.which(argv[0]) is None:
        return None
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def parse_proc_net_dev(text: str) -> dict[str, Counters]:
    out: dict[str, Counters] = {}
    for line in text.splitlines():
        if ":" not in line or "|" in line:
            continue
        name, _, rest = line.partition(":")
        vals = rest.split()
        if len(vals) != len(PROC_NET_DEV_FIELDS):
            continue
        try:
            out[name.strip()] = dict(zip(PROC_NET_DEV_FIELDS, map(int, vals), strict=True))
        except ValueError:
            continue
    return out


def parse_ethtool_stats(text: str) -> Counters:
    stats: Counters = {}
    for line in text.splitlines():
        k, sep, v = line.strip().rpartition(":")
        if not sep:
            continue
        v = v.strip()
        if v.isdigit():
            stats[k.strip()] = int(v)
    return stats


def _json(runner: Runner, argv: Sequence[str]) -> list[dict[str, Any]]:
    raw = runner(argv)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


@dataclass
class Snapshot:
    taken_at: float
    counters: dict[str, Counters]
    ethtool: dict[str, Counters] = field(default_factory=dict)


@dataclass
class Finding:
    severity: str  # info | warning | critical
    check: str
    interface: str | None
    message: str


@dataclass
class InterfaceHealth:
    name: str
    oper_state: str
    admin_up: bool
    mtu: int | None
    master: str | None
    kind: str | None
    rx_pps: float | None = None
    tx_pps: float | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    new_drops: int | None = None
    new_errors: int | None = None
    lifetime_drops: int = 0
    lifetime_errors: int = 0


@dataclass
class HealthReport:
    host: str
    interval_s: float
    interfaces: list[InterfaceHealth]
    findings: list[Finding]
    default_route: bool
    sources: dict[str, bool]

    @property
    def status(self) -> str:
        sev = {f.severity for f in self.findings}
        return "critical" if "critical" in sev else "warning" if "warning" in sev else "ok"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status
        return d


@dataclass(frozen=True)
class Thresholds:
    drop_ratio: float = 0.001  # new drops / new packets in the window
    expect_mtu: Mapping[str, int] = field(default_factory=dict)


def take_snapshot(
    proc_net_dev: Path,
    runner: Runner,
    ethtool_ifaces: Sequence[str],
    clock: Callable[[], float] = time.monotonic,
) -> Snapshot:
    counters = parse_proc_net_dev(proc_net_dev.read_text(encoding="utf-8"))
    eth: dict[str, Counters] = {}
    for iface in ethtool_ifaces:
        raw = runner(["ethtool", "-S", iface])
        if raw:
            stats = parse_ethtool_stats(raw)
            if stats:
                eth[iface] = stats
    return Snapshot(clock(), counters, eth)


def _delta(a: int, b: int) -> int | None:
    """Counter delta; None if the counter went backwards (reset or 32-bit wrap)."""
    return b - a if b >= a else None


def _physical(name: str, sys_class_net: Path) -> bool:
    return (sys_class_net / name / "device").exists()


def analyze(
    first: Snapshot,
    second: Snapshot | None,
    links: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    thresholds: Thresholds,
    *,
    host: str = "localhost",
    only: Sequence[str] = (),
    sources: dict[str, bool] | None = None,
) -> HealthReport:
    findings: list[Finding] = []
    link_by_name: dict[str, dict[str, Any]] = {
        str(lk["ifname"]): lk for lk in links if lk.get("ifname")
    }
    names = sorted(set(first.counters) | set(link_by_name))
    if only:
        names = [n for n in names if n in only]
        for n in only:
            if n not in first.counters and n not in link_by_name:
                findings.append(Finding("critical", "interface_missing", n, "interface not found"))
    interval = (second.taken_at - first.taken_at) if second else 0.0
    # An empty Linux bridge (e.g. docker0 with no containers) has no carrier by
    # design; report it as info rather than as a failed link.
    idle_bridges = {
        n
        for n, lk in link_by_name.items()
        if (lk.get("linkinfo") or {}).get("info_kind") == "bridge"
        and not any(m.get("master") == n and m.get("operstate") == "UP" for m in links)
    }
    ifaces: list[InterfaceHealth] = []
    for name in names:
        lk = link_by_name.get(name, {})
        flags = lk.get("flags") or []
        oper = str(lk.get("operstate", "UNKNOWN"))
        kind = (lk.get("linkinfo") or {}).get("info_kind")
        ih = InterfaceHealth(
            name=name,
            oper_state=oper,
            admin_up="UP" in flags,
            mtu=lk.get("mtu"),
            master=lk.get("master"),
            kind=kind,
        )
        c1 = first.counters.get(name)
        if c1:
            ih.lifetime_drops = c1["rx_drop"] + c1["tx_drop"]
            ih.lifetime_errors = c1["rx_errs"] + c1["tx_errs"]
        # --- link state
        if name != "lo" and ih.admin_up and (oper == "DOWN" or "NO-CARRIER" in flags):
            if name in idle_bridges:
                findings.append(
                    Finding(
                        "info",
                        "bridge_no_ports",
                        name,
                        "bridge is up but has no active member ports",
                    )
                )
            else:
                findings.append(
                    Finding(
                        "critical",
                        "link_down",
                        name,
                        "administratively up but no carrier / oper state DOWN",
                    )
                )
        # --- MTU expectations and bond/bridge consistency
        want = thresholds.expect_mtu.get(name)
        if want is not None and ih.mtu is not None and ih.mtu != want:
            findings.append(
                Finding("warning", "mtu_mismatch", name, f"MTU {ih.mtu}, expected {want}")
            )
        if ih.master and ih.master in link_by_name:
            mmtu = link_by_name[ih.master].get("mtu")
            if mmtu is not None and ih.mtu is not None and mmtu != ih.mtu:
                findings.append(
                    Finding(
                        "warning",
                        "mtu_member_mismatch",
                        name,
                        f"MTU {ih.mtu} differs from master {ih.master} ({mmtu})",
                    )
                )
        # --- counter rates over the sampling window
        c2 = second.counters.get(name) if second else None
        if c1 and c2 and interval > 0:
            d = {k: _delta(c1[k], c2[k]) for k in PROC_NET_DEV_FIELDS}
            if any(v is None for v in d.values()):
                findings.append(
                    Finding(
                        "info",
                        "counter_reset",
                        name,
                        "a counter went backwards during the window; skipped",
                    )
                )
            else:
                dd: dict[str, int] = {k: v for k, v in d.items() if v is not None}
                ih.rx_pps = round(dd["rx_packets"] / interval, 1)
                ih.tx_pps = round(dd["tx_packets"] / interval, 1)
                ih.rx_bps = round(dd["rx_bytes"] * 8 / interval, 1)
                ih.tx_bps = round(dd["tx_bytes"] * 8 / interval, 1)
                ih.new_drops = dd["rx_drop"] + dd["tx_drop"]
                ih.new_errors = dd["rx_errs"] + dd["tx_errs"] + dd["rx_frame"] + dd["tx_carrier"]
                pkts = dd["rx_packets"] + dd["tx_packets"]
                if ih.new_errors:
                    findings.append(
                        Finding(
                            "critical",
                            "errors_increasing",
                            name,
                            f"{ih.new_errors} new rx/tx errors in {interval:.1f}s",
                        )
                    )
                if ih.new_drops:
                    ratio = ih.new_drops / max(pkts, 1)
                    sev = "warning" if ratio >= thresholds.drop_ratio else "info"
                    findings.append(
                        Finding(
                            sev,
                            "drops_increasing",
                            name,
                            f"{ih.new_drops} new drops in {interval:.1f}s "
                            f"({ratio:.3%} of {pkts} packets)",
                        )
                    )
        # --- NIC driver statistics
        e1 = first.ethtool.get(name)
        e2 = second.ethtool.get(name) if second else None
        if e1:
            bad = {k: v for k, v in e1.items() if v and _ETHTOOL_BAD.search(k)}
            if e2:
                grew = {k: e2[k] - e1[k] for k in bad if k in e2 and e2[k] > e1[k]}
                if grew:
                    top = ", ".join(f"{k}+{v}" for k, v in sorted(grew.items())[:6])
                    findings.append(Finding("warning", "nic_counters_increasing", name, top))
            elif bad:
                top = ", ".join(f"{k}={v}" for k, v in sorted(bad.items())[:6])
                findings.append(Finding("info", "nic_counters_nonzero", name, top))
        ifaces.append(ih)

    # --- routing
    default = any(r.get("dst") == "default" for r in routes)
    if routes and not default:
        findings.append(Finding("warning", "no_default_route", None, "no IPv4 default route"))
    for r in routes:
        dev = r.get("dev")
        rlk = link_by_name.get(dev or "")
        if rlk and (rlk.get("operstate") == "DOWN" or "linkdown" in (r.get("flags") or [])):
            sev = "info" if dev in idle_bridges else "warning"
            findings.append(
                Finding(
                    sev,
                    "route_via_down_link",
                    dev,
                    f"route {r.get('dst')} uses a link that is down",
                )
            )
    return HealthReport(host, round(interval, 3), ifaces, findings, default, sources or {})


def run_health(
    *,
    interval: float = 2.0,
    thresholds: Thresholds | None = None,
    only: Sequence[str] = (),
    proc_net_dev: Path = Path("/proc/net/dev"),
    sys_class_net: Path = Path("/sys/class/net"),
    runner: Runner = subprocess_runner,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    host: str | None = None,
) -> HealthReport:
    import socket

    thresholds = thresholds or Thresholds()
    links = _json(runner, ["ip", "-j", "-d", "link", "show"])
    routes = _json(runner, ["ip", "-j", "route", "show"])
    names = [lk["ifname"] for lk in links if "ifname" in lk]
    phys = [n for n in names if _physical(n, sys_class_net) and (not only or n in only)]
    first = take_snapshot(proc_net_dev, runner, phys, clock)
    second = None
    if interval > 0:
        sleep(interval)
        second = take_snapshot(proc_net_dev, runner, phys, clock)
    sources = {
        "proc_net_dev": True,
        "ip_link": bool(links),
        "ip_route": bool(routes),
        "ethtool": bool(first.ethtool),
    }
    return analyze(
        first,
        second,
        links,
        routes,
        thresholds,
        host=host or socket.gethostname(),
        only=only,
        sources=sources,
    )


def _human_bps(v: float | None) -> str:
    if v is None:
        return "-"
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if v < 1000:
            return f"{v:.0f}{unit}" if unit == "bps" else f"{v:.1f}{unit}"
        v /= 1000
    return f"{v:.1f}Tbps"


def to_text(rep: HealthReport) -> str:
    lines = [
        f"host {rep.host}  window {rep.interval_s:.1f}s  status {rep.status.upper()}  "
        f"default-route {'yes' if rep.default_route else 'no'}",
        f"{'IFACE':<16}{'STATE':<9}{'MTU':>6}{'RX':>11}{'TX':>11}"
        f"{'DROPS(new)':>12}{'ERRS(new)':>11}",
    ]
    for i in rep.interfaces:
        nd = "-" if i.new_drops is None else str(i.new_drops)
        ne = "-" if i.new_errors is None else str(i.new_errors)
        lines.append(
            f"{i.name:<16}{i.oper_state:<9}{(i.mtu or 0):>6}{_human_bps(i.rx_bps):>11}"
            f"{_human_bps(i.tx_bps):>11}{nd:>12}{ne:>11}"
        )
    if rep.findings:
        lines.append("")
        for f in rep.findings:
            lines.append(
                f"[{f.severity.upper():<8}] {f.check:<24} {f.interface or '-':<12} {f.message}"
            )
    else:
        lines.append("\nno findings")
    missing = [k for k, v in rep.sources.items() if not v]
    if missing:
        lines.append(f"(unavailable data sources: {', '.join(missing)})")
    return "\n".join(lines) + "\n"
