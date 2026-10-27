"""Command-line interface: ``nexus inventory|backup|comply|health|pcap|mock-devices``.

Exit codes: 0 success; 1 policy/health threshold breached or some devices
failed; 2 usage or input error.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from nexus import __version__
from nexus.backup import load_backups, write_backups
from nexus.collector import RetryPolicy, collect
from nexus.compliance import (
    SEVERITIES,
    DeviceCompliance,
    PolicyError,
    build_report,
    evaluate_device,
    load_policies,
    should_fail,
)
from nexus.health import Thresholds, run_health
from nexus.health import to_text as health_text
from nexus.inventory import Device, Inventory, InventoryError, load_inventory
from nexus.pcap import PcapError, analyze_pcap
from nexus.platforms import PLATFORMS
from nexus.report import to_html, to_json, to_text
from nexus.transport import FixtureTransport, SSHTransport, Transport

log = logging.getLogger("nexus")


def _limit(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def _select(args: argparse.Namespace) -> tuple[Inventory, list[Device]]:
    inv = load_inventory(args.inventory)
    devs = inv.select(_limit(args.limit))
    if not devs:
        raise InventoryError([f"--limit {args.limit} matched no devices"])
    return inv, devs


def _transport(args: argparse.Namespace) -> Transport:
    return FixtureTransport(args.fixtures) if args.fixtures else SSHTransport()


def _policy(args: argparse.Namespace) -> RetryPolicy:
    return RetryPolicy(retries=args.retries, backoff_s=args.backoff)


def _write(path: str | None, text: str) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")


# ------------------------------------------------------------------ commands


async def _probe(devs: list[Device], concurrency: int) -> dict[str, str]:
    sem = asyncio.Semaphore(concurrency)

    async def one(d: Device) -> tuple[str, str]:
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(d.host, d.port), d.timeout)
                w.close()
                await w.wait_closed()
                return d.name, "reachable"
            except (OSError, TimeoutError) as e:
                return d.name, f"unreachable ({type(e).__name__})"

    return dict(await asyncio.gather(*(one(d) for d in devs)))


def cmd_inventory(args: argparse.Namespace) -> int:
    _, devs = _select(args)
    probe = asyncio.run(_probe(devs, args.concurrency)) if args.probe else {}
    rows = [d.public_dict() | ({"tcp": probe[d.name]} if probe else {}) for d in devs]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'NAME':<14} {'HOST':<22} {'PLATFORM':<14} {'GROUPS':<16} TAGS")
        for r in rows:
            tags = ",".join(f"{k}={v}" for k, v in r["tags"].items())
            extra = f"  [{r['tcp']}]" if probe else ""
            print(
                f"{r['name']:<14} {r['host'] + ':' + str(r['port']):<22} {r['platform']:<14} "
                f"{','.join(r['groups']):<16} {tags}{extra}"
            )
        print(f"\n{len(rows)} device(s)")
    return 1 if probe and any(v != "reachable" for v in probe.values()) else 0


def cmd_backup(args: argparse.Namespace) -> int:
    inv, devs = _select(args)
    results = asyncio.run(
        collect(
            devs,
            lambda d: [PLATFORMS[d.platform].config_command],
            _transport(args),
            concurrency=args.concurrency,
            policy=_policy(args),
        )
    )
    run = write_backups(results, {d.name: d for d in inv}, args.output, use_git=args.git)
    attempts = {r.device: r.attempts for r in results}
    if args.json:
        print(json.dumps(run.to_dict(), indent=2))
    else:
        for e in run.entries:
            detail = f"+{e.added} -{e.removed}" if e.status == "changed" else (e.error or "")
            print(f"{e.device:<14} {e.status:<10} attempts={attempts[e.device]:<2} {detail}")
            if e.status == "changed" and args.show_diff:
                print(e.diff, end="")
        c = run.counts
        commit = f"; git commit {run.commit}" if run.commit else ""
        if run.git_error:
            commit = "; git commit FAILED (see warning)"
        print(
            f"\n{c['new']} new, {c['changed']} changed, {c['unchanged']} unchanged, "
            f"{c['failed']} failed -> {args.output}{commit}"
        )
    return 1 if run.counts["failed"] else 0


def cmd_comply(args: argparse.Namespace) -> int:
    rules = load_policies(args.policy)
    _inv, devs = _select(args)
    evaluated: list[DeviceCompliance] = []
    if args.from_backup:
        configs = load_backups(args.from_backup)
        source = f"backup:{args.from_backup}"
        for d in devs:
            if d.name in configs:
                evaluated.append(evaluate_device(d.name, d.platform, configs[d.name], rules))
            else:
                evaluated.append(DeviceCompliance(d.name, d.platform, [], error="no backup found"))
    else:
        source = "fixtures:" + args.fixtures if args.fixtures else "live:ssh"
        results = asyncio.run(
            collect(
                devs,
                lambda d: [PLATFORMS[d.platform].config_command],
                _transport(args),
                concurrency=args.concurrency,
                policy=_policy(args),
            )
        )
        for d, r in zip(devs, results, strict=True):
            if r.ok:
                cfg = PLATFORMS[d.platform].normalize_config(
                    r.outputs[PLATFORMS[d.platform].config_command]
                )
                evaluated.append(evaluate_device(d.name, d.platform, cfg, rules))
            else:
                evaluated.append(
                    DeviceCompliance(d.name, d.platform, [], error=f"{r.error_kind}: {r.error}")
                )
    report = build_report(evaluated, rules, source=source)
    _write(args.json_out, to_json(report))
    _write(args.html_out, to_html(report))
    print(to_json(report) if args.json else to_text(report), end="")
    errors = report["summary"]["devices_with_errors"] and not args.allow_unreachable
    return 1 if should_fail(report, args.fail_on) or errors else 0


def cmd_health(args: argparse.Namespace) -> int:
    expect: dict[str, int] = {}
    for item in args.expect_mtu or []:
        name, sep, val = item.partition("=")
        if not sep or not val.isdigit():
            raise ValueError(f"--expect-mtu expects IFACE=MTU, got {item!r}")
        expect[name] = int(val)
    rep = run_health(
        interval=args.interval,
        thresholds=Thresholds(drop_ratio=args.drop_ratio, expect_mtu=expect),
        only=_limit(args.iface),
        proc_net_dev=Path(args.proc_net_dev),
    )
    _write(args.json_out, json.dumps(rep.to_dict(), indent=2) + "\n")
    print(json.dumps(rep.to_dict(), indent=2) if args.json else health_text(rep), end="")
    if args.json:
        print()
    order = {"ok": 0, "warning": 1, "critical": 2}
    return 1 if args.fail_on != "never" and order[rep.status] >= order[args.fail_on] else 0


def cmd_pcap(args: argparse.Namespace) -> int:
    s = analyze_pcap(args.file, engine=args.engine, top=args.top)
    if args.json:
        print(json.dumps(s.to_dict(), indent=2))
        return 0
    st = s.stats
    print(f"{s.path}  (engine: {s.engine})")
    dur = (st["last_ts_ns"] - st["first_ts_ns"]) / 1e9 if st["packets"] else 0.0
    print(
        f"packets {st['packets']}  wire bytes {st['bytes_wire']}  "
        f"captured bytes {st['bytes_captured']}  span {dur:.3f}s"
    )
    keys = [
        "ipv4",
        "ipv6",
        "arp",
        "other_l3",
        "tcp",
        "udp",
        "icmp",
        "other_l4",
        "vlan_tagged",
        "qinq",
        "fragments",
        "bad_ipv4_csum",
        "truncated",
        "malformed",
    ]
    print("  " + "  ".join(f"{k}={st[k]}" for k in keys))
    print(f"\nflows {s.flow_count} (untracked: {s.flows_dropped}); top {len(s.flows)} by bytes:")

    def ep(addr: str, port: int) -> str:
        if not port:
            return addr
        return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"

    for f in s.flows:
        print(
            f"  {f['proto']:<5} {ep(f['src'], f['src_port']):>30} -> "
            f"{ep(f['dst'], f['dst_port']):<30} "
            f"{f['packets']:>6} pkts {f['bytes']:>9} B"
        )
    if s.warning:
        print(f"\nwarning: {s.warning}", file=sys.stderr)
    return 0


def cmd_mock_devices(args: argparse.Namespace) -> int:
    from nexus.mockdev import MockLab, devices_from_fixtures

    password = os.environ.get(args.password_env)
    if not password:
        raise ValueError(f"set {args.password_env} to the password the fake devices accept")
    devices = devices_from_fixtures(args.fixtures, args.base_port)

    async def serve() -> None:
        lab = MockLab(devices, password, host=args.listen)
        ports = await lab.start()
        for name, port in ports.items():
            print(f"mock device {name:<14} ssh://{args.listen}:{port}", flush=True)
        await asyncio.Event().wait()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve())
    return 0


# ------------------------------------------------------------------- parser


def _collection_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-i", "--inventory", required=True, help="inventory YAML file")
    p.add_argument("-l", "--limit", action="append", help="device, group or tag=value (repeatable)")
    p.add_argument("--concurrency", type=int, default=10, help="max parallel sessions (10)")
    p.add_argument("--retries", type=int, default=2, help="retries for transient errors (2)")
    p.add_argument("--backoff", type=float, default=0.5, help="base retry delay seconds (0.5)")
    p.add_argument("--fixtures", help="replay recorded output from this directory instead of SSH")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="nexus", description=__doc__.splitlines()[0] if __doc__ else ""
    )
    ap.add_argument("--version", action="version", version=f"nexus {__version__}")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inventory", help="validate and list the inventory")
    p.add_argument("-i", "--inventory", required=True)
    p.add_argument("-l", "--limit", action="append")
    p.add_argument("--probe", action="store_true", help="TCP-connect to each device's SSH port")
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("backup", help="collect running configs and store them with diffs")
    _collection_args(p)
    p.add_argument("-o", "--output", default="backups", help="backup directory (./backups)")
    p.add_argument("--git", action="store_true", help="commit each run in a git repo")
    p.add_argument("--show-diff", action="store_true", help="print unified diffs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("comply", help="evaluate configs against YAML policies")
    _collection_args(p)
    p.add_argument("-p", "--policy", action="append", required=True, help="policy file or dir")
    p.add_argument("--from-backup", help="evaluate stored backups instead of collecting live")
    p.add_argument("--json-out", help="write the JSON report here")
    p.add_argument("--html-out", help="write the HTML report here")
    p.add_argument(
        "--fail-on",
        choices=[*SEVERITIES, "never"],
        default="high",
        help="exit 1 if a failure of this severity or worse exists (high)",
    )
    p.add_argument(
        "--allow-unreachable",
        action="store_true",
        help="don't exit 1 just because some devices could not be evaluated",
    )
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.set_defaults(func=cmd_comply)

    p = sub.add_parser("health", help="Linux host network health (interfaces, routes, drops)")
    p.add_argument("--interval", type=float, default=2.0, help="sampling window seconds (2)")
    p.add_argument("--iface", action="append", help="only these interfaces")
    p.add_argument("--expect-mtu", action="append", metavar="IFACE=MTU")
    p.add_argument("--drop-ratio", type=float, default=0.001, help="drop/packet warning ratio")
    p.add_argument("--proc-net-dev", default="/proc/net/dev", help=argparse.SUPPRESS)
    p.add_argument("--fail-on", choices=["warning", "critical", "never"], default="critical")
    p.add_argument("--json-out")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("pcap", help="summarise a pcap file (C parser, Python fallback)")
    p.add_argument("file")
    p.add_argument("--engine", choices=["auto", "c", "python"], default="auto")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_pcap)

    p = sub.add_parser("mock-devices", help="run fake SSH devices from fixtures (demo/tests)")
    p.add_argument("--fixtures", required=True, help="one sub-directory per device")
    p.add_argument("--listen", default="127.0.0.1", help="bind address (127.0.0.1)")
    p.add_argument(
        "--base-port", type=int, default=2201, help="first port; devices sorted by name (2201)"
    )
    p.add_argument(
        "--password-env", default="NEXUS_PASSWORD", help="env var holding the lab password"
    )
    p.set_defaults(func=cmd_mock_devices)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    if getattr(args, "concurrency", 1) < 1:
        print("nexus: --concurrency must be >= 1", file=sys.stderr)
        return 2
    try:
        rc: int = args.func(args)
        return rc
    except (InventoryError, PolicyError, PcapError, ValueError, FileNotFoundError) as e:
        print(f"nexus: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
