"""Packet parser tests. The C library and the Python twin must agree."""

from __future__ import annotations

import os
import random
import struct
from pathlib import Path

import pytest

from nexus import pcap, pcapgen
from nexus.pcap import PcapError, analyze_pcap, parse_frame

HAVE_C = pcap.load_library() is not None
REQUIRE_C = os.environ.get("NEXUS_REQUIRE_CLIB") == "1"
needs_c = pytest.mark.skipif(not HAVE_C and not REQUIRE_C, reason="libnexus_pkt not built")


def test_c_library_present_when_required() -> None:
    if REQUIRE_C:
        assert HAVE_C, pcap.library_status()


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    p = tmp_path / "sample.pcap"
    pcapgen.write_sample(p)
    return p


def test_python_engine_counts_sample(sample: Path) -> None:
    s = analyze_pcap(sample, engine="python")
    st = s.stats
    assert st["packets"] == 204
    assert st["ipv4"] + st["ipv6"] + st["arp"] + st["other_l3"] == st["packets"]
    assert st["tcp"] + st["udp"] + st["icmp"] + st["other_l4"] == st["ipv4"] + st["ipv6"]
    assert (st["fragments"], st["bad_ipv4_csum"], st["truncated"]) == (2, 1, 1)
    assert st["qinq"] <= st["vlan_tagged"]
    top = s.flows[0]
    assert (top["src"], top["dst"], top["dst_port"], top["proto"]) == (
        "10.0.10.5",
        "10.0.20.8",
        443,
        "tcp",
    )


@needs_c
def test_c_and_python_agree_on_sample(sample: Path) -> None:
    c = analyze_pcap(sample, engine="c", top=1000)
    py = analyze_pcap(sample, engine="python", top=1000)
    assert c.engine == "c"
    assert c.stats == py.stats
    assert c.flows == py.flows
    assert c.flow_count == py.flow_count and c.flows_dropped == 0


def _random_frames(rng: random.Random, n: int) -> list[tuple[float, bytes, int | None]]:
    base = [f for _, f, _ in pcapgen.sample_frames(seed=rng.randrange(1000), n_background=50)]
    out: list[tuple[float, bytes, int | None]] = []
    for i in range(n):
        f = bytearray(rng.choice(base))
        op = rng.random()
        if op < 0.3 and f:  # flip random bytes (header fields included)
            for _ in range(rng.randint(1, 4)):
                f[rng.randrange(len(f))] = rng.randrange(256)
        elif op < 0.5:  # cut anywhere
            f = f[: rng.randrange(len(f) + 1)]
        elif op < 0.6:  # pure noise
            f = bytearray(rng.randbytes(rng.randrange(80)))
        wire = len(f) + (rng.randrange(50) if rng.random() < 0.1 else 0)
        out.append((1000.0 + i / 1000, bytes(f), wire))
    return out


@needs_c
@pytest.mark.parametrize("seed", range(6))
def test_differential_fuzz(tmp_path: Path, seed: int) -> None:
    rng = random.Random(seed)
    p = tmp_path / f"fuzz{seed}.pcap"
    pcapgen.write_pcap(p, _random_frames(rng, 400), big_endian=bool(seed % 2), nsec=seed % 3 == 0)
    c = analyze_pcap(p, engine="c", top=10_000)
    py = analyze_pcap(p, engine="python", top=10_000)
    assert c.stats == py.stats
    assert c.flows == py.flows


@pytest.mark.parametrize("engine", ["python", pytest.param("c", marks=needs_c)])
def test_file_level_errors(tmp_path: Path, sample: Path, engine: str) -> None:
    bad = tmp_path / "x.pcapng"
    bad.write_bytes(bytes.fromhex("0a0d0d0a") + bytes(40))
    with pytest.raises(PcapError, match="bad magic"):
        analyze_pcap(bad, engine=engine)
    raw = tmp_path / "raw.pcap"
    raw.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    with pytest.raises(PcapError, match="link type"):
        analyze_pcap(raw, engine=engine)
    with pytest.raises(PcapError):
        analyze_pcap(tmp_path / "missing.pcap", engine=engine)
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(sample.read_bytes()[:-7])
    s = analyze_pcap(cut, engine=engine)
    assert s.stats["packets"] == 203 and s.warning == "file truncated mid-record"
    big = tmp_path / "big.pcap"
    big.write_bytes(
        raw.read_bytes()[:20] + struct.pack("<I", 1) + struct.pack("<IIII", 0, 0, 10**7, 10**7)
    )
    assert analyze_pcap(big, engine=engine).warning == pcap.ERRORS[-7]


def test_parse_frame_vlan_and_ports() -> None:
    f = pcapgen.eth(
        0x0800, pcapgen.ipv4("1.2.3.4", "5.6.7.8", 17, pcapgen.udp(1, 2)), vlans=[300, 99]
    )
    fi = parse_frame(f)
    assert fi.flags & pcap.F_QINQ and (fi.vlan_outer, fi.vlan_inner) == (300, 99)
    assert (fi.src_port, fi.dst_port) == (1, 2)


def test_independent_oracle_dpkt(sample: Path) -> None:
    """Cross-check protocol counts against dpkt, an unrelated parser."""
    dpkt = pytest.importorskip("dpkt")
    counts = {"ipv4": 0, "ipv6": 0, "arp": 0, "tcp": 0, "udp": 0, "vlan": 0}
    with sample.open("rb") as fh:
        for _, buf in dpkt.pcap.Reader(fh):
            if len(buf) < 60 and len(buf) <= 34:
                continue  # dpkt can't decode the snaplen-truncated frame
            e = dpkt.ethernet.Ethernet(buf)
            if getattr(e, "vlan_tags", None):
                counts["vlan"] += 1
            if isinstance(e.data, dpkt.ip.IP):
                counts["ipv4"] += 1
                if e.data.offset == 0 and isinstance(e.data.data, dpkt.tcp.TCP):
                    counts["tcp"] += 1
                if isinstance(e.data.data, dpkt.udp.UDP) and e.data.offset == 0:
                    counts["udp"] += 1
            elif isinstance(e.data, dpkt.ip6.IP6):
                counts["ipv6"] += 1
                counts["tcp"] += isinstance(e.data.data, dpkt.tcp.TCP)
            elif isinstance(e.data, dpkt.arp.ARP):
                counts["arp"] += 1
    st = analyze_pcap(sample, engine="python").stats
    assert counts["ipv4"] == st["ipv4"] - 1  # minus the truncated frame dpkt skipped
    assert counts["ipv6"] == st["ipv6"]
    assert counts["arp"] == st["arp"]
    assert counts["tcp"] == st["tcp"] - 1
    assert counts["udp"] == st["udp"] - 1  # non-first fragment carries no UDP header
    assert counts["vlan"] == st["vlan_tagged"]
