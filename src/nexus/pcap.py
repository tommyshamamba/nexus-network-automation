"""Offline capture analysis.

The fast path is ``libnexus_pkt`` (``csrc/``), loaded with ctypes. A pure
Python implementation of the same decoder lives here too: it is the fallback
when the shared library has not been built, and the tests run both engines
over the same captures and require identical counters (differential testing).
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NX_OK = 0
ERRORS = {
    -1: "invalid argument",
    -2: "i/o error",
    -3: "not a classic pcap file (bad magic)",
    -4: "unsupported link type (only Ethernet is supported)",
    -5: "file truncated mid-record",
    -6: "flow table storage too small",
    -7: "record length exceeds maximum capture length",
}
FATAL = {-1, -2, -3, -4, -6}
MAX_CAPLEN = 262144

STAT_FIELDS = (
    "packets",
    "bytes_captured",
    "bytes_wire",
    "vlan_tagged",
    "qinq",
    "arp",
    "ipv4",
    "ipv6",
    "other_l3",
    "tcp",
    "udp",
    "icmp",
    "other_l4",
    "fragments",
    "bad_ipv4_csum",
    "truncated",
    "malformed",
)

F_VLAN, F_QINQ, F_IPV4, F_IPV6, F_ARP = 0x1, 0x2, 0x4, 0x8, 0x10
F_FRAGMENT, F_BAD_CSUM, F_TRUNCATED, F_MALFORMED, F_HAS_PORTS = 0x20, 0x40, 0x80, 0x100, 0x200


class PcapError(Exception):
    pass


# ----------------------------------------------------------------- ctypes ABI


class _Stats(ctypes.Structure):
    _fields_ = [
        *[(f, ctypes.c_uint64) for f in STAT_FIELDS],
        ("min_wire_len", ctypes.c_uint32),
        ("max_wire_len", ctypes.c_uint32),
        ("first_ts_ns", ctypes.c_uint64),
        ("last_ts_ns", ctypes.c_uint64),
    ]


class _Flow(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint8 * 16),
        ("dst_ip", ctypes.c_uint8 * 16),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("ip_proto", ctypes.c_uint8),
        ("ip_version", ctypes.c_uint8),
        ("_pad", ctypes.c_uint16),
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
    ]


class _FlowTable(ctypes.Structure):
    _fields_ = [
        ("slots", ctypes.POINTER(_Flow)),
        ("capacity", ctypes.c_uint32),
        ("used", ctypes.c_uint32),
        ("dropped", ctypes.c_uint64),
    ]


def _candidate_paths() -> list[Path]:
    here = Path(__file__).resolve().parent
    env = os.environ.get("NEXUS_PKT_LIB")
    paths = [Path(env)] if env else []
    paths += [here / "_lib" / "libnexus_pkt.so"]
    paths += [p / "build" / "libnexus_pkt.so" for p in here.parents[:3]]
    return paths


_lib: ctypes.CDLL | None = None
_lib_error: str | None = None


def load_library() -> ctypes.CDLL | None:
    """Load libnexus_pkt once; returns None if it is not available."""
    global _lib, _lib_error
    if _lib is not None or _lib_error is not None:
        return _lib
    for p in _candidate_paths():
        if p.is_file():
            try:
                lib = ctypes.CDLL(str(p))
            except OSError as e:
                _lib_error = f"{p}: {e}"
                continue
            lib.nx_abi_version.restype = ctypes.c_int
            if lib.nx_abi_version() != 1:
                _lib_error = f"{p}: ABI version mismatch"
                continue
            lib.nx_pcap_parse_file.argtypes = [
                ctypes.c_char_p,
                ctypes.POINTER(_Stats),
                ctypes.POINTER(_FlowTable),
            ]
            lib.nx_pcap_parse_file.restype = ctypes.c_int
            lib.nx_flow_table_init.argtypes = [
                ctypes.POINTER(_FlowTable),
                ctypes.POINTER(_Flow),
                ctypes.c_uint32,
            ]
            lib.nx_flow_table_init.restype = ctypes.c_int
            _lib, _lib_error = lib, None
            return _lib
    _lib_error = _lib_error or "libnexus_pkt.so not found (build csrc/ with CMake)"
    return None


def library_status() -> str:
    load_library()
    return "loaded" if _lib is not None else f"unavailable: {_lib_error}"


# --------------------------------------------------------------- result model


@dataclass
class PcapSummary:
    path: str
    engine: str
    stats: dict[str, int]
    flows: list[dict[str, Any]] = field(default_factory=list)
    flow_count: int = 0
    flows_dropped: int = 0
    warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "engine": self.engine,
            "stats": self.stats,
            "flow_count": self.flow_count,
            "flows_dropped": self.flows_dropped,
            "top_flows": self.flows,
            "warning": self.warning,
        }


def _ip_str(raw: bytes, ver: int) -> str:
    return str(ipaddress.ip_address(raw[:4] if ver == 4 else raw[:16]))


_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 47: "gre", 50: "esp", 132: "sctp"}


def _flow_dict(
    src: bytes, dst: bytes, sp: int, dp: int, proto: int, ver: int, pkts: int, byts: int
) -> dict[str, Any]:
    return {
        "src": _ip_str(src, ver),
        "dst": _ip_str(dst, ver),
        "src_port": sp,
        "dst_port": dp,
        "proto": _PROTO.get(proto, str(proto)),
        "packets": pkts,
        "bytes": byts,
    }


def _top(flows: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    def key(f: dict[str, Any]) -> tuple[Any, ...]:
        return (
            -f["bytes"],
            -f["packets"],
            f["src"],
            f["dst"],
            f["src_port"],
            f["dst_port"],
            f["proto"],
        )

    return sorted(flows, key=key)[:n]


# ------------------------------------------------------------------ C engine


def _analyze_c(lib: ctypes.CDLL, path: Path, top: int, capacity: int) -> PcapSummary:
    stats = _Stats()
    slots = (_Flow * capacity)()
    table = _FlowTable()
    if lib.nx_flow_table_init(ctypes.byref(table), slots, capacity) != NX_OK:
        raise PcapError("flow table capacity must be a power of two")
    rc = lib.nx_pcap_parse_file(os.fsencode(path), ctypes.byref(stats), ctypes.byref(table))
    if rc in FATAL:
        raise PcapError(f"{path}: {ERRORS.get(rc, rc)}")
    flows = [
        _flow_dict(
            bytes(f.src_ip),
            bytes(f.dst_ip),
            f.src_port,
            f.dst_port,
            f.ip_proto,
            f.ip_version,
            f.packets,
            f.bytes,
        )
        for f in slots
        if f.ip_version
    ]
    st = {f[0]: int(getattr(stats, f[0])) for f in _Stats._fields_}
    return PcapSummary(
        str(path),
        "c",
        st,
        _top(flows, top),
        len(flows),
        int(table.dropped),
        None if rc == NX_OK else ERRORS.get(rc, str(rc)),
    )


# ------------------------------------------------------------- Python engine


def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return int(~s & 0xFFFF)


@dataclass
class FrameInfo:
    flags: int = 0
    ethertype: int = 0
    vlan_outer: int = 0
    vlan_inner: int = 0
    ip_proto: int = 0
    src_ip: bytes = b""
    dst_ip: bytes = b""
    src_port: int = 0
    dst_port: int = 0


def _ports(fi: FrameInfo, l4: bytes) -> None:
    if fi.ip_proto not in (6, 17):
        return
    if len(l4) < 4:
        fi.flags |= F_TRUNCATED
        return
    fi.src_port, fi.dst_port = struct.unpack_from("!HH", l4)
    fi.flags |= F_HAS_PORTS


def _ipv4(fi: FrameInfo, ip: bytes) -> None:
    if len(ip) < 20:
        fi.flags |= F_TRUNCATED
        return
    if ip[0] >> 4 != 4:
        fi.flags |= F_MALFORMED
        return
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    if ihl < 20 or total < ihl:
        fi.flags |= F_MALFORMED
        return
    if len(ip) < ihl:
        fi.flags |= F_TRUNCATED
        return
    fi.flags |= F_IPV4
    fi.ip_proto = ip[9]
    fi.src_ip, fi.dst_ip = ip[12:16], ip[16:20]
    if inet_checksum(ip[:ihl]) != 0:
        fi.flags |= F_BAD_CSUM
    frag = struct.unpack_from("!H", ip, 6)[0]
    off = frag & 0x1FFF
    if frag & 0x2000 or off:
        fi.flags |= F_FRAGMENT
    if total > len(ip):
        fi.flags |= F_TRUNCATED
    l3 = ip[: min(len(ip), total)]
    if off:
        return
    _ports(fi, l3[ihl:])


def _ipv6(fi: FrameInfo, ip: bytes) -> None:
    if len(ip) < 40:
        fi.flags |= F_TRUNCATED
        return
    if ip[0] >> 4 != 6:
        fi.flags |= F_MALFORMED
        return
    payload = struct.unpack_from("!H", ip, 4)[0]
    fi.flags |= F_IPV6
    fi.src_ip, fi.dst_ip = ip[8:24], ip[24:40]
    if payload + 40 > len(ip):
        fi.flags |= F_TRUNCATED
        l3 = ip
    else:
        l3 = ip[: payload + 40]
    nh, pos, n = ip[6], 40, 0
    while nh in (0, 43, 44, 60):
        if n >= 8:
            fi.flags |= F_MALFORMED
            fi.ip_proto = nh
            return
        n += 1
        if pos + 8 > len(l3):
            fi.flags |= F_TRUNCATED
            fi.ip_proto = nh
            return
        ext = l3[pos : pos + 8]
        if nh == 44:
            fi.flags |= F_FRAGMENT
            fo = struct.unpack_from("!H", ext, 2)[0] >> 3
            nh = ext[0]
            pos += 8
            if fo:
                fi.ip_proto = nh
                return
            continue
        hlen = (ext[1] + 1) * 8
        nh = ext[0]
        pos += hlen
        if pos > len(l3):
            fi.flags |= F_TRUNCATED
            fi.ip_proto = nh
            return
    fi.ip_proto = nh
    _ports(fi, l3[pos:])


def parse_frame(frame: bytes) -> FrameInfo:
    """Pure-Python twin of ``nx_parse_frame``."""
    fi = FrameInfo()
    if len(frame) < 14:
        fi.flags |= F_TRUNCATED
        return fi
    off = 12
    et = struct.unpack_from("!H", frame, off)[0]
    tags = 0
    while et in (0x8100, 0x88A8):
        if tags >= 2:
            fi.flags |= F_MALFORMED
            break
        if off + 6 > len(frame):
            fi.flags |= F_TRUNCATED
            fi.ethertype = et
            return fi
        vid = struct.unpack_from("!H", frame, off + 2)[0] & 0x0FFF
        if tags == 0:
            fi.vlan_outer = vid
        else:
            fi.vlan_inner = vid
        tags += 1
        off += 4
        et = struct.unpack_from("!H", frame, off)[0]
    if tags:
        fi.flags |= F_VLAN
    if tags > 1:
        fi.flags |= F_QINQ
    fi.ethertype = et
    if fi.flags & F_MALFORMED:
        return fi
    off += 2
    if et == 0x0800:
        _ipv4(fi, frame[off:])
    elif et == 0x86DD:
        _ipv6(fi, frame[off:])
    elif et == 0x0806:
        fi.flags |= F_ARP
        if len(frame) - off < 28:
            fi.flags |= F_TRUNCATED
    return fi


def _analyze_py(path: Path, top: int) -> PcapSummary:
    try:
        data = path.read_bytes()
    except OSError as e:
        raise PcapError(f"{path}: {ERRORS[-2]} ({e})") from None
    st: dict[str, int] = {f[0]: 0 for f in _Stats._fields_}
    flows: dict[tuple[bytes, bytes, int, int, int, int], list[int]] = {}
    warning = None

    if len(data) < 24:
        magic_ok = len(data) >= 4 and struct.unpack_from("<I", data)[0] in (
            0xA1B2C3D4,
            0xA1B23C4D,
            0xD4C3B2A1,
            0x4D3CB2A1,
        )
        raise PcapError(f"{path}: {ERRORS[-5] if magic_ok else ERRORS[-3]}")
    magic = struct.unpack_from("<I", data)[0]
    order, nsec = {
        0xA1B2C3D4: ("<", False),
        0xA1B23C4D: ("<", True),
        0xD4C3B2A1: (">", False),
        0x4D3CB2A1: (">", True),
    }.get(magic, ("", False))
    if not order:
        raise PcapError(f"{path}: {ERRORS[-3]}")
    if struct.unpack_from(order + "I", data, 20)[0] & 0x0FFFFFFF != 1:
        raise PcapError(f"{path}: {ERRORS[-4]}")
    pos = 24
    while pos < len(data):
        if len(data) - pos < 16:
            warning = ERRORS[-5]
            break
        sec, frac, caplen, wire = struct.unpack_from(order + "IIII", data, pos)
        if caplen > MAX_CAPLEN:
            warning = ERRORS[-7]
            break
        pos += 16
        if len(data) - pos < caplen:
            warning = ERRORS[-5]
            break
        frame = data[pos : pos + caplen]
        pos += caplen
        ts = sec * 1_000_000_000 + (frac if nsec else frac * 1000)
        if st["packets"] == 0:
            st["first_ts_ns"], st["min_wire_len"], st["max_wire_len"] = ts, wire, wire
        st["last_ts_ns"] = ts
        st["packets"] += 1
        st["bytes_captured"] += caplen
        st["bytes_wire"] += wire
        st["min_wire_len"] = min(st["min_wire_len"], wire)
        st["max_wire_len"] = max(st["max_wire_len"], wire)
        fi = parse_frame(frame)
        if caplen > wire:
            fi.flags |= F_MALFORMED
        if caplen < wire or fi.flags & F_TRUNCATED:
            st["truncated"] += 1
        for flag, key in (
            (F_MALFORMED, "malformed"),
            (F_VLAN, "vlan_tagged"),
            (F_QINQ, "qinq"),
            (F_FRAGMENT, "fragments"),
            (F_BAD_CSUM, "bad_ipv4_csum"),
        ):
            if fi.flags & flag:
                st[key] += 1
        if fi.flags & F_ARP:
            st["arp"] += 1
        elif fi.flags & (F_IPV4 | F_IPV6):
            st["ipv4" if fi.flags & F_IPV4 else "ipv6"] += 1
            p = fi.ip_proto
            st[
                "tcp" if p == 6 else "udp" if p == 17 else "icmp" if p in (1, 58) else "other_l4"
            ] += 1
            ver = 4 if fi.flags & F_IPV4 else 6
            sp, dp = (fi.src_port, fi.dst_port) if fi.flags & F_HAS_PORTS else (0, 0)
            k = (fi.src_ip, fi.dst_ip, sp, dp, p, ver)
            acc = flows.setdefault(k, [0, 0])
            acc[0] += 1
            acc[1] += wire
        else:
            st["other_l3"] += 1
    fl = [_flow_dict(s, d, sp, dp, p, v, c[0], c[1]) for (s, d, sp, dp, p, v), c in flows.items()]
    return PcapSummary(str(path), "python", st, _top(fl, top), len(fl), 0, warning)


def analyze_pcap(
    path: str | Path, *, engine: str = "auto", top: int = 10, flow_capacity: int = 65536
) -> PcapSummary:
    """Summarise a capture. ``engine`` is ``auto`` (C if built), ``c`` or ``python``."""
    p = Path(path)
    if engine not in ("auto", "c", "python"):
        raise ValueError("engine must be auto, c or python")
    if engine in ("auto", "c"):
        lib = load_library()
        if lib is not None:
            return _analyze_c(lib, p, top, flow_capacity)
        if engine == "c":
            raise PcapError(f"C engine requested but {library_status()}")
    return _analyze_py(p, top)
