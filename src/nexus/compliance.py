"""Compliance rules engine.

Policies are YAML files with a list of rules. Each rule has a ``type``:

``must_match``            at least one line matches ``pattern``
``must_not_match``        no line matches ``pattern`` (offending lines are evidence)
``count``                 number of matching lines is within ``min``/``max``
``section_must_contain``  every section whose header matches ``section`` has a
                          child line matching ``pattern`` (indentation-based
                          configs: IOS, EOS)
``vlans_present``         every VLAN ID in ``vlans`` is defined
``vlans_absent``          none of the VLAN IDs in ``vlans`` is defined

Patterns are Python regular expressions applied line by line. Rules can be
restricted to ``platforms``. Severity is one of low/medium/high/critical.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from nexus.platforms import PLATFORMS

SEVERITIES = ("low", "medium", "high", "critical")
RULE_TYPES = (
    "must_match",
    "must_not_match",
    "count",
    "section_must_contain",
    "vlans_present",
    "vlans_absent",
)
MAX_EVIDENCE = 10


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    type: str
    severity: str
    policy: str
    pattern: re.Pattern[str] | None = None
    section: re.Pattern[str] | None = None
    min: int | None = None
    max: int | None = None
    vlans: tuple[int, ...] = ()
    platforms: tuple[str, ...] = ()
    remediation: str = ""

    def applies_to(self, platform: str) -> bool:
        return not self.platforms or platform in self.platforms


@dataclass
class RuleResult:
    rule_id: str
    title: str
    severity: str
    status: str  # pass | fail | skip
    message: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class DeviceCompliance:
    device: str
    platform: str
    results: list[RuleResult]
    error: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        c = {"pass": 0, "fail": 0, "skip": 0}
        for r in self.results:
            c[r.status] += 1
        return c

    @property
    def score(self) -> float | None:
        c = self.counts
        total = c["pass"] + c["fail"]
        return round(100.0 * c["pass"] / total, 1) if total else None


# ------------------------------------------------------------------ loading


def _compile(rule_id: str, key: str, value: Any) -> re.Pattern[str]:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"rule {rule_id}: '{key}' must be a non-empty regex string")
    try:
        return re.compile(value)
    except re.error as e:
        raise PolicyError(f"rule {rule_id}: invalid regex in '{key}': {e}") from None


def parse_policy(data: Any, source: str = "<policy>") -> list[Rule]:
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise PolicyError(f"{source}: expected a mapping with a 'rules' list")
    policy_name = str(data.get("policy") or Path(source).stem)
    rules: list[Rule] = []
    for i, raw in enumerate(data["rules"]):
        if not isinstance(raw, dict):
            raise PolicyError(f"{source}: rules[{i}] must be a mapping")
        rid = str(raw.get("id") or "")
        if not rid:
            raise PolicyError(f"{source}: rules[{i}] is missing 'id'")
        rtype = raw.get("type")
        if rtype not in RULE_TYPES:
            raise PolicyError(
                f"rule {rid}: unknown type {rtype!r} (one of {', '.join(RULE_TYPES)})"
            )
        sev = raw.get("severity", "medium")
        if sev not in SEVERITIES:
            raise PolicyError(f"rule {rid}: severity must be one of {', '.join(SEVERITIES)}")
        plats = tuple(raw.get("platforms") or ())
        bad = [p for p in plats if p not in PLATFORMS]
        if bad:
            raise PolicyError(f"rule {rid}: unknown platforms {bad}")
        kw: dict[str, Any] = {}
        if rtype in ("must_match", "must_not_match", "count", "section_must_contain"):
            kw["pattern"] = _compile(rid, "pattern", raw.get("pattern"))
        if rtype == "section_must_contain":
            kw["section"] = _compile(rid, "section", raw.get("section"))
        if rtype == "count":
            mn, mx = raw.get("min"), raw.get("max")
            if mn is None and mx is None:
                raise PolicyError(f"rule {rid}: 'count' needs 'min' and/or 'max'")
            for k, v in (("min", mn), ("max", mx)):
                if v is not None and (not isinstance(v, int) or v < 0):
                    raise PolicyError(f"rule {rid}: '{k}' must be a non-negative integer")
            if mn is not None and mx is not None and mn > mx:
                raise PolicyError(f"rule {rid}: min > max")
            kw["min"], kw["max"] = mn, mx
        if rtype in ("vlans_present", "vlans_absent"):
            vl = raw.get("vlans")
            if (
                not isinstance(vl, list)
                or not vl
                or not all(isinstance(v, int) and 1 <= v <= 4094 for v in vl)
            ):
                raise PolicyError(f"rule {rid}: 'vlans' must be a list of IDs 1-4094")
            kw["vlans"] = tuple(vl)
        rules.append(
            Rule(
                id=rid,
                title=str(raw.get("title") or rid),
                type=rtype,
                severity=sev,
                policy=policy_name,
                platforms=plats,
                remediation=str(raw.get("remediation") or ""),
                **kw,
            )
        )
    ids = [r.id for r in rules]
    dup = {x for x in ids if ids.count(x) > 1}
    if dup:
        raise PolicyError(f"{source}: duplicate rule ids {sorted(dup)}")
    return rules


def load_policies(paths: Iterable[str | Path]) -> list[Rule]:
    """Load policy files; a directory loads every ``*.yaml``/``*.yml`` in it."""
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted([*p.glob("*.yaml"), *p.glob("*.yml")]))
        elif p.is_file():
            files.append(p)
        else:
            raise PolicyError(f"policy path not found: {p}")
    if not files:
        raise PolicyError("no policy files found")
    rules: list[Rule] = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise PolicyError(f"{f}: YAML parse error: {e}") from None
        rules.extend(parse_policy(data, str(f)))
    ids = [r.id for r in rules]
    dup = {x for x in ids if ids.count(x) > 1}
    if dup:
        raise PolicyError(f"duplicate rule ids across policy files: {sorted(dup)}")
    return rules


# ------------------------------------------------------------- config model


def config_lines(config: str) -> list[str]:
    return [ln.rstrip() for ln in config.splitlines()]


def sections(lines: list[str], header: re.Pattern[str]) -> list[tuple[str, list[str]]]:
    """Indentation-based sections: a header at column 0 and its indented children."""
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for ln in lines:
        if not ln.strip():
            continue
        if not ln[0].isspace():
            current = None
            if header.search(ln):
                current = (ln, [])
                out.append(current)
        elif current is not None:
            current[1].append(ln.strip())
    return out


_VLAN_LINE = re.compile(r"^vlan\s+([0-9][0-9,\-\s]*)$")
_JUNOS_VLAN = re.compile(r"^set vlans \S+ vlan-id (\d+)\b")


def expand_vlan_list(spec: str) -> set[int]:
    out: set[int] = set()
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi or hi - lo > 4094:
                continue
            out.update(range(lo, hi + 1))
        else:
            out.add(int(part))
    return {v for v in out if 1 <= v <= 4094}


def defined_vlans(lines: list[str], platform: str) -> set[int]:
    vlans: set[int] = set()
    for ln in lines:
        if platform == "juniper_junos":
            m = _JUNOS_VLAN.match(ln)
            if m:
                vlans.add(int(m.group(1)))
        else:
            m = _VLAN_LINE.match(ln)
            if m:
                vlans |= expand_vlan_list(m.group(1))
    return vlans


def _fmt_ranges(vs: Iterable[int]) -> str:
    return ", ".join(str(v) for v in sorted(vs))


# ---------------------------------------------------------------- evaluation


def evaluate_rule(rule: Rule, lines: list[str], platform: str) -> RuleResult:
    def res(status: str, msg: str, ev: list[str] | None = None) -> RuleResult:
        return RuleResult(
            rule.id,
            rule.title,
            rule.severity,
            status,
            msg,
            (ev or [])[:MAX_EVIDENCE],
            rule.remediation,
        )

    if not rule.applies_to(platform):
        return res("skip", f"not applicable to {platform}")
    if rule.type in ("must_match", "must_not_match", "count"):
        assert rule.pattern is not None
        hits = [f"{n}: {ln}" for n, ln in enumerate(lines, 1) if rule.pattern.search(ln)]
        if rule.type == "must_match":
            return (
                res("pass", "required line present", hits)
                if hits
                else res("fail", f"no line matches /{rule.pattern.pattern}/")
            )
        if rule.type == "must_not_match":
            return (
                res("fail", f"{len(hits)} forbidden line(s) found", hits)
                if hits
                else res("pass", "no forbidden lines")
            )
        n = len(hits)
        ok = (rule.min is None or n >= rule.min) and (rule.max is None or n <= rule.max)
        bounds = (
            f"min={rule.min}"
            if rule.max is None
            else (f"max={rule.max}" if rule.min is None else f"{rule.min}..{rule.max}")
        )
        return res("pass" if ok else "fail", f"{n} matching line(s), expected {bounds}", hits)
    if rule.type == "section_must_contain":
        assert rule.pattern is not None and rule.section is not None
        secs = sections(lines, rule.section)
        if not secs:
            return res("fail", f"no section matches /{rule.section.pattern}/")
        missing = [hdr for hdr, kids in secs if not any(rule.pattern.search(k) for k in kids)]
        if missing:
            return res(
                "fail",
                f"{len(missing)} of {len(secs)} section(s) lack /{rule.pattern.pattern}/",
                missing,
            )
        return res("pass", f"all {len(secs)} section(s) compliant", [h for h, _ in secs])
    defined = defined_vlans(lines, platform)
    want = set(rule.vlans)
    if rule.type == "vlans_present":
        miss = want - defined
        if miss:
            return res("fail", f"missing VLAN(s): {_fmt_ranges(miss)}")
        return res("pass", f"VLAN(s) {_fmt_ranges(want)} defined")
    bad = want & defined
    if bad:
        return res("fail", f"forbidden VLAN(s) defined: {_fmt_ranges(bad)}")
    return res("pass", "no forbidden VLANs defined")


def evaluate_device(device: str, platform: str, config: str, rules: list[Rule]) -> DeviceCompliance:
    lines = config_lines(config)
    return DeviceCompliance(device, platform, [evaluate_rule(r, lines, platform) for r in rules])


def build_report(
    devices: list[DeviceCompliance],
    rules: list[Rule],
    *,
    source: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    by_sev = {s: 0 for s in SEVERITIES}
    totals = {"pass": 0, "fail": 0, "skip": 0}
    for d in devices:
        for r in d.results:
            totals[r.status] += 1
            if r.status == "fail":
                by_sev[r.severity] += 1
    return {
        "generated_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "nexus comply",
        "source": source,
        "policies": sorted({r.policy for r in rules}),
        "rule_count": len(rules),
        "summary": {
            "devices": len(devices),
            "devices_with_errors": sum(1 for d in devices if d.error),
            "devices_compliant": sum(1 for d in devices if not d.error and d.counts["fail"] == 0),
            **totals,
            "failures_by_severity": by_sev,
        },
        "devices": [
            {
                "device": d.device,
                "platform": d.platform,
                "error": d.error,
                "score": d.score,
                "counts": d.counts,
                "results": [asdict(r) for r in d.results],
            }
            for d in devices
        ],
    }


def worst_failure(report: Mapping[str, Any]) -> str | None:
    sev = report["summary"]["failures_by_severity"]
    for s in reversed(SEVERITIES):
        if sev.get(s):
            return s
    return None


def should_fail(report: Mapping[str, Any], threshold: str) -> bool:
    if threshold == "never":
        return False
    w = worst_failure(report)
    return w is not None and SEVERITIES.index(w) >= SEVERITIES.index(threshold)
