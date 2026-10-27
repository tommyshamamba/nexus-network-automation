"""Render compliance reports as JSON, HTML and a plain-text summary."""

from __future__ import annotations

import json
from html import escape
from typing import Any

_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1f2328}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}
th,td{border:1px solid #d0d7de;padding:.35rem .5rem;text-align:left;vertical-align:top}
td{font-size:.9rem}
th{background:#f6f8fa} code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem}
pre{margin:0;white-space:pre-wrap}
.pass{color:#1a7f37;font-weight:600}.fail{color:#cf222e;font-weight:600}.skip{color:#6e7781}
.sev-critical,.sev-high{color:#cf222e}.sev-medium{color:#9a6700}.sev-low{color:#6e7781}
.meta{color:#57606a;font-size:.85rem}
"""


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def to_html(report: dict[str, Any]) -> str:
    s = report["summary"]
    e = escape
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>NEXUS compliance report</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>NEXUS compliance report</h1>",
        f"<p class='meta'>Generated {e(report['generated_at'])} &middot; source: "
        f"<code>{e(report['source'])}</code> &middot; policies: "
        f"{e(', '.join(report['policies']))} ({report['rule_count']} rules)</p>",
        "<table><tr><th>Devices</th><th>Compliant</th><th>Unreachable/errors</th>"
        "<th>Checks passed</th><th>Checks failed</th><th>Skipped</th>"
        "<th>Failures by severity</th></tr>",
        f"<tr><td>{s['devices']}</td><td>{s['devices_compliant']}</td>"
        f"<td>{s['devices_with_errors']}</td><td class='pass'>{s['pass']}</td>"
        f"<td class='fail'>{s['fail']}</td><td>{s['skip']}</td><td>"
        + ", ".join(
            f"<span class='sev-{k}'>{k}: {v}</span>"
            for k, v in reversed(list(s["failures_by_severity"].items()))
        )
        + "</td></tr></table>",
        "<h2>Devices</h2><table><tr><th>Device</th><th>Platform</th><th>Score</th>"
        "<th>Pass</th><th>Fail</th><th>Skip</th><th>Error</th></tr>",
    ]
    for d in report["devices"]:
        score = "n/a" if d["score"] is None else f"{d['score']:.1f}%"
        out.append(
            f"<tr><td><a href='#dev-{e(d['device'])}'>{e(d['device'])}</a></td>"
            f"<td>{e(d['platform'])}</td><td>{score}</td>"
            f"<td>{d['counts']['pass']}</td><td>{d['counts']['fail']}</td>"
            f"<td>{d['counts']['skip']}</td><td>{e(d['error'] or '')}</td></tr>"
        )
    out.append("</table>")
    for d in report["devices"]:
        out.append(
            f"<h2 id='dev-{e(d['device'])}'>{e(d['device'])} "
            f"<span class='meta'>({e(d['platform'])})</span></h2>"
        )
        if d["error"]:
            out.append(f"<p class='fail'>Not evaluated: {e(d['error'])}</p>")
            continue
        out.append(
            "<table><tr><th>Rule</th><th>Severity</th><th>Status</th>"
            "<th>Detail</th><th>Evidence</th><th>Remediation</th></tr>"
        )
        order = {"fail": 0, "pass": 1, "skip": 2}
        for r in sorted(d["results"], key=lambda r: (order[r["status"]], r["rule_id"])):
            ev = "\n".join(r["evidence"])
            out.append(
                f"<tr><td><code>{e(r['rule_id'])}</code><br>{e(r['title'])}</td>"
                f"<td class='sev-{e(r['severity'])}'>{e(r['severity'])}</td>"
                f"<td class='{e(r['status'])}'>{e(r['status'].upper())}</td>"
                f"<td>{e(r['message'])}</td><td><pre>{e(ev)}</pre></td>"
                f"<td>{e(r['remediation']) if r['status'] == 'fail' else ''}</td></tr>"
            )
        out.append("</table>")
    out.append("</body></html>\n")
    return "\n".join(out)


def to_text(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"{'DEVICE':<14} {'PLATFORM':<14} {'SCORE':>7} {'PASS':>5} {'FAIL':>5} {'SKIP':>5}  NOTE"
    ]
    for d in report["devices"]:
        score = "n/a" if d["score"] is None else f"{d['score']:.1f}%"
        c = d["counts"]
        note = d["error"] or ", ".join(r["rule_id"] for r in d["results"] if r["status"] == "fail")
        lines.append(
            f"{d['device']:<14} {d['platform']:<14} {score:>7} {c['pass']:>5} "
            f"{c['fail']:>5} {c['skip']:>5}  {note}"
        )
    sev = ", ".join(f"{k}={v}" for k, v in s["failures_by_severity"].items() if v)
    lines.append(
        f"\n{s['devices_compliant']}/{s['devices']} devices compliant; "
        f"{s['fail']} failed checks ({sev or 'none'}); {s['devices_with_errors']} not evaluated"
    )
    return "\n".join(lines) + "\n"
