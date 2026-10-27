from __future__ import annotations

import json

from nexus.compliance import DeviceCompliance, build_report, evaluate_device, parse_policy
from nexus.report import to_html, to_json, to_text


def _report() -> dict[str, object]:
    rules = parse_policy(
        {
            "policy": "p",
            "rules": [
                {
                    "id": "B-1",
                    "type": "must_match",
                    "pattern": "^banner",
                    "severity": "low",
                    "title": "<script>alert(1)</script>",
                    "remediation": "add a banner",
                },
            ],
        }
    )
    devs = [
        evaluate_device("sw<1>", "cisco_ios", "hostname x\n", rules),
        DeviceCompliance("sw2", "cisco_ios", [], error="timeout: connect timed out"),
    ]
    return build_report(devs, rules, source="unit")


def test_json_round_trip() -> None:
    rep = _report()
    back = json.loads(to_json(rep))  # type: ignore[arg-type]
    assert back["summary"]["devices"] == 2
    assert back["summary"]["devices_with_errors"] == 1
    assert back["devices"][0]["results"][0]["status"] == "fail"


def test_html_escapes_untrusted_strings() -> None:
    html = to_html(_report())  # type: ignore[arg-type]
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "sw&lt;1&gt;" in html
    assert "Not evaluated: timeout" in html
    assert "add a banner" in html  # remediation shown for failures


def test_text_summary() -> None:
    txt = to_text(_report())  # type: ignore[arg-type]
    assert "0/2 devices compliant" in txt
    assert "B-1" in txt and "timeout" in txt
