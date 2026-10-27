"""Per-platform knowledge: which commands to run and how to clean output.

Volatile lines (timestamps, byte counts, NTP clock drift) are removed before
a config is stored, otherwise every backup would show a spurious diff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Platform:
    name: str
    config_command: str
    facts_commands: tuple[str, ...]
    volatile: tuple[re.Pattern[str], ...]
    comment_prefix: str

    def normalize_config(self, text: str) -> str:
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        kept = [ln.rstrip() for ln in lines if not any(p.search(ln) for p in self.volatile)]
        while kept and not kept[0].strip():
            kept.pop(0)
        while kept and not kept[-1].strip():
            kept.pop()
        return "\n".join(kept) + "\n"


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


PLATFORMS: dict[str, Platform] = {
    "cisco_ios": Platform(
        name="cisco_ios",
        config_command="show running-config",
        facts_commands=("show version",),
        volatile=_rx(
            r"^Building configuration",
            r"^Current configuration\s*:",
            r"^! (Last configuration change|NVRAM config last updated)",
            r"^ntp clock-period",
        ),
        comment_prefix="!",
    ),
    "arista_eos": Platform(
        name="arista_eos",
        config_command="show running-config",
        facts_commands=("show version",),
        volatile=_rx(
            r"^! Command: show running-config", r"^! (device|Startup-config last modified)"
        ),
        comment_prefix="!",
    ),
    "juniper_junos": Platform(
        name="juniper_junos",
        config_command="show configuration | display set",
        facts_commands=("show version",),
        volatile=_rx(r"^## Last (commit|changed)"),
        comment_prefix="#",
    ),
}
