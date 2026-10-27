"""Device inventory loaded from YAML.

Example::

    defaults:
      username: ${NEXUS_USERNAME:-admin}
      password_env: NEXUS_PASSWORD   # name of the env var, never the secret
      port: 22
    groups:
      core: {platform: arista_eos}
    devices:
      - {name: core-sw1, host: 10.0.0.1, groups: [core]}

Secrets are never read from the file itself: ``password_env`` names an
environment variable and ``key_file`` points at an SSH private key.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nexus.platforms import PLATFORMS

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})*$"
)

_ALLOWED_KEYS = {
    "name",
    "host",
    "port",
    "platform",
    "username",
    "password_env",
    "key_file",
    "groups",
    "tags",
    "timeout",
    "strict_host_key",
    "known_hosts",
}


class InventoryError(ValueError):
    """Raised when the inventory file is invalid. Lists every problem found."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid inventory:\n  - " + "\n  - ".join(problems))


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    platform: str
    port: int = 22
    username: str | None = None
    password_env: str | None = None
    key_file: str | None = None
    groups: tuple[str, ...] = ()
    tags: Mapping[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    strict_host_key: bool = True
    known_hosts: str | None = None

    def password(self) -> str | None:
        """Resolve the password from the environment at connect time."""
        if not self.password_env:
            return None
        return os.environ.get(self.password_env)

    def public_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "platform": self.platform,
            "groups": list(self.groups),
            "tags": dict(self.tags),
            "auth": "key" if self.key_file else ("password" if self.password_env else "agent"),
        }


@dataclass(frozen=True)
class Inventory:
    devices: tuple[Device, ...]

    def __iter__(self) -> Any:
        return iter(self.devices)

    def __len__(self) -> int:
        return len(self.devices)

    def get(self, name: str) -> Device:
        for d in self.devices:
            if d.name == name:
                return d
        raise KeyError(name)

    def select(self, limit: Iterable[str] | None = None) -> list[Device]:
        """Filter by device name, group name, or ``key=value`` tag."""
        wanted = [w for w in (limit or []) if w]
        if not wanted:
            return list(self.devices)
        out: list[Device] = []
        for d in self.devices:
            for w in wanted:
                if "=" in w:
                    k, v = w.split("=", 1)
                    hit = d.tags.get(k) == v
                else:
                    hit = w == d.name or w in d.groups
                if hit:
                    out.append(d)
                    break
        return out


def expand_env(value: Any, env: Mapping[str, str] | None = None) -> Any:
    """Expand ``${VAR}`` and ``${VAR:-default}`` in strings, recursively."""
    env = os.environ if env is None else env
    if isinstance(value, str):

        def sub(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in env and env[name] != "":
                return env[name]
            if default is not None:
                return default
            raise KeyError(name)

        return _ENV_RE.sub(sub, value)
    if isinstance(value, list):
        return [expand_env(v, env) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, env) for k, v in value.items()}
    return value


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.match(host))


def parse_inventory(data: Any, env: Mapping[str, str] | None = None) -> Inventory:
    problems: list[str] = []
    if not isinstance(data, dict):
        raise InventoryError(["top level must be a mapping with a 'devices' list"])
    defaults = data.get("defaults") or {}
    groups = data.get("groups") or {}
    raw_devices = data.get("devices")
    if not isinstance(defaults, dict):
        problems.append("'defaults' must be a mapping")
        defaults = {}
    if not isinstance(groups, dict):
        problems.append("'groups' must be a mapping of group name -> settings")
        groups = {}
    if not isinstance(raw_devices, list) or not raw_devices:
        problems.append("'devices' must be a non-empty list")
        raise InventoryError(problems)

    seen: set[str] = set()
    devices: list[Device] = []
    for idx, raw in enumerate(raw_devices):
        where = f"devices[{idx}]"
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        where = f"devices[{idx}] ({raw.get('name', '?')})"
        dev_groups = raw.get("groups") or []
        if not isinstance(dev_groups, list):
            problems.append(f"{where}: 'groups' must be a list")
            dev_groups = []
        merged: dict[str, Any] = dict(defaults)
        for g in dev_groups:
            if g not in groups:
                problems.append(f"{where}: unknown group '{g}'")
                continue
            merged.update(groups[g] or {})
        merged.update(raw)
        merged["groups"] = dev_groups
        unknown = set(merged) - _ALLOWED_KEYS - {"password"}
        if unknown:
            problems.append(f"{where}: unknown keys {sorted(unknown)}")
        if "password" in merged:
            problems.append(f"{where}: plaintext 'password' is not allowed; use password_env")
        try:
            merged = expand_env(merged, env)
        except KeyError as e:
            problems.append(f"{where}: environment variable {e.args[0]} is not set")
            continue

        name = str(merged.get("name", ""))
        host = str(merged.get("host", ""))
        platform = str(merged.get("platform", ""))
        if not _NAME_RE.match(name):
            problems.append(f"{where}: 'name' is missing or has invalid characters")
        elif name in seen:
            problems.append(f"{where}: duplicate device name '{name}'")
        seen.add(name)
        if not host or not _valid_host(host):
            problems.append(f"{where}: 'host' is missing or not a valid IP/hostname")
        if platform not in PLATFORMS:
            problems.append(
                f"{where}: platform '{platform}' is not supported "
                f"(choose from {', '.join(sorted(PLATFORMS))})"
            )
        try:
            port = int(merged.get("port", 22))
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            problems.append(f"{where}: 'port' must be an integer 1-65535")
            port = 22
        try:
            timeout = float(merged.get("timeout", 10.0))
            if timeout <= 0:
                raise ValueError
        except (TypeError, ValueError):
            problems.append(f"{where}: 'timeout' must be a positive number")
            timeout = 10.0
        tags = merged.get("tags") or {}
        if not isinstance(tags, dict):
            problems.append(f"{where}: 'tags' must be a mapping")
            tags = {}
        devices.append(
            Device(
                name=name,
                host=host,
                platform=platform,
                port=port,
                username=merged.get("username"),
                password_env=merged.get("password_env"),
                key_file=merged.get("key_file"),
                groups=tuple(str(g) for g in dev_groups),
                tags={str(k): str(v) for k, v in tags.items()},
                timeout=timeout,
                strict_host_key=bool(merged.get("strict_host_key", True)),
                known_hosts=merged.get("known_hosts"),
            )
        )
    if problems:
        raise InventoryError(problems)
    return Inventory(tuple(devices))


def load_inventory(path: str | Path, env: Mapping[str, str] | None = None) -> Inventory:
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise InventoryError([f"inventory file not found: {p}"]) from None
    except yaml.YAMLError as e:
        raise InventoryError([f"YAML parse error in {p}: {e}"]) from None
    return parse_inventory(data, env)
