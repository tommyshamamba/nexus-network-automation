"""Configuration backup with git-style unified diffs.

Each device's normalised running config is written to ``<dest>/<name>.cfg``.
The diff against the previous copy is produced with ``difflib`` in the same
``a/`` ``b/`` unified format git uses, so it pastes cleanly into a review or
ticket. With ``use_git=True`` the backup directory is also a git repository
and every run that changes something becomes a commit, which gives history,
blame and ``git log -p`` for free.
"""

from __future__ import annotations

import difflib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.collector import DeviceResult
from nexus.inventory import Device
from nexus.platforms import PLATFORMS

log = logging.getLogger(__name__)


@dataclass
class BackupEntry:
    device: str
    status: str  # new | changed | unchanged | failed
    path: str | None = None
    added: int = 0
    removed: int = 0
    diff: str = ""
    error: str | None = None


@dataclass
class BackupRun:
    timestamp: str
    entries: list[BackupEntry]
    commit: str | None = None
    git_error: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        c = {"new": 0, "changed": 0, "unchanged": 0, "failed": 0}
        for e in self.entries:
            c[e.status] += 1
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "commit": self.commit,
            "git_error": self.git_error,
            "counts": self.counts,
            "devices": [asdict(e) for e in self.entries],
        }


def unified_diff(old: str, new: str, name: str) -> tuple[str, int, int]:
    """Return (diff_text, lines_added, lines_removed)."""
    lines = list(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )
    added = sum(1 for ln in lines if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in lines if ln.startswith("-") and not ln.startswith("---"))
    return "".join(lines), added, removed


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _git(dest: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(dest), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _git_commit(dest: Path, run: BackupRun) -> str | None:
    if shutil.which("git") is None:
        raise RuntimeError("git is not installed but --git was requested")
    if not (dest / ".git").exists():
        _git(dest, "init", "-q")
    if not any(dest.glob("*.cfg")):
        return None  # nothing collected yet (e.g. every device failed on the first run)
    _git(dest, "add", "-A", "--", "*.cfg")
    if not _git(dest, "status", "--porcelain", "--", "*.cfg"):
        return None
    c = run.counts
    msg = f"backup {run.timestamp}: {c['new']} new, {c['changed']} changed, {c['failed']} failed"
    env_args = ["-c", "user.name=nexus", "-c", "user.email=nexus@localhost"]
    subprocess.run(
        ["git", "-C", str(dest), *env_args, "commit", "-q", "-m", msg],
        check=True,
        capture_output=True,
        text=True,
    )
    return _git(dest, "rev-parse", "--short", "HEAD")


def write_backups(
    results: list[DeviceResult],
    devices: dict[str, Device],
    dest: str | Path,
    *,
    use_git: bool = False,
    now: datetime | None = None,
) -> BackupRun:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    ts = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    entries: list[BackupEntry] = []
    for r in results:
        dev = devices[r.device]
        plat = PLATFORMS[dev.platform]
        if not r.ok:
            entries.append(BackupEntry(r.device, "failed", error=r.error))
            continue
        raw = r.outputs.get(plat.config_command, "")
        if not raw.strip():
            entries.append(BackupEntry(r.device, "failed", error="empty configuration output"))
            continue
        cfg = plat.normalize_config(raw)
        name = f"{r.device}.cfg"
        path = dest / name
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old is None:
            _atomic_write(path, cfg)
            entries.append(BackupEntry(r.device, "new", str(path), added=cfg.count("\n")))
        elif old == cfg:
            entries.append(BackupEntry(r.device, "unchanged", str(path)))
        else:
            diff, added, removed = unified_diff(old, cfg, name)
            _atomic_write(path, cfg)
            entries.append(BackupEntry(r.device, "changed", str(path), added, removed, diff))
    run = BackupRun(ts, entries)
    if use_git:
        try:
            run.commit = _git_commit(dest, run)
        except subprocess.CalledProcessError as e:
            # The backups themselves are already on disk; a git problem should not lose them.
            run.git_error = (e.stderr or str(e)).strip()
            log.warning("git commit failed in %s: %s", dest, run.git_error)
    _atomic_write(dest / ".nexus" / "last_backup.json", json.dumps(run.to_dict(), indent=2))
    return run


def load_backups(src: str | Path) -> dict[str, str]:
    """Read ``<name>.cfg`` files written by :func:`write_backups`."""
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(Path(src).glob("*.cfg"))}
