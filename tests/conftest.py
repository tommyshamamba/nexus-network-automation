from __future__ import annotations

import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from nexus.mockdev import MockLab, devices_from_fixtures

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
FIXTURES = EXAMPLES / "fixtures"
POLICIES = EXAMPLES / "policies"
DATA = Path(__file__).resolve().parent / "data"
LAB_PASSWORD = "lab-test-password"


@pytest.fixture
def lab_fixtures(tmp_path: Path) -> Path:
    """A writable copy of the example device fixtures."""
    dst = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, dst)
    return dst


@pytest.fixture
async def mock_lab(lab_fixtures: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[MockLab]:
    monkeypatch.setenv("NEXUS_PASSWORD", LAB_PASSWORD)
    lab = MockLab(devices_from_fixtures(lab_fixtures), LAB_PASSWORD)
    await lab.start()
    try:
        yield lab
    finally:
        await lab.stop()


def lab_inventory(lab: MockLab, path: Path, extra: str = "") -> Path:
    """Inventory YAML pointing at the ephemeral ports of a running MockLab."""
    plat = {"access-sw1": "cisco_ios", "core-sw1": "arista_eos", "edge-rtr1": "juniper_junos"}
    lines = [
        "defaults: {username: netops, password_env: NEXUS_PASSWORD, timeout: 3,"
        " strict_host_key: false}",
        "devices:",
    ]
    for d in lab.devices:
        lines.append(
            f"  - {{name: {d.name}, host: 127.0.0.1, port: {d.port}, platform: {plat[d.name]}}}"
        )
    path.write_text("\n".join(lines) + "\n" + extra)
    return path
