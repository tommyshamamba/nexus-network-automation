"""Collector behaviour with an in-memory transport (no network)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from nexus.collector import RetryPolicy, collect
from nexus.inventory import Device
from nexus.transport import AuthError, CollectTimeout, CommandError, ConnectError, FixtureTransport
from tests.conftest import FIXTURES

FAST = RetryPolicy(retries=2, backoff_s=0.001, jitter=False)


def devs(n: int) -> list[Device]:
    return [Device(name=f"d{i}", host="10.0.0.1", platform="cisco_ios") for i in range(n)]


class FakeSession:
    async def run(self, command: str) -> str:
        await asyncio.sleep(0.01)
        return f"out:{command}"


class FakeTransport:
    """Scripted failures per device; tracks peak concurrency."""

    def __init__(self, script: dict[str, list[Exception]] | None = None):
        self.script = script or {}
        self.active = 0
        self.peak = 0
        self.opens: dict[str, int] = {}

    @asynccontextmanager
    async def session(self, device: Device) -> AsyncIterator[FakeSession]:
        self.opens[device.name] = self.opens.get(device.name, 0) + 1
        errs = self.script.get(device.name, [])
        if errs:
            raise errs.pop(0)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            yield FakeSession()
        finally:
            self.active -= 1


async def test_concurrency_limit_is_respected() -> None:
    t = FakeTransport()
    res = await collect(devs(25), lambda d: ["show a", "show b"], t, concurrency=4, policy=FAST)
    assert all(r.ok for r in res)
    assert t.peak == 4
    assert [r.device for r in res] == [f"d{i}" for i in range(25)]  # inventory order kept
    assert res[0].outputs == {"show a": "out:show a", "show b": "out:show b"}


async def test_transient_errors_are_retried() -> None:
    t = FakeTransport({"d0": [ConnectError("refused"), CollectTimeout("slow")]})
    [r] = await collect(devs(1), lambda d: ["x"], t, policy=FAST)
    assert r.ok and r.attempts == 3 and r.error is None


async def test_retries_are_bounded() -> None:
    t = FakeTransport({"d0": [ConnectError("refused")] * 10})
    [r] = await collect(devs(1), lambda d: ["x"], t, policy=FAST)
    assert not r.ok and r.attempts == 3 and r.error_kind == "connect"


@pytest.mark.parametrize("exc", [AuthError("bad password"), CommandError("% Invalid input")])
async def test_permanent_errors_are_not_retried(exc: Exception) -> None:
    t = FakeTransport({"d0": [exc]})
    [r] = await collect(devs(1), lambda d: ["x"], t, policy=FAST)
    assert not r.ok and r.attempts == 1 and t.opens["d0"] == 1


async def test_unexpected_exception_is_contained() -> None:
    t = FakeTransport({"d1": [RuntimeError("bug")]})
    res = await collect(devs(3), lambda d: ["x"], t, policy=FAST)
    assert [r.ok for r in res] == [True, False, True]
    assert res[1].error_kind == "internal" and "RuntimeError" in (res[1].error or "")


async def test_invalid_concurrency() -> None:
    with pytest.raises(ValueError):
        await collect(devs(1), lambda d: ["x"], FakeTransport(), concurrency=0)


def test_backoff_is_exponential_and_capped() -> None:
    p = RetryPolicy(backoff_s=1, max_backoff_s=5, jitter=False)
    assert [p.delay(n) for n in (1, 2, 3, 4)] == [1, 2, 4, 5]
    pj = RetryPolicy(backoff_s=1, jitter=True)
    assert all(0.5 <= pj.delay(1) <= 1 for _ in range(50))


async def test_fixture_transport() -> None:
    d = Device(name="core-sw1", host="x", platform="arista_eos")
    [r] = await collect(
        [d], lambda d: ["show version", "show nope"], FixtureTransport(FIXTURES), policy=FAST
    )
    assert not r.ok and r.error_kind == "command"
    [r] = await collect([d], lambda d: ["show version"], FixtureTransport(FIXTURES), policy=FAST)
    assert r.ok and "4.31.2F" in r.outputs["show version"]
    missing = Device(name="ghost", host="x", platform="cisco_ios")
    [r] = await collect([missing], lambda d: ["x"], FixtureTransport(FIXTURES), policy=FAST)
    assert r.error_kind == "connect" and r.attempts == 3
