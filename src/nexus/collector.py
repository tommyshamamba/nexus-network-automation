"""Concurrent command collection with bounded parallelism, retries and timeouts."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from nexus.inventory import Device
from nexus.transport import CollectError, Transport

log = logging.getLogger(__name__)


@dataclass
class DeviceResult:
    device: str
    ok: bool
    outputs: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    error_kind: str | None = None
    attempts: int = 0
    elapsed_s: float = 0.0

    def to_dict(self, include_outputs: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if not include_outputs:
            d["outputs"] = sorted(self.outputs)
        d["elapsed_s"] = round(self.elapsed_s, 3)
        return d


@dataclass(frozen=True)
class RetryPolicy:
    retries: int = 2  # extra attempts after the first
    backoff_s: float = 0.5  # base delay; doubles each attempt
    max_backoff_s: float = 8.0
    jitter: bool = True

    def delay(self, attempt: int) -> float:
        d: float = min(self.max_backoff_s, self.backoff_s * (2 ** (attempt - 1)))
        return random.uniform(d / 2, d) if self.jitter else d


async def _collect_one(
    device: Device,
    commands: Sequence[str],
    transport: Transport,
    sem: asyncio.Semaphore,
    policy: RetryPolicy,
) -> DeviceResult:
    res = DeviceResult(device=device.name, ok=False)
    start = time.monotonic()
    async with sem:
        while True:
            res.attempts += 1
            try:
                async with transport.session(device) as sess:
                    outputs = {}
                    for cmd in commands:
                        outputs[cmd] = await sess.run(cmd)
                res.ok, res.outputs, res.error, res.error_kind = True, outputs, None, None
                break
            except CollectError as e:
                res.error, res.error_kind = str(e), e.kind
                if not e.retryable or res.attempts > policy.retries:
                    log.warning(
                        "%s: giving up after %d attempt(s): %s", device.name, res.attempts, e
                    )
                    break
                delay = policy.delay(res.attempts)
                log.info(
                    "%s: attempt %d failed (%s), retrying in %.2fs",
                    device.name,
                    res.attempts,
                    e.kind,
                    delay,
                )
                await asyncio.sleep(delay)
            except Exception as e:  # never let one device take down the run
                log.exception("%s: unexpected error", device.name)
                res.error, res.error_kind = f"{type(e).__name__}: {e}", "internal"
                break
    res.elapsed_s = time.monotonic() - start
    return res


async def collect(
    devices: Sequence[Device],
    commands_for: Callable[[Device], Sequence[str]],
    transport: Transport,
    *,
    concurrency: int = 10,
    policy: RetryPolicy | None = None,
) -> list[DeviceResult]:
    """Run ``commands_for(device)`` on every device, at most ``concurrency``
    sessions at once. Never raises for per-device failures; inspect
    ``DeviceResult.ok``. Results keep inventory order."""
    if concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    policy = policy or RetryPolicy()
    sem = asyncio.Semaphore(concurrency)
    tasks = [_collect_one(d, list(commands_for(d)), transport, sem, policy) for d in devices]
    return list(await asyncio.gather(*tasks))
