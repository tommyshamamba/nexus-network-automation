"""Fake SSH network devices for tests and the demo.

Each device is an asyncssh server on its own TCP port that answers exec
requests with recorded output from ``<fixtures>/<device>/<command_slug>.txt``.
Files are re-read on every command, so a demo can change a "device" config
between two backups. Unknown commands behave like IOS: ``% Invalid input``
on stderr and a non-zero exit status.

This is a test double: it speaks real SSH (key exchange, password auth,
exec channels) so the client code path is the same one used against real
equipment, but it is not a device emulator.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh

from nexus.transport import command_slug

log = logging.getLogger(__name__)


@dataclass
class MockDevice:
    name: str
    fixture_dir: Path
    delay_s: float = 0.0  # sleep before answering each command (timeout tests)
    port: int = 0


class _AuthServer(asyncssh.SSHServer):
    def __init__(self, password: str):
        self._password = password

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return hmac.compare_digest(password.encode(), self._password.encode())


def _handler(dev: MockDevice) -> Any:
    async def handle(process: Any) -> None:
        cmd = (process.command or "").strip()
        try:
            if dev.delay_s:
                await asyncio.sleep(dev.delay_s)
            if not cmd:
                process.stdout.write(f"{dev.name}: interactive shells are not emulated\n")
                process.exit(1)
                return
            path = dev.fixture_dir / f"{command_slug(cmd)}.txt"
            if path.is_file():
                process.stdout.write(path.read_text(encoding="utf-8"))
                process.exit(0)
            else:
                process.stderr.write(f"% Invalid input detected: '{cmd}'\n")
                process.exit(1)
        except (OSError, asyncssh.Error):  # client went away
            process.close()

    return handle


class MockLab:
    """A set of fake devices sharing one password and a throwaway host key."""

    def __init__(self, devices: list[MockDevice], password: str, host: str = "127.0.0.1"):
        self.devices = devices
        self.password = password
        self.host = host
        self._servers: list[Any] = []
        self._key = asyncssh.generate_private_key("ssh-ed25519")

    async def start(self) -> dict[str, int]:
        for dev in self.devices:
            server = await asyncssh.create_server(
                lambda: _AuthServer(self.password),
                self.host,
                dev.port,
                server_host_keys=[self._key],
                process_factory=_handler(dev),
                encoding="utf-8",
            )
            dev.port = server.sockets[0].getsockname()[1]
            self._servers.append(server)
            log.info("mock device %s listening on %s:%d", dev.name, self.host, dev.port)
        return {d.name: d.port for d in self.devices}

    async def stop(self) -> None:
        for s in self._servers:
            s.close()
            await s.wait_closed()
        self._servers.clear()

    async def __aenter__(self) -> MockLab:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()


def devices_from_fixtures(root: str | Path, base_port: int = 0) -> list[MockDevice]:
    """One device per sub-directory, ports assigned in sorted-name order."""
    dirs = sorted(p for p in Path(root).iterdir() if p.is_dir())
    return [
        MockDevice(p.name, p, port=(base_port + i) if base_port else 0) for i, p in enumerate(dirs)
    ]
