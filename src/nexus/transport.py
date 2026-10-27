"""Transports: how commands reach a device.

``SSHTransport`` uses asyncssh (exec channel, one command per channel).
``FixtureTransport`` replays recorded command output from disk, which is what
the unit tests and offline compliance runs use.

Errors are normalised into a small hierarchy so the collector can decide
what is worth retrying: a refused connection or a timeout may be transient,
a rejected password or an unknown host key is not.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Protocol

import asyncssh

from nexus.inventory import Device


class CollectError(Exception):
    kind = "error"
    retryable = False


class AuthError(CollectError):
    kind = "auth"


class HostKeyError(CollectError):
    kind = "host_key"


class ConnectError(CollectError):
    kind = "connect"
    retryable = True


class CollectTimeout(CollectError):
    kind = "timeout"
    retryable = True


class CommandError(CollectError):
    kind = "command"


class Session(Protocol):
    async def run(self, command: str) -> str: ...


class Transport(Protocol):
    def session(self, device: Device) -> AbstractAsyncContextManager[Session]: ...


def command_slug(command: str) -> str:
    """File-system safe name for a command: ``show run | i x`` -> ``show_run_i_x``."""
    return re.sub(r"[^A-Za-z0-9-]+", "_", command).strip("_")


# --------------------------------------------------------------------------- SSH


class _SSHSession:
    def __init__(self, conn: Any, device: Device):
        self._conn = conn
        self._device = device

    async def run(self, command: str) -> str:
        try:
            res = await asyncio.wait_for(
                self._conn.run(command, check=False), timeout=self._device.timeout
            )
        except TimeoutError:
            raise CollectTimeout(
                f"command '{command}' timed out after {self._device.timeout:g}s"
            ) from None
        except (asyncssh.Error, OSError) as e:
            raise ConnectError(f"connection lost during '{command}': {e}") from e
        if res.exit_status not in (0, None):
            err = (res.stderr or "").strip() if isinstance(res.stderr, str) else ""
            raise CommandError(f"'{command}' exited with status {res.exit_status}: {err}")
        out = res.stdout
        return out if isinstance(out, str) else out.decode("utf-8", "replace")


class SSHTransport:
    """asyncssh-based transport. Host keys are verified unless the inventory
    explicitly sets ``strict_host_key: false`` (lab use only)."""

    @asynccontextmanager
    async def session(self, device: Device):  # type: ignore[no-untyped-def]
        known_hosts: Any = () if device.strict_host_key else None
        if device.strict_host_key and device.known_hosts:
            known_hosts = device.known_hosts
        opts: dict[str, Any] = {
            "username": device.username,
            "known_hosts": known_hosts,
            "connect_timeout": device.timeout,
            "login_timeout": device.timeout,
        }
        pw = device.password()
        if pw is not None:
            opts["password"] = pw
        if device.key_file:
            opts["client_keys"] = [device.key_file]
        elif pw is not None:
            opts["client_keys"] = None  # don't offer agent/default keys first
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(device.host, device.port, **opts),
                timeout=device.timeout,
            )
        except TimeoutError:
            raise CollectTimeout(f"connect timed out after {device.timeout:g}s") from None
        except asyncssh.PermissionDenied as e:
            raise AuthError(f"authentication failed: {e.reason}") from e
        except asyncssh.HostKeyNotVerifiable as e:
            raise HostKeyError(f"host key not verifiable: {e.reason}") from e
        except asyncssh.Error as e:
            raise ConnectError(f"ssh error: {e}") from e
        except OSError as e:
            raise ConnectError(f"cannot connect to {device.host}:{device.port}: {e}") from e
        try:
            yield _SSHSession(conn, device)
        finally:
            conn.close()
            with suppress(TimeoutError, OSError, asyncssh.Error):
                await asyncio.wait_for(conn.wait_closed(), timeout=2)


# --------------------------------------------------------------------- fixtures


class _FixtureSession:
    def __init__(self, root: Path):
        self._root = root

    async def run(self, command: str) -> str:
        path = self._root / f"{command_slug(command)}.txt"
        if not path.is_file():
            raise CommandError(f"no recorded output for '{command}' ({path})")
        return path.read_text(encoding="utf-8")


class FixtureTransport:
    """Replays ``<root>/<device-name>/<command_slug>.txt``."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    @asynccontextmanager
    async def session(self, device: Device):  # type: ignore[no-untyped-def]
        d = self.root / device.name
        if not d.is_dir():
            raise ConnectError(f"no fixtures for device '{device.name}' in {self.root}")
        yield _FixtureSession(d)
