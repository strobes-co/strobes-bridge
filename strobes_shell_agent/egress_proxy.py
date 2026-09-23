"""The egress proxy — where the bridge's network scope is actually enforced.

Commands run inside an OS sandbox (see :mod:`procsandbox`) whose only permitted
destination is this proxy on loopback. Everything else is refused by the kernel,
so a tool that ignores proxy settings does not slip past — it simply gets no
network at all. That is the difference between this and the usual
``HTTP_PROXY`` arrangement, which a program is free to disregard.

Speaking SOCKS5 (with remote name resolution) buys two things an L3 filter
cannot offer:

* **Exact hostname rules.** The client sends the *name*, so ``example.com`` is
  matched as a name. An IP allowlist derived from a name over-grants badly on
  shared infrastructure — one ``/32`` for a CDN-hosted target authorises every
  other site on that address.
* **No rebinding window.** The proxy resolves, decides, and then connects to
  the very address it just validated (:attr:`Decision.addresses`), so a record
  that changes between check and connect buys nothing.

HTTP proxy verbs are accepted on the same port for tools that only speak
``HTTP(S)_PROXY``; the protocol is detected from the first byte.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import struct
import time
from typing import Callable, Optional

from strobes_shell_agent.netpolicy import Checker, NetworkPolicy

logger = logging.getLogger(__name__)

# SOCKS5 (RFC 1928)
_SOCKS5 = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 0x01, 0x03, 0x04
_REP_OK = 0x00
_REP_GENERAL = 0x01
_REP_NOT_ALLOWED = 0x02  # "connection not allowed by ruleset" — our denial
_REP_HOST_UNREACH = 0x04
_REP_CMD_UNSUPPORTED = 0x07

# Windows filters egress by port, and a filter cannot be written against a port
# the proxy has not bound yet — so the proxy claims one from a fixed range
# rather than an ephemeral port. The range matches the one srt uses.
DEFAULT_PORT_RANGE = (60080, 60089)

_IO_CHUNK = 64 * 1024
_CONNECT_TIMEOUT_S = 15
_HANDSHAKE_TIMEOUT_S = 30


class Denial:
    """One refused connection, kept so the caller can explain the failure."""

    __slots__ = ("host", "port", "reason", "at")

    def __init__(self, host: str, port: int, reason: str):
        self.host, self.port, self.reason = host, port, reason
        self.at = time.time()

    def as_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "reason": self.reason}

    def __str__(self) -> str:
        return f"{self.host}:{self.port} — {self.reason}"


class EgressProxy:
    """A loopback SOCKS5 / HTTP proxy that enforces a :class:`NetworkPolicy`.

    One instance is shared by every sandboxed command. The policy is consulted
    per connection rather than captured at start-up, so a scope pushed from the
    platform takes effect on the next connection without a restart.
    """

    def __init__(self, policy: NetworkPolicy, host: str = "127.0.0.1", port: int = 0,
                 on_denial: Optional[Callable[[Denial], None]] = None,
                 max_denials: int = 200, socket_path: Optional[str] = None,
                 port_range: Optional[tuple] = None):
        self._checker = Checker(policy)
        self.host = host
        self._want_port = port
        self._port_range = port_range
        self.port: Optional[int] = None
        self.socket_path = socket_path
        self._server: Optional[asyncio.AbstractServer] = None
        self._unix_server: Optional[asyncio.AbstractServer] = None
        self._on_denial = on_denial
        self._max_denials = max_denials
        self.denials: list[Denial] = []
        self.allowed_count = 0
        self.denied_count = 0

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> int:
        """Bind and begin serving. Returns the TCP port actually bound.

        When ``socket_path`` is set a UNIX listener is added alongside. A
        network namespace (the Linux sandbox) has no route to the host's
        loopback, but a *filesystem* UNIX socket crosses that boundary, so this
        is how the sandboxed relay reaches the proxy there.
        """
        self._server = await self._bind()
        self.port = self._server.sockets[0].getsockname()[1]

        if self.socket_path:
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass
            self._unix_server = await asyncio.start_unix_server(
                self._handle, self.socket_path
            )
            os.chmod(self.socket_path, 0o600)

        logger.info("Egress proxy listening on %s:%s%s", self.host, self.port,
                    f" (+unix {self.socket_path})" if self.socket_path else "")
        return self.port

    async def _bind(self):
        """Bind the TCP listener, honouring a fixed port range when given.

        Several bridges (or a stale process) may be competing for the range, so
        each port is tried in turn and the first free one wins.
        """
        if not self._port_range:
            return await asyncio.start_server(self._handle, self.host, self._want_port)

        lo, hi = self._port_range
        last: Optional[OSError] = None
        for candidate in range(lo, hi + 1):
            try:
                return await asyncio.start_server(self._handle, self.host, candidate)
            except OSError as e:
                last = e
        raise RuntimeError(
            f"no free port in {lo}-{hi} for the egress proxy; "
            f"the egress filter is written against that range ({last})"
        )

    async def stop(self) -> None:
        for server in (self._server, self._unix_server):
            if server is not None:
                server.close()
                try:
                    await server.wait_closed()
                except Exception:
                    pass
        self._server = None
        self._unix_server = None
        if self.socket_path:
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

    def set_policy(self, policy: NetworkPolicy) -> None:
        """Swap the policy; the next connection is judged by the new one."""
        self._checker = Checker(policy)

    @property
    def policy(self) -> NetworkPolicy:
        return self._checker.policy

    def drain_denials(self) -> list:
        """Take and clear the recorded denials (used to explain a failed run)."""
        out = [d.as_dict() for d in self.denials]
        self.denials.clear()
        return out

    # -- decisions ----------------------------------------------------------

    def _decide(self, host: str, port: int):
        decision = self._checker.check(host, port)
        if decision.allowed:
            self.allowed_count += 1
        else:
            self.denied_count += 1
            denial = Denial(host, port, decision.reason)
            # Bounded: a scanner hitting an out-of-scope range would otherwise
            # grow this without limit.
            if len(self.denials) < self._max_denials:
                self.denials.append(denial)
            logger.info("egress denied: %s", denial)
            if self._on_denial is not None:
                try:
                    self._on_denial(denial)
                except Exception:
                    pass
        return decision

    # -- connection handling ------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await asyncio.wait_for(self._dispatch(reader, writer), _HANDSHAKE_TIMEOUT_S)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:
            logger.debug("proxy connection error: %s", e)
        finally:
            _close(writer)

    async def _dispatch(self, reader, writer):
        first = await reader.read(1)
        if not first:
            return
        if first[0] == _SOCKS5:
            await self._socks5(reader, writer)
        else:
            await self._http(first, reader, writer)

    # -- SOCKS5 -------------------------------------------------------------

    async def _socks5(self, reader, writer):
        # Greeting: we already consumed VER.
        nmethods = (await reader.readexactly(1))[0]
        await reader.readexactly(nmethods)
        writer.write(bytes([_SOCKS5, 0x00]))  # no authentication
        await writer.drain()

        ver, cmd, _rsv, atyp = await reader.readexactly(4)
        if ver != _SOCKS5:
            return
        if cmd != _CMD_CONNECT:
            # BIND/UDP-ASSOCIATE would make the sandbox reachable; refuse both.
            await self._socks5_reply(writer, _REP_CMD_UNSUPPORTED)
            return

        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == _ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        elif atyp == _ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("idna", errors="replace")
        else:
            await self._socks5_reply(writer, _REP_GENERAL)
            return
        port = struct.unpack("!H", await reader.readexactly(2))[0]

        decision = self._decide(host, port)
        if not decision.allowed:
            await self._socks5_reply(writer, _REP_NOT_ALLOWED)
            return

        upstream = await self._connect(decision.addresses, host, port)
        if upstream is None:
            await self._socks5_reply(writer, _REP_HOST_UNREACH)
            return

        up_reader, up_writer = upstream
        await self._socks5_reply(writer, _REP_OK)
        await _pipe(reader, writer, up_reader, up_writer)

    async def _socks5_reply(self, writer, rep: int):
        # BND.ADDR/BND.PORT are unused by clients for CONNECT; zeros are fine.
        writer.write(bytes([_SOCKS5, rep, 0x00, _ATYP_IPV4]) + b"\x00" * 4 + b"\x00\x00")
        try:
            await writer.drain()
        except ConnectionError:
            pass

    # -- HTTP proxy ---------------------------------------------------------

    async def _http(self, first: bytes, reader, writer):
        head = first + await reader.readuntil(b"\r\n\r\n")
        line, _, rest = head.partition(b"\r\n")
        try:
            method, target, _version = line.decode("latin-1").split(" ", 2)
        except ValueError:
            return

        if method.upper() == "CONNECT":
            host, port = _split_hostport(target, 443)
            decision = self._decide(host, port)
            if not decision.allowed:
                await _http_deny(writer, decision.reason)
                return
            upstream = await self._connect(decision.addresses, host, port)
            if upstream is None:
                await _http_error(writer, 502, "Bad Gateway", "upstream unreachable")
                return
            up_reader, up_writer = upstream
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await _pipe(reader, writer, up_reader, up_writer)
            return

        # Absolute-URI form: GET http://host/path HTTP/1.1
        if "://" not in target:
            await _http_error(writer, 400, "Bad Request", "proxy requests must use an absolute URI")
            return
        scheme, _, remainder = target.partition("://")
        authority = remainder.split("/", 1)[0]
        host, port = _split_hostport(authority, 443 if scheme == "https" else 80)

        decision = self._decide(host, port)
        if not decision.allowed:
            await _http_deny(writer, decision.reason)
            return
        upstream = await self._connect(decision.addresses, host, port)
        if upstream is None:
            await _http_error(writer, 502, "Bad Gateway", "upstream unreachable")
            return
        up_reader, up_writer = upstream
        # Replay the request as-is; origin servers accept an absolute URI.
        up_writer.write(head)
        await up_writer.drain()
        await _pipe(reader, writer, up_reader, up_writer)

    # -- upstream -----------------------------------------------------------

    async def _connect(self, addresses: tuple, host: str, port: int):
        """Connect to one of the addresses the decision validated.

        Deliberately does not re-resolve ``host``: the policy was decided
        against these addresses, so anything else would be unchecked.
        """
        candidates = list(addresses) or ([host] if _is_ip(host) else [])
        for addr in candidates:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(addr, port), _CONNECT_TIMEOUT_S
                )
            except (OSError, asyncio.TimeoutError):
                continue
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split_hostport(authority: str, default_port: int) -> tuple:
    if authority.startswith("["):  # [v6]:port
        host, _, tail = authority[1:].partition("]")
        port = int(tail[1:]) if tail.startswith(":") and tail[1:].isdigit() else default_port
        return host, port
    host, sep, tail = authority.rpartition(":")
    if sep and tail.isdigit():
        return host, int(tail)
    return authority, default_port


async def _http_deny(writer, reason: str):
    # 403 with the reason in the body, so the refusal is legible in tool output
    # instead of looking like a network failure.
    await _http_error(writer, 403, "Forbidden", f"egress denied: {reason}")


async def _http_error(writer, code: int, phrase: str, body: str):
    payload = body.encode()
    writer.write(
        f"HTTP/1.1 {code} {phrase}\r\nContent-Length: {len(payload)}\r\n"
        f"Content-Type: text/plain\r\nConnection: close\r\n\r\n".encode() + payload
    )
    try:
        await writer.drain()
    except ConnectionError:
        pass


def _close(writer):
    try:
        writer.close()
    except Exception:
        pass


async def _pipe(c_reader, c_writer, u_reader, u_writer):
    """Shuttle bytes both ways until either side closes."""
    async def copy(src, dst):
        try:
            while True:
                data = await src.read(_IO_CHUNK)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(
        copy(c_reader, u_writer),
        copy(u_reader, c_writer),
        return_exceptions=True,
    )
