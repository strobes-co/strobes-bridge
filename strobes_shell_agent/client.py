"""WebSocket client that connects to the Strobes platform."""

import asyncio
import json
import logging
import platform
import os
import ssl
import time
from typing import Optional

import websockets
from websockets.exceptions import ConnectionClosed

from strobes_shell_agent import pack
from strobes_shell_agent import selfupdate
from strobes_shell_agent import sessions
from strobes_shell_agent import responder
from strobes_shell_agent import __version__ as AGENT_VERSION
from strobes_shell_agent.executor import (
    execute_shell_command,
    execute_code,
    read_file,
    write_file,
    list_files,
    file_pull,
    file_push,
    get_env_info,
    bg_start,
    bg_poll,
    bg_cancel,
)
from strobes_shell_agent.pty_handler import (
    handle_pty_open,
    handle_pty_input,
    handle_pty_resize,
    handle_pty_close,
    close_all as close_all_pty,
)

logger = logging.getLogger(__name__)

# Reconnection settings
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 60.0
BACKOFF_MULTIPLIER = 2.0
PING_INTERVAL = 30  # seconds


class ShellBridgeClient:
    """WebSocket client that connects to the Strobes shell bridge."""

    def __init__(
        self,
        url: str,
        api_key: str,
        org_id: str,
        bridge_id: str,
        name: str = "",
        cwd: Optional[str] = None,
        ssl_verify: bool = True,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.org_id = org_id
        self.bridge_id = bridge_id
        self.name = name or platform.node()
        self.cwd = cwd or os.getcwd()
        self.ssl_verify = ssl_verify
        self._ws = None
        self._running = False
        self._stop_event = asyncio.Event()

    @property
    def ws_url(self) -> str:
        """Build the WebSocket connection URL."""
        base = self.url
        # Convert http(s) to ws(s)
        if base.startswith("https://"):
            base = "wss://" + base[8:]
        elif base.startswith("http://"):
            base = "ws://" + base[7:]
        elif not base.startswith(("ws://", "wss://")):
            base = "wss://" + base

        return (
            f"{base}/ws/{self.org_id}/shell-bridge/"
            f"?api_key={self.api_key}&bridge_id={self.bridge_id}"
        )

    async def connect_forever(self):
        """Connect with automatic reconnection on disconnect."""
        self._running = True
        backoff = INITIAL_BACKOFF

        # Provision the sandbox pack once at startup (no-op unless STROBES_PACK_URL is
        # set or a pack is already installed). Runs in a thread so a large download
        # never blocks the event loop. Never raises.
        try:
            p = await asyncio.to_thread(pack.ensure_pack)
            if p:
                logger.info("Sandbox pack ready: %s", pack.status())
            else:
                logger.info("No sandbox pack; using host tools.")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Sandbox pack provisioning skipped: {e}")

        while self._running:
            try:
                logger.info(f"Connecting to {self.url}...")
                connect_kwargs = {
                    "ping_interval": None,  # We handle pings ourselves
                    "max_size": 10_485_760,  # 10MB max message
                    "close_timeout": 5,
                }
                if self.ws_url.startswith("wss://") and not self.ssl_verify:
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    connect_kwargs["ssl"] = ssl_context

                async with websockets.connect(self.ws_url, **connect_kwargs) as ws:
                    self._ws = ws
                    backoff = INITIAL_BACKOFF  # Reset on successful connect
                    logger.info(f"Connected! Bridge ID: {self.bridge_id}")

                    # Send identify
                    await self._send_identify()

                    # Run ping loop + message handler. Whichever finishes
                    # first (typically the message handler when the socket
                    # closes) triggers cancellation of the other, so we
                    # never wait out the ping interval before reconnecting.
                    ping_task = asyncio.create_task(self._ping_loop())
                    handler_task = asyncio.create_task(self._message_handler())
                    done, pending = await asyncio.wait(
                        {ping_task, handler_task},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in pending:
                        t.cancel()
                    for t in pending:
                        try:
                            await t
                        except (asyncio.CancelledError, Exception):
                            pass
                    # Surface any exception from the completed task
                    for t in done:
                        exc = t.exception()
                        if exc:
                            raise exc
            except ConnectionClosed as e:
                logger.warning(f"Connection closed: {e}")
                await close_all_pty()
            except ConnectionRefusedError:
                logger.error("Connection refused. Check URL and API key.")
            except Exception as e:
                logger.error(f"Connection error: {e}")
            finally:
                self._ws = None

            if not self._running:
                break

            logger.info(f"Reconnecting in {backoff:.0f}s...")
            # Cancellable sleep: wakes up immediately if stop() is called.
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                # stop_event was set during backoff: exit the loop.
                break
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * BACKOFF_MULTIPLIER, MAX_BACKOFF)

    async def _send_identify(self):
        """Send identify message with daemon metadata."""
        await self._ws.send(json.dumps({
            "type": "identify",
            "data": {
                "shell_name": self.name,
                "os": platform.system(),
                "os_version": platform.version(),
                "arch": platform.machine(),
                "hostname": platform.node(),
                "cwd": self.cwd,
                "python": platform.python_version(),
                "agent_version": AGENT_VERSION,
                "pack": pack.status(),
                # Capabilities the platform can rely on for this daemon.
                "features": ["bg_exec"],
            },
        }))

    async def _apply_updates(self, data: dict):
        """Apply server-requested updates: sandbox pack in place, then the agent
        binary (which re-execs, so it goes last). Everything runs in a worker thread
        (downloads + extraction are blocking) and is fully guarded — a failed or
        absent update must never disturb the live connection.

        Recognised fields (all optional): ``required_pack_version`` + ``pack_url``,
        ``required_agent_version`` + ``agent_url``. URLs default to the operator-set
        ``STROBES_PACK_URL`` / ``STROBES_AGENT_URL`` when omitted."""
        try:
            pack_version = data.get("required_pack_version") or data.get("pack_version")
            pack_url = data.get("pack_url")
            if pack.needs_update(pack_version):
                logger.info("pack update required: have %s, want %s",
                            pack.installed_version(), pack_version)
                await asyncio.to_thread(pack.update_pack, pack_url, pack_version)

            agent_version = data.get("required_agent_version") or data.get("agent_version")
            agent_url = data.get("agent_url")
            if agent_version and agent_version != AGENT_VERSION:
                # apply_update re-execs / exits on success and never returns.
                await asyncio.to_thread(selfupdate.maybe_update, agent_version, agent_url)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"update check skipped: {e}")

    async def _ping_loop(self):
        """Send periodic pings to keep connection alive."""
        while self._running and self._ws:
            try:
                await self._ws.send(json.dumps({
                    "type": "ping",
                    "timestamp": time.time(),
                }))
                await asyncio.sleep(PING_INTERVAL)
            except ConnectionClosed:
                break
            except Exception as e:
                logger.debug(f"Ping error: {e}")
                break

    async def _message_handler(self):
        """Handle incoming messages from the platform."""
        try:
            async for message in self._ws:
                try:
                    msg = json.loads(message)
                except json.JSONDecodeError:
                    logger.warning("Received invalid JSON")
                    continue

                msg_type = msg.get("type")

                if msg_type == "command":
                    # Execute command in background to not block other messages
                    asyncio.create_task(self._handle_command(msg))

                elif msg_type == "pty_open":
                    # Open interactive PTY session
                    asyncio.create_task(self._handle_pty_open(msg))

                elif msg_type == "pty_input":
                    # Write input to PTY (fire-and-forget, no response needed)
                    session_id = msg.get("session_id", "")
                    await handle_pty_input(session_id, msg.get("data", ""))

                elif msg_type == "pty_resize":
                    session_id = msg.get("session_id", "")
                    handle_pty_resize(session_id, msg.get("cols", 80), msg.get("rows", 24))

                elif msg_type == "pty_close":
                    session_id = msg.get("session_id", "")
                    await handle_pty_close(session_id)

                elif msg_type == "identify_ack":
                    data = msg.get("data", {})
                    logger.info(
                        f"Identified as bridge_id={data.get('bridge_id')}, "
                        f"connection_id={data.get('connection_id')}"
                    )
                    # The platform tells each bridge, on connect, what it should be
                    # running. Apply any required update NOW ("when required to the
                    # bridge") — pack first (cheap, in-place), then the binary (which
                    # re-execs, so it must run last). Off the event loop; guarded.
                    asyncio.create_task(self._apply_updates(data))

                elif msg_type == "update":
                    # Explicit server push (out of band from identify) — same handler.
                    asyncio.create_task(self._apply_updates(msg.get("data", msg)))

                elif msg_type == "pong":
                    pass  # Keepalive acknowledged

                else:
                    logger.debug(f"Unknown message type: {msg_type}")
        except ConnectionClosed as e:
            logger.info(f"WebSocket closed: code={e.code} reason={e.reason!r}")

    async def _handle_pty_open(self, msg: dict):
        """Handle PTY open request from the platform."""
        session_id = msg.get("session_id", "")
        cols = msg.get("cols", 80)
        rows = msg.get("rows", 24)
        request_id = msg.get("request_id")

        logger.info(f"Opening PTY session: {session_id} ({cols}x{rows})")
        result = await handle_pty_open(self._ws, session_id, cols, rows)

        # Send response if request_id provided
        if request_id:
            try:
                await self._ws.send(json.dumps({
                    "type": "response",
                    "request_id": request_id,
                    "data": result,
                }))
            except Exception:
                pass

    async def _handle_command(self, msg: dict):
        """Handle a command from the platform."""
        request_id = msg.get("request_id")
        command = msg.get("command")
        params = msg.get("params", {})

        logger.info(f"Executing command: {command} (request_id={request_id}) params={params}")
        t0 = time.monotonic()

        try:
            result = await self._dispatch_command(command, params)
        except Exception as e:
            logger.error(f"Command {command} failed: {e}", exc_info=True)
            result = {"success": False, "error": str(e)}

        dt = int((time.monotonic() - t0) * 1000)
        logger.info(
            f"Completed {command} (request_id={request_id}) success={result.get('success')} "
            f"exit={result.get('exit_code')} in {dt}ms "
            f"stdout={len(result.get('stdout','') or '')}b stderr={len(result.get('stderr','') or '')}b"
        )

        # Send response
        try:
            payload = json.dumps({
                "type": "response",
                "request_id": request_id,
                "data": result,
            })
            await self._ws.send(payload)
            logger.info(f"Response sent for {request_id} ({len(payload)}b)")
        except ConnectionClosed:
            logger.warning(f"Cannot send response for {request_id}: connection closed")
        except Exception as e:
            logger.error(f"Failed to send response for {request_id}: {e}", exc_info=True)

    async def _dispatch_command(self, command: str, params: dict) -> dict:
        """Dispatch a command to the appropriate executor."""
        if command == "shell_execute":
            return await execute_shell_command(
                command=params.get("command", ""),
                timeout=params.get("timeout", 60),
                cwd=params.get("cwd", self.cwd),
            )

        elif command == "shell_execute_code":
            return await execute_code(
                language=params.get("language", "python"),
                code=params.get("code", ""),
                timeout=params.get("timeout", 60),
                cwd=params.get("cwd", self.cwd),
            )

        # --- Background jobs (detached; platform polls) ---
        # Run in a worker thread: bg_cancel can block on taskkill, and none of
        # these should stall the daemon's event loop.
        elif command == "shell_bg_start":
            return await asyncio.to_thread(
                bg_start,
                params.get("task_id", ""),
                params.get("command", ""),
                params.get("cwd", self.cwd),
                params.get("timeout", 0),
            )

        elif command == "shell_bg_poll":
            return await asyncio.to_thread(
                bg_poll,
                params.get("task_id", ""),
                params.get("offset", 0),
            )

        elif command == "shell_bg_cancel":
            return await asyncio.to_thread(
                bg_cancel,
                params.get("task_id", ""),
            )

        # --- Persistent, reusable shell sessions (retainable footholds) ---
        # A session keeps a live shell (cwd/env/sudo/ssh preserved) so agents can
        # create one and reuse it across commands. Run in worker threads: PTY I/O
        # + waits must not stall the daemon event loop.
        elif command == "session_create":
            return await asyncio.to_thread(
                sessions.session_create,
                params.get("cwd") or self.cwd,
                params.get("label", ""),
                params.get("shell"),
            )

        elif command == "session_list":
            return await asyncio.to_thread(sessions.session_list)

        elif command == "session_exec":
            return await asyncio.to_thread(
                sessions.session_exec,
                params.get("session_id", ""),
                params.get("command", ""),
                params.get("timeout", 60),
            )

        elif command == "session_delete":
            return await asyncio.to_thread(
                sessions.session_delete,
                params.get("session_id", ""),
            )

        # --- Responder: background LLMNR/NBT-NS/mDNS poisoning + hash capture ---
        elif command == "responder_start":
            return await asyncio.to_thread(
                responder.responder_start,
                params.get("interface"),
                params.get("analyze", True),
                params.get("wpad", False),
            )

        elif command == "responder_status":
            return await asyncio.to_thread(responder.responder_status)

        elif command == "responder_captures":
            return await asyncio.to_thread(responder.responder_captures)

        elif command == "responder_stop":
            return await asyncio.to_thread(responder.responder_stop)

        elif command == "file_read":
            return read_file(params.get("path", ""))

        elif command == "file_write":
            return write_file(
                path=params.get("path", ""),
                content=params.get("content", ""),
                mode=params.get("mode", "overwrite"),
            )

        elif command == "file_list":
            return list_files(
                directory=params.get("directory", "."),
                pattern=params.get("pattern"),
                recursive=params.get("recursive", False),
            )

        elif command == "file_pull":
            # workspace -> machine, via one-time presigned S3 GET
            return await asyncio.to_thread(
                file_pull,
                params.get("path", ""),
                params.get("url", ""),
                params.get("sha256"),
                params.get("timeout", 300),
            )

        elif command == "file_push":
            # machine -> workspace, via one-time presigned S3 PUT
            return await asyncio.to_thread(
                file_push,
                params.get("path", ""),
                params.get("url", ""),
                params.get("content_type", "application/octet-stream"),
                params.get("timeout", 300),
            )

        elif command == "env_info":
            return get_env_info()

        else:
            return {"success": False, "error": f"Unknown command: {command}"}

    def stop(self):
        """Signal the client to stop reconnecting."""
        self._running = False
        self._stop_event.set()
        if self._ws:
            asyncio.create_task(self._ws.close())
