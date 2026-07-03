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
from strobes_shell_agent.executor import (
    execute_shell_command,
    execute_code,
    read_file,
    write_file,
    list_files,
    upload_file,
    download_file,
    get_env_info,
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
                "agent_version": "0.1.0",
                "pack": pack.status(),
            },
        }))

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

        elif command == "file_upload":
            return upload_file(
                path=params.get("path", ""),
                content_b64=params.get("content_b64", ""),
            )

        elif command == "file_download":
            return download_file(params.get("path", ""))

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
