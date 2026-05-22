"""Tests for ShellBridgeClient — focused on reconnect + URL building."""

import asyncio
import json
import time

import pytest
import websockets

from strobes_shell_agent.client import ShellBridgeClient


def test_ws_url_https():
    c = ShellBridgeClient(
        url="https://example.com",
        api_key="K", org_id="O", bridge_id="B", name="x",
    )
    assert c.ws_url.startswith("wss://example.com/ws/O/shell-bridge/")
    assert "api_key=K" in c.ws_url
    assert "bridge_id=B" in c.ws_url


def test_ws_url_http():
    c = ShellBridgeClient(
        url="http://localhost:8000",
        api_key="K", org_id="O", bridge_id="B", name="x",
    )
    assert c.ws_url.startswith("ws://localhost:8000/")


def test_ws_url_trailing_slash():
    c = ShellBridgeClient(
        url="https://example.com/",
        api_key="K", org_id="O", bridge_id="B", name="x",
    )
    assert "https://example.com//" not in c.ws_url


@pytest.mark.asyncio
async def test_reconnect_is_fast_after_close():
    """When the server closes the socket, the agent should reconnect
    within seconds — NOT wait out the 30s ping interval."""
    served = {"count": 0}
    drop_event = asyncio.Event()

    async def handler(ws):
        served["count"] += 1
        n = served["count"]
        msg = await ws.recv()
        assert json.loads(msg)["type"] == "identify"
        await ws.send(json.dumps({
            "type": "identify_ack",
            "data": {"bridge_id": "B", "connection_id": f"c{n}"},
        }))
        # Drop after a short window.
        await asyncio.sleep(0.5)
        await ws.close(code=1011, reason="test-drop")
        if n >= 2:
            drop_event.set()

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        c = ShellBridgeClient(
            url=f"http://127.0.0.1:{port}",
            api_key="K", org_id="O", bridge_id="B", name="x",
        )
        task = asyncio.create_task(c.connect_forever())
        try:
            t0 = time.monotonic()
            await asyncio.wait_for(drop_event.wait(), timeout=15)
            elapsed = time.monotonic() - t0
            # Two connections + drop + reconnect must complete well
            # before the 30s ping interval would force the issue.
            assert elapsed < 10, f"Reconnect was too slow: {elapsed:.1f}s"
        finally:
            c.stop()
            try:
                await asyncio.wait_for(task, timeout=5)
            except asyncio.TimeoutError:
                task.cancel()


@pytest.mark.asyncio
async def test_stop_cancels_long_backoff():
    """stop() during exponential backoff must exit promptly,
    not wait the full backoff duration."""
    c = ShellBridgeClient(
        url="http://127.0.0.1:9",  # nothing listening
        api_key="K", org_id="O", bridge_id="B", name="x",
    )
    task = asyncio.create_task(c.connect_forever())
    # Let the agent fail a few times so backoff grows.
    await asyncio.sleep(4)
    t0 = time.monotonic()
    c.stop()
    await asyncio.wait_for(task, timeout=2)
    assert time.monotonic() - t0 < 2
