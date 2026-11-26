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


def _client():
    return ShellBridgeClient(
        url="https://example.com",
        api_key="K", org_id="O", bridge_id="B", name="x",
    )


@pytest.mark.asyncio
async def test_command_finishing_after_disconnect_does_not_crash(monkeypatch, caplog):
    """A command that outlives its connection used to raise
    AttributeError: 'NoneType' object has no attribute 'send'."""
    c = _client()
    c._ws = None

    async def fake_dispatch(command, params):
        return {"success": True}

    monkeypatch.setattr(c, "_dispatch_command", fake_dispatch)
    with caplog.at_level("WARNING"):
        await c._handle_command({"request_id": "r1", "command": "env_info"})
    assert "disconnected while it ran" in caplog.text
    assert "AttributeError" not in caplog.text
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


@pytest.mark.asyncio
async def test_failed_pack_update_not_retried_on_reconnect(monkeypatch):
    from strobes_shell_agent import client as client_mod

    calls = []
    monkeypatch.setattr(client_mod.pack, "needs_update", lambda v: True)
    monkeypatch.setattr(client_mod.pack, "installed_version", lambda: "old")

    def fake_update(url, version):
        calls.append(version)
        return None  # failed

    monkeypatch.setattr(client_mod.pack, "update_pack", fake_update)
    c = _client()
    for _ in range(3):  # three reconnects, each with an identify_ack
        await c._apply_updates({"required_pack_version": "v9"})
    assert calls == ["v9"]

    # A different version is still attempted.
    await c._apply_updates({"required_pack_version": "v10"})
    assert calls == ["v9", "v10"]


@pytest.mark.asyncio
async def test_pack_update_is_single_flight(monkeypatch):
    from strobes_shell_agent import client as client_mod
    import threading

    started = threading.Event()
    release = threading.Event()
    calls = []
    monkeypatch.setattr(client_mod.pack, "needs_update", lambda v: True)
    monkeypatch.setattr(client_mod.pack, "installed_version", lambda: "old")

    def slow_update(url, version):
        calls.append(version)
        started.set()
        release.wait(5)
        return "path"

    monkeypatch.setattr(client_mod.pack, "update_pack", slow_update)
    c = _client()
    first = asyncio.create_task(c._apply_updates({"required_pack_version": "v9"}))
    await asyncio.to_thread(started.wait, 5)
    await c._apply_updates({"required_pack_version": "v9"})  # concurrent reconnect
    release.set()
    await first
    assert calls == ["v9"]


@pytest.mark.asyncio
async def test_failed_agent_update_not_retried(monkeypatch):
    from strobes_shell_agent import client as client_mod

    calls = []
    monkeypatch.setattr(client_mod.selfupdate, "maybe_update",
                        lambda v, url: calls.append(v) or False)
    c = _client()
    for _ in range(3):
        await c._apply_updates({"required_agent_version": "99.0.0"})
    assert calls == ["99.0.0"]


@pytest.mark.asyncio
async def test_large_manifest_is_received_and_close_reason_logged(caplog):
    """A >10MB platform message (a 2000-file push manifest) used to make the
    client close with 1009, logged only as 'code=1006 reason='''."""
    from strobes_shell_agent import client as client_mod

    got = []
    big = json.dumps({"type": "pong", "pad": "x" * 12_000_000})

    async def handler(ws):
        await ws.recv()  # identify
        await ws.send(big)
        await ws.close(code=4000, reason="done")

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        c = ShellBridgeClient(
            url=f"http://127.0.0.1:{port}",
            api_key="K", org_id="O", bridge_id="B", name="x",
        )
        orig = c._message_handler

        async def handler_once():
            await orig()
            got.append(True)
            c.stop()

        c._message_handler = handler_once
        with caplog.at_level("INFO"):
            await asyncio.wait_for(c.connect_forever(), timeout=15)

    assert got
    assert "received=4000 'done'" in caplog.text
    assert "1009" not in caplog.text
    assert client_mod.MAX_MESSAGE_SIZE > 12_000_000
