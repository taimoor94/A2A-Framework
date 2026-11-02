"""The control plane shuts down promptly with a gateway stream open: on an exit signal the
open /cp/v1/stream responses end, so uvicorn (which waits for open responses before the
lifespan shutdown) reaches the lifespan cleanup at once; ``control serve`` also bounds that
wait. A maintenance pass running at shutdown finishes before the engine is disposed."""

from __future__ import annotations

import asyncio
import signal
import socket
import time
from typing import Any

import httpx
import pytest
import uvicorn
from sse_starlette.sse import AppStatus

pytest.importorskip("fastapi")

from a2agw.control import app as app_mod
from a2agw.control import channel
from a2agw.control.app import create_app
from a2agw.control.settings import ControlSettings

GRACEFUL_S = 8.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _until(predicate: Any, timeout: float = 10.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


async def test_exit_signal_ends_open_streams_and_runs_the_cleanup(tmp_path, monkeypatch):
    drained: list[bool] = []
    real_drain = channel.Background.drain

    async def drain(self: channel.Background) -> None:
        drained.append(True)
        await real_drain(self)

    monkeypatch.setattr(channel.Background, "drain", drain)
    port = _free_port()
    settings = ControlSettings(
        base_url="https://cp.example",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}",
    )
    app = create_app(settings, maintenance_interval_s=3600)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            timeout_graceful_shutdown=GRACEFUL_S,  # type: ignore[arg-type]
        )
    )
    # uvicorn re-raises a captured exit signal once it stops: keep that from ending pytest
    previous = signal.signal(signal.SIGTERM, lambda sig, frame: None)
    served = asyncio.create_task(server.serve())
    reader: asyncio.Task[None] | None = None
    try:
        await _until(lambda: server.started)
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        opened = asyncio.Event()

        async def read() -> None:
            headers = {"authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(timeout=30) as hc:
                url = f"http://127.0.0.1:{port}/cp/v1/stream?applied=0"
                async with hc.stream("GET", url, headers=headers) as r:
                    async for line in r.aiter_lines():
                        if line.startswith("event: hello"):
                            opened.set()

        reader = asyncio.create_task(read())
        await asyncio.wait_for(opened.wait(), 10)
        start = time.monotonic()
        signal.raise_signal(signal.SIGTERM)
        await asyncio.wait_for(served, 30)
        assert time.monotonic() - start < GRACEFUL_S / 2  # not the bound: the stream ended
        assert drained == [True]  # the lifespan cleanup ran
        await asyncio.wait_for(reader, 5)  # the stream ended normally
    finally:
        if reader is not None and not reader.done():
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        if not served.done():
            server.should_exit = True
            await asyncio.wait_for(served, 30)
        signal.signal(signal.SIGTERM, previous)
        # sse_starlette patches uvicorn's handle_exit to set a process-global flag that ends
        # every later SSE response at once: reset it, or the gateway streams in later tests end
        AppStatus.should_exit = False


def test_control_serve_bounds_the_graceful_shutdown(tmp_path, monkeypatch):
    import uvicorn as uv
    from typer.testing import CliRunner

    from a2agw.cli import app as cli_app

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uv, "run", lambda *a, **kw: seen.update(kw))
    cfg = tmp_path / "control.yaml"
    cfg.write_text(
        f"base_url: https://cp.example\ndb_url: sqlite+aiosqlite:///{tmp_path / 'cp.db'}\n"
    )
    result = CliRunner().invoke(cli_app, ["control", "serve", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    assert seen["timeout_graceful_shutdown"] == app_mod.GRACEFUL_SHUTDOWN_S


async def test_a_maintenance_pass_finishes_before_the_engine_goes(sqlite_settings, run_app):
    """Shutdown stops the loop between passes; a pass already running is not cancelled
    mid-database-call: it finishes, then the engine is disposed."""
    entered = asyncio.Event()
    release = asyncio.Event()
    outcome: list[str] = []
    app = create_app(sqlite_settings, maintenance_interval_s=0.01)

    async def slow_hook(_now: float) -> None:
        entered.set()
        try:
            await release.wait()
            outcome.append("finished")
        except asyncio.CancelledError:
            outcome.append("cancelled")
            raise

    async with app.router.lifespan_context(app):
        app.state.maintenance.hooks.append(slow_hook)
        await asyncio.wait_for(entered.wait(), 10)
        asyncio.get_running_loop().call_later(0.2, release.set)
    assert outcome == ["finished"]
