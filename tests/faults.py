"""Test helper: a fault-injection ASGI middleware that wraps a partner app.

``FaultInjector(app, plan)`` looks up each HTTP request in ``plan``, first by its JSON-RPC
method (``SendMessage``, ``SendStreamingMessage``, ``GetTask``, ``CancelTask``,
``SubscribeToTask``...), then by its path (``/agents/p/rest/message:send``...). A request
without a planned fault goes to the wrapped app unchanged.

Faults:

- ``latency(s)``: wait ``s`` seconds, then forward the request.
- ``status(code)``: answer ``code`` with an empty JSON object; the app never sees the call.
- ``drop_stream_after(n_events)``: forward, but drop the connection after ``n_events``
  server-sent events (with ``tests/streaming_asgi.py`` the client sees
  ``httpx.RemoteProtocolError`` mid-body, as from a real connection reset).
- ``malformed_body()``: answer 200 ``application/json`` with a body that is not JSON.
- ``close_connection()``: drop the connection before any response
  (``httpx.RemoteProtocolError``, as httpcore reports a server that disconnects).

``times`` limits a fault to its first N matching requests (None: every request).
``injector.seen`` lists the key of every request that hit a fault.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

Kind = Literal["latency", "status", "drop_stream_after", "malformed_body", "close_connection"]


@dataclass
class Fault:
    kind: Kind
    value: float = 0.0
    times: int | None = None
    used: int = field(default=0, compare=False)

    def take(self) -> bool:
        if self.times is not None and self.used >= self.times:
            return False
        self.used += 1
        return True


def latency(s: float, *, times: int | None = None) -> Fault:
    return Fault("latency", s, times)


def status(code: int, *, times: int | None = None) -> Fault:
    return Fault("status", code, times)


def drop_stream_after(n_events: int, *, times: int | None = None) -> Fault:
    return Fault("drop_stream_after", n_events, times)


def malformed_body(*, times: int | None = None) -> Fault:
    return Fault("malformed_body", times=times)


def close_connection(*, times: int | None = None) -> Fault:
    return Fault("close_connection", times=times)


def _rpc_method(body: bytes) -> str | None:
    try:
        data = json.loads(body)
    except ValueError:
        return None
    method = data.get("method") if isinstance(data, dict) else None
    return method if isinstance(method, str) else None


class FaultInjector:
    def __init__(self, app: Any, plan: dict[str, Fault]) -> None:
        self.app = app
        self.plan = plan
        self.seen: list[str] = []

    def _fault_for(self, method: str | None, path: str) -> tuple[str, Fault] | None:
        for key in (method, path):
            if key is not None and key in self.plan and self.plan[key].take():
                return key, self.plan[key]
        return None

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        hit = self._fault_for(_rpc_method(body), scope["path"])
        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        if hit is None:
            await self.app(scope, replay, send)
            return
        key, fault = hit
        self.seen.append(key)
        match fault.kind:
            case "latency":
                await asyncio.sleep(fault.value)
                await self.app(scope, replay, send)
            case "status":
                await _respond(send, int(fault.value), b"{}")
            case "malformed_body":
                await _respond(send, 200, b'{"jsonrpc": "2.0", "result": {not json')
            case "close_connection":
                raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
            case "drop_stream_after":
                await self._drop_after(scope, replay, send, int(fault.value))

    async def _drop_after(self, scope: dict, receive: Any, send: Any, n_events: int) -> None:
        events = 0
        dropped = asyncio.Event()

        async def counting_send(message: dict) -> None:
            nonlocal events
            if dropped.is_set():
                raise OSError("stream dropped")
            if message["type"] != "http.response.body":
                await send(message)
                return
            out = bytearray()
            for line in message.get("body", b"").splitlines(keepends=True):
                if events >= n_events:
                    break
                out.extend(line)
                if line in (b"\n", b"\r\n"):
                    events += 1
            if events >= n_events:
                dropped.set()
                if out:
                    await send(
                        {"type": "http.response.body", "body": bytes(out), "more_body": True}
                    )
                return
            await send(message)

        app_task = asyncio.ensure_future(self.app(scope, receive, counting_send))
        waiter = asyncio.ensure_future(dropped.wait())
        await asyncio.wait({app_task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        if not dropped.is_set():  # the response ended before n events: nothing to drop
            await app_task
            return
        app_task.cancel()
        try:
            await app_task
        except (asyncio.CancelledError, OSError):
            pass
        raise ConnectionResetError("connection dropped mid-stream")


async def _respond(send: Any, code: int, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": code,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
