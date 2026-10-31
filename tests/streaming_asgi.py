"""Test helper: an httpx transport that routes by host to ASGI apps and really streams.

An app that raises ``ConnectionError`` after it started its response breaks the body stream
the way a dropped connection does (``httpx.RemoteProtocolError``).

The transport owns the app task of every request, as a server does: a request whose client
gives up keeps running (its work is not cut short), and ``stop_serving()`` (also run by
``aclose()``) shuts down like a server does: new requests are refused, the requests still
running are cancelled and waited for. Shut down this way before the app's own shutdown, or an
abandoned request outlives the app and keeps using its database after the engine is disposed.

``streaming_transport(httpx2)`` builds the same transport for ``httpx2`` (the MCP client's
HTTP library)."""

from __future__ import annotations

import asyncio
from types import ModuleType
from typing import Any

import httpx


async def _cancel_and_wait(tasks: set[asyncio.Task]) -> None:
    """Cancel the tasks and wait until they have finished, cleanups included (SQLAlchemy
    returns a connection from a shielded task of its own)."""
    pending = [t for t in tasks if not t.done()]
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.wait(pending)


def streaming_transport(httpx: ModuleType) -> type:
    """``StreamingASGITransport`` for an httpx-compatible module."""

    class _Body(httpx.AsyncByteStream):
        def __init__(self, queue: asyncio.Queue, task: asyncio.Task, disconnected: asyncio.Event):
            self._queue = queue
            self._task = task
            self._disconnected = disconnected

        async def __aiter__(self):
            while True:
                chunk = await self._queue.get()
                if chunk is None:
                    return
                if isinstance(chunk, BaseException):  # the app failed mid-body: a broken stream
                    raise httpx.RemoteProtocolError(
                        "peer closed connection without sending complete message body"
                    )
                if chunk:
                    yield chunk

        async def aclose(self) -> None:
            self._disconnected.set()
            if not self._task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(self._task), 1.0)
                except (TimeoutError, Exception):  # noqa: BLE001
                    await _cancel_and_wait({self._task})

    class StreamingASGITransport(httpx.AsyncBaseTransport):
        """Routes by host to ASGI apps; response bodies are streamed chunk by chunk."""

        def __init__(self, apps: dict[str, Any]):
            self.apps = apps
            self.requests: list[tuple[str, str, bytes]] = []  # (host, path, body)
            self._running: set[asyncio.Task] = set()  # app tasks of requests not yet finished
            self._serving = True

        async def stop_serving(self) -> None:
            """Refuse new requests, then cancel the ones still running and wait for them."""
            self._serving = False
            await _cancel_and_wait(self._running)

        async def aclose(self) -> None:
            await self.stop_serving()

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if not self._serving:
                raise httpx.ConnectError("connection refused: server stopped", request=request)
            body = b"".join([c async for c in request.stream])  # type: ignore[union-attr]
            self.requests.append((request.url.host, request.url.path, body))
            app = self.apps[request.url.host]
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": request.method,
                "headers": [(k.lower(), v) for k, v in request.headers.raw],
                "scheme": request.url.scheme,
                "path": request.url.path,
                "raw_path": request.url.raw_path.split(b"?")[0],
                "query_string": request.url.query,
                "server": (request.url.host, request.url.port),
                "client": ("127.0.0.1", 123),
                "root_path": "",
            }
            queue: asyncio.Queue = asyncio.Queue()
            started: asyncio.Future = asyncio.get_running_loop().create_future()
            disconnected = asyncio.Event()
            body_sent = False

            async def receive():
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                await disconnected.wait()
                return {"type": "http.disconnect"}

            async def send(message):
                if message["type"] == "http.response.start":
                    if not started.done():  # not when the client already gave up
                        started.set_result(message)
                elif message["type"] == "http.response.body":
                    if disconnected.is_set():
                        return  # the client is gone: dropped, as uvicorn does
                    queue.put_nowait(message.get("body", b""))
                    if not message.get("more_body", False):
                        queue.put_nowait(None)

            async def run():
                try:
                    await app(scope, receive, send)
                except BaseException as e:  # noqa: BLE001
                    if not started.done():
                        started.set_exception(e if isinstance(e, Exception) else RuntimeError())
                    elif isinstance(e, ConnectionError) and not disconnected.is_set():
                        queue.put_nowait(e)  # the server dropped the connection mid-response
                finally:
                    queue.put_nowait(None)

            task = asyncio.create_task(
                run(), name=f"asgi {request.method} {request.url.host}{request.url.path}"
            )
            self._running.add(task)
            task.add_done_callback(self._running.discard)
            try:
                start = await started
            except BaseException:
                # The client gave up before the response started (e.g. its timeout): the
                # request carries on, as on a real server, until it ends or stop_serving().
                disconnected.set()
                started.cancel()
                raise
            return httpx.Response(
                start["status"],
                headers=start.get("headers", []),
                stream=_Body(queue, task, disconnected),
                request=request,
            )

    return StreamingASGITransport


StreamingASGITransport = streaming_transport(httpx)
