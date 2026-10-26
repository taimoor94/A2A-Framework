"""Test helper: an httpx transport that routes by host to ASGI apps and really streams.

An app that raises ``ConnectionError`` after it started its response breaks the body stream
the way a dropped connection does (``httpx.RemoteProtocolError``).

``streaming_transport(httpx2)`` builds the same transport for ``httpx2`` (the MCP client's
HTTP library)."""

from __future__ import annotations

import asyncio
from types import ModuleType
from typing import Any

import httpx


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
                    self._task.cancel()

    class StreamingASGITransport(httpx.AsyncBaseTransport):
        """Routes by host to ASGI apps; response bodies are streamed chunk by chunk."""

        def __init__(self, apps: dict[str, Any]):
            self.apps = apps
            self.requests: list[tuple[str, str, bytes]] = []  # (host, path, body)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
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
                    started.set_result(message)
                elif message["type"] == "http.response.body":
                    if disconnected.is_set():
                        raise OSError("client disconnected")
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

            task = asyncio.create_task(run())
            start = await started
            return httpx.Response(
                start["status"],
                headers=start.get("headers", []),
                stream=_Body(queue, task, disconnected),
                request=request,
            )

    return StreamingASGITransport


StreamingASGITransport = streaming_transport(httpx)
