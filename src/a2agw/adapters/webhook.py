"""Webhook adapter: an external agent, in any language, served over HTTP (spec 7.7).

Each turn is one ``POST`` of the ``a2agw.invoke/1`` body (``a2agw.gateway.protocol``) to the
agent's URL; the response streams wire events back (``application/x-ndjson``, one event per
line) or carries them at once (``application/json``). ``docs/sidecar.md`` is the contract an
agent implements.

Security and failure handling:

- The request goes through a guarded client (``a2agw.consult.guarded_net``) vetted with the
  configured tier (default ``internal``: loopback and private addresses are allowed, metadata
  addresses never are). A client injected with ``http=`` is used as given (the test seam).
- With a ``secret``, every request is signed (``X-A2AGW-Signature``, see ``protocol.sign``).
- ``timeout_s`` is one end-to-end deadline for the whole turn, connect to last event.
- Failures become a ``Failed`` event whose reason is fixed text (the A2A caller sees it);
  the agent's response body is never included. Details go to the ``a2agw.agent.<id>`` logger
  at WARNING: an error class, a status code or a protocol rule, never a value.
- Cancelling ``run()`` (or closing its generator) closes the response: closing the
  connection is the agent's cancel signal.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, aclosing
from typing import Any, TypeVar

import httpx

from a2agw.adapters._stream import stream_events
from a2agw.consult.guarded_net import fixed_tier, guarded_async_client, is_unsafe_address
from a2agw.consult.netguard import Tier, check_url_syntax, require_https
from a2agw.core.events import AgentEvent, Done, Failed
from a2agw.core.spi import InboundContext
from a2agw.gateway.protocol import (
    MAX_EVENTS,
    MAX_LINE_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL,
    TERMINAL,
    ConsultGrant,
    ProtocolError,
    build_invoke,
    parse_event,
    sign,
)

__all__ = ["WebhookAdapter"]

NDJSON = "application/x-ndjson"
JSON = "application/json"

T = TypeVar("T")
ConsultFn = Callable[[InboundContext], Awaitable[ConsultGrant | None]]
_Within = Callable[[Awaitable[Any]], Awaitable[Any]]


class WebhookAdapter:
    """Inbound adapter for an external agent behind ``url`` (see the module docstring)."""

    def __init__(
        self,
        url: str,
        *,
        secret: str | None = None,
        timeout_s: float = 300.0,
        tier: Tier = "internal",
        http: httpx.AsyncClient | None = None,
        durable_sessions: bool = False,
        consult: ConsultFn | None = None,
    ) -> None:
        check_url_syntax(url)  # UnsafeURL (a ValueError) naming the rule, not the URL
        if tier != "internal":
            require_https(url)
        if not timeout_s > 0:
            raise ValueError("timeout_s must be positive")
        self.url = url
        self.secret = secret
        self.timeout_s = float(timeout_s)
        self.tier: Tier = tier
        self.http = http
        self.durable_sessions = durable_sessions
        self.consult = consult

    def __repr__(self) -> str:  # never the secret
        return f"WebhookAdapter(url={self.url!r}, tier={self.tier!r}, timeout_s={self.timeout_s})"

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        log = logging.getLogger(f"a2agw.agent.{ctx.agent_id}")
        async with (
            aclosing(self._turn(ctx, log)) as items,
            aclosing(stream_events(items)) as events,
        ):
            terminal = False
            async for ev in events:
                terminal = isinstance(ev, TERMINAL)
                yield ev
        if not terminal:  # a clean end of stream without a terminal event
            yield Done()

    def _headers(self, body: bytes) -> dict[str, str]:
        ts = str(int(time.time()))
        headers = {
            "Content-Type": JSON,
            "Accept": f"{NDJSON}, {JSON}",
            "X-A2AGW-Protocol": PROTOCOL,
            "X-A2AGW-Timestamp": ts,
        }
        if self.secret is not None:
            headers["X-A2AGW-Signature"] = sign(self.secret, ts, body)
        return headers

    async def _turn(
        self, ctx: InboundContext, log: logging.Logger
    ) -> AsyncIterator[AgentEvent | str]:
        """Wire events (a ``str`` is a text delta), then possibly one ``Failed``."""
        deadline = asyncio.get_running_loop().time() + self.timeout_s

        async def within(aw: Awaitable[T]) -> T:
            async with asyncio.timeout_at(deadline):
                return await aw

        grant = await self.consult(ctx) if self.consult is not None else None
        invoke = build_invoke(ctx, consult=grant, deadline=time.time() + self.timeout_s)
        body = json.dumps(invoke, separators=(",", ":")).encode()
        connected = False
        failure: str | None = None
        try:
            async with AsyncExitStack() as stack:
                client = self.http
                if client is None:
                    client = await stack.enter_async_context(
                        guarded_async_client(
                            fixed_tier(self.tier), timeout=httpx.Timeout(self.timeout_s)
                        )
                    )
                request = client.stream("POST", self.url, content=body, headers=self._headers(body))
                response = await within(stack.enter_async_context(request))
                connected = True
                if not 200 <= response.status_code < 300:
                    log.warning("agent returned HTTP %d", response.status_code)
                    failure = f"agent returned HTTP {response.status_code}"
                else:
                    async with aclosing(self._events(response, within)) as events:
                        async for item in events:
                            yield item
                            if isinstance(item, TERMINAL):
                                return
        except (TimeoutError, httpx.TimeoutException):
            log.warning("agent timed out after %ss", self.timeout_s)
            failure = "agent timed out"
        except ProtocolError as e:
            log.warning("agent protocol error: %s", e)
            failure = "agent protocol error"
        except httpx.TransportError as e:
            reason = "unsafe address" if is_unsafe_address(e) else type(e).__name__
            if connected:
                log.warning("agent connection lost: %s", reason)
                failure = "agent connection lost"
            else:
                log.warning("agent unreachable: %s", reason)
                failure = "agent unreachable"
        if failure is not None:
            yield Failed(failure)

    async def _events(
        self, response: httpx.Response, within: _Within
    ) -> AsyncIterator[AgentEvent | str]:
        ctype = response.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in (NDJSON, JSON):
            raise ProtocolError("unsupported response content type")
        count = 0

        def event(raw: Any) -> AgentEvent | str:
            nonlocal count
            count += 1
            if count > MAX_EVENTS:
                raise ProtocolError("more than MAX_EVENTS events")
            return parse_event(raw)

        async with aclosing(_chunks(response, within)) as chunks:
            if ctype == JSON:
                data = _loads(b"".join([c async for c in chunks]))
                if not isinstance(data, dict) or len(data) != 1:
                    raise ProtocolError("JSON response needs exactly one of text or events")
                if "text" in data:
                    if not isinstance(data["text"], str):
                        raise ProtocolError("JSON response text must be a string")
                    yield Done(data["text"])
                    return
                raw_events = data.get("events")
                if not isinstance(raw_events, list):
                    raise ProtocolError("JSON response needs exactly one of text or events")
                for raw in raw_events:
                    yield event(raw)
                return

            buf = bytearray()
            async for chunk in chunks:
                buf += chunk
                while (i := buf.find(b"\n")) >= 0:
                    line = bytes(buf[:i])
                    del buf[: i + 1]
                    if line.strip():
                        yield event(_loads(_line(line)))
                if len(buf) > MAX_LINE_BYTES:
                    raise ProtocolError("line longer than MAX_LINE_BYTES")
            if buf.strip():  # a last line without its newline
                yield event(_loads(_line(bytes(buf))))


def _line(line: bytes) -> bytes:
    line = line.removesuffix(b"\r")
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolError("line longer than MAX_LINE_BYTES")
    return line


def _loads(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (ValueError, RecursionError):  # incl. UnicodeDecodeError
        raise ProtocolError("invalid JSON") from None


async def _chunks(response: httpx.Response, within: _Within) -> AsyncIterator[bytes]:
    """The decoded body, each read under the turn deadline, at most MAX_RESPONSE_BYTES."""
    it = response.aiter_bytes()
    total = 0
    try:
        while (chunk := await within(anext(it, None))) is not None:
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ProtocolError("response larger than MAX_RESPONSE_BYTES")
            yield chunk
    finally:
        await it.aclose()
