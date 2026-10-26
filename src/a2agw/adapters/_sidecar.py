"""Turn plumbing shared by the sidecar adapters (``webhook``, ``stdio``): the turn deadline,
the consult grant step, JSON line parsing and the run wrapper that ends every turn with a
terminal event. Failure reasons are fixed text (the A2A caller sees them); details go to the
agent's logger as an error class or a protocol rule, never a value."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import aclosing
from typing import Any, TypeVar

from a2agw.adapters._stream import stream_events
from a2agw.core.events import AgentEvent, Done
from a2agw.core.spi import InboundContext
from a2agw.gateway.protocol import MAX_LINE_BYTES, TERMINAL, ConsultGrant, ProtocolError

T = TypeVar("T")
ConsultFn = Callable[[InboundContext], Awaitable[ConsultGrant | None]]


class TurnFailure(Exception):
    """Ends a turn with ``Failed(reason)``; ``reason`` is fixed text, never an agent value."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class TurnDeadline:
    """One end-to-end deadline for a turn, captured once when the turn starts on both clocks:
    the event loop's (enforced, see ``within``) and the wall clock's (``wall``, epoch seconds,
    sent to the agent as the invoke body's ``deadline``)."""

    def __init__(self, timeout_s: float) -> None:
        self.timeout_s = timeout_s
        self.loop_at = asyncio.get_running_loop().time() + timeout_s
        self.wall = time.time() + timeout_s

    async def within(self, aw: Awaitable[T]) -> T:
        """Await ``aw``; ``TimeoutError`` once the deadline has passed."""
        async with asyncio.timeout_at(self.loop_at):
            return await aw


async def consult_grant(
    consult: ConsultFn | None, ctx: InboundContext, deadline: TurnDeadline, log: logging.Logger
) -> ConsultGrant | None:
    """The turn's consult grant (None without a ``consult`` callable), bounded by the turn
    deadline. A failure raises ``TurnFailure``; nothing has been sent to the agent yet."""
    if consult is None:
        return None
    try:
        return await deadline.within(consult(ctx))
    except TimeoutError:
        log.warning("agent timed out after %ss (consult setup)", deadline.timeout_s)
        raise TurnFailure("agent timed out") from None
    except Exception as e:  # noqa: BLE001 - any failure of the grant callable
        log.warning("agent consult setup failed: %s", type(e).__name__)
        raise TurnFailure("agent consult setup failed") from None


def check_line(line: bytes) -> bytes:
    """One JSON line without its newline (and a trailing ``\\r``), within MAX_LINE_BYTES."""
    line = line.removesuffix(b"\r")
    if len(line) > MAX_LINE_BYTES:
        raise ProtocolError("line longer than MAX_LINE_BYTES")
    return line


def loads(data: bytes) -> Any:
    """``json.loads``; invalid JSON (or bytes that are not UTF-8) is a ``ProtocolError``."""
    try:
        return json.loads(data)
    except (ValueError, RecursionError):  # incl. UnicodeDecodeError
        raise ProtocolError("invalid JSON") from None


async def run_turn(items: AsyncIterator[AgentEvent | str]) -> AsyncIterator[AgentEvent]:
    """A turn's wire items as events: text deltas become the streamed "output" artifact
    (``stream_events``, its last chunk marked ``last``), nothing is read after a terminal
    event, and a turn that ends without one completes with ``Done()``. Closing the result
    closes ``items``."""
    async with aclosing(items) as source, aclosing(stream_events(source)) as events:
        terminal = False
        async for ev in events:
            terminal = isinstance(ev, TERMINAL)
            yield ev
    if not terminal:
        yield Done()
