"""In-process pub/sub for gateway events.

``publish`` never blocks. Each subscriber has a bounded queue; when a queue is
full, its oldest event is dropped to make room for the new one, and ``dropped``
is incremented. A ring buffer of recent events is kept for late readers.

``subscribe`` registers its queue immediately, so an event published right after
``subscribe`` returns is delivered. ``subscribe_with_replay`` takes the snapshot
and registers the queue in one synchronous step, so a replay-then-live consumer
sees no gap and no duplicates.
"""

from __future__ import annotations

import asyncio
import collections
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Self

EventKind = Literal["task.state", "partner.call", "partner.state", "security.denied"]

# Pushed into a subscriber's queue on close so a pending __anext__ wakes up.
_CLOSED = object()


@dataclass(frozen=True)
class GatewayEvent:
    kind: EventKind
    agent_id: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)


class Subscription:
    """A live stream of events. Use ``async for``, or ``async with`` to unregister."""

    def __init__(self, bus: EventBus, queue: asyncio.Queue[Any]) -> None:
        self._bus = bus
        self._queue = queue
        self._closed = False

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> GatewayEvent:
        if self._closed:
            raise StopAsyncIteration
        item = await self._queue.get()
        if self._closed or item is _CLOSED:
            raise StopAsyncIteration
        return item

    async def aclose(self) -> None:
        """Unregister this subscriber. Idempotent."""
        if self._closed:
            return
        self._closed = True
        self._bus._subscribers.discard(self._queue)
        # Wake a __anext__ that is already waiting on the queue.
        if self._queue.full():
            self._queue.get_nowait()
        self._queue.put_nowait(_CLOSED)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class EventBus:
    def __init__(self, recent_size: int = 200) -> None:
        self._recent: collections.deque[GatewayEvent] = collections.deque(maxlen=recent_size)
        self._subscribers: set[asyncio.Queue[Any]] = set()
        self.dropped: int = 0

    def publish(self, ev: GatewayEvent) -> None:
        """Record and fan out an event. Never awaits or blocks."""
        self._recent.append(ev)
        for q in self._subscribers:
            if q.full():
                q.get_nowait()
                self.dropped += 1
            q.put_nowait(ev)

    def subscribe(self, maxsize: int = 1000) -> Subscription:
        """Register a subscriber now. Events published from this point on are queued."""
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize)
        self._subscribers.add(q)
        return Subscription(self, q)

    def subscribe_with_replay(
        self, n: int = 50, maxsize: int = 1000
    ) -> tuple[list[GatewayEvent], Subscription]:
        """Return ``(recent(n), subscription)`` with no gap and no duplicates.

        The snapshot and the queue registration happen in one synchronous step with
        no await in between. Each published event lands either in the snapshot
        (published before) or in the subscription (published after), never both.
        """
        sub = self.subscribe(maxsize)
        return self.recent(n), sub

    def recent(self, n: int = 200) -> list[GatewayEvent]:
        """Return the newest ``n`` events, oldest first."""
        if n <= 0:
            return []
        return list(self._recent)[-n:]
