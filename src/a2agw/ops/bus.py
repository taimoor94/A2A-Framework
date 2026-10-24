"""In-process pub/sub for gateway events.

``publish`` never blocks. Each subscriber has a bounded queue; when a queue is
full, its oldest event is dropped to make room for the new one, and ``dropped``
is incremented. A ring buffer of recent events is kept for late readers.
"""

from __future__ import annotations

import asyncio
import collections
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

EventKind = Literal["task.state", "partner.call", "partner.state", "security.denied"]


@dataclass(frozen=True)
class GatewayEvent:
    kind: EventKind
    agent_id: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)


class EventBus:
    def __init__(self, recent_size: int = 200) -> None:
        self._recent: collections.deque[GatewayEvent] = collections.deque(maxlen=recent_size)
        self._subscribers: set[asyncio.Queue[GatewayEvent]] = set()
        self.dropped: int = 0

    def publish(self, ev: GatewayEvent) -> None:
        """Record and fan out an event. Never awaits or blocks."""
        self._recent.append(ev)
        for q in self._subscribers:
            if q.full():
                q.get_nowait()
                self.dropped += 1
            q.put_nowait(ev)

    async def subscribe(self, maxsize: int = 1000) -> AsyncIterator[GatewayEvent]:
        """Yield events published after the subscription is registered.

        Registration happens on the first ``__anext__`` call. The subscriber is
        removed when the generator is closed or cancelled.
        """
        q: asyncio.Queue[GatewayEvent] = asyncio.Queue(maxsize)
        self._subscribers.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subscribers.discard(q)

    def recent(self, n: int = 200) -> list[GatewayEvent]:
        """Return the newest ``n`` events, oldest first."""
        if n <= 0:
            return []
        return list(self._recent)[-n:]
