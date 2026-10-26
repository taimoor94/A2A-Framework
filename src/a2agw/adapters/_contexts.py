"""Per-context state shared by the framework adapters: one entry per A2A context (or any
hashable key), turns on one key serialised, at most ``max_size`` entries kept.

Each entry has a lock and an in-flight count. A turn counts itself in before it waits for the
lock and out when it ends (however it ends), and only entries with no turn in flight are ever
evicted. Counting before the wait matters: a released lock looks free while the next waiter
is still being woken, and evicting the entry then would let that waiter run on an orphan
while a new turn on the same key made a fresh entry and ran beside it.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable, Hashable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Generic, TypeVar

__all__ = ["ContextRegistry"]

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    in_flight: int = 0  # turns holding or waiting for ``lock``


class ContextRegistry(Generic[K, V]):
    """An LRU of per-key state ``V`` (made by ``factory(key)`` on first use).

    ``async with registry.turn(key) as value`` runs one turn: it waits for the key's earlier
    turns to finish and marks the key most recently used. Past ``max_size`` entries the least
    recently used idle ones are dropped, each passed to ``on_evict(key, value)`` (synchronous,
    so nothing runs between the drop and the clean-up). Iterating yields the keys, least
    recently used first."""

    def __init__(
        self,
        factory: Callable[[K], V],
        *,
        max_size: int,
        on_evict: Callable[[K, V], None] | None = None,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be at least 1")
        self.factory = factory
        self.max_size = max_size
        self.on_evict = on_evict
        self._entries: OrderedDict[K, _Entry[V]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[K]:
        return iter(list(self._entries))

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __getitem__(self, key: K) -> V:
        return self._entries[key].value

    def _claim(self, key: K) -> _Entry[V]:
        entry = self._entries.get(key)
        if entry is None:
            entry = self._entries[key] = _Entry(self.factory(key))
        self._entries.move_to_end(key)
        entry.in_flight += 1  # before anything can evict it
        excess = len(self._entries) - self.max_size
        if excess > 0:
            idle = [k for k, e in self._entries.items() if e.in_flight == 0]
            for k in idle[:excess]:
                dropped = self._entries.pop(k)
                if self.on_evict is not None:
                    self.on_evict(k, dropped.value)
        return entry

    @asynccontextmanager
    async def turn(self, key: K) -> AsyncIterator[V]:
        """Hold ``key`` for one turn and yield its state."""
        entry = self._claim(key)
        try:
            async with entry.lock:
                yield entry.value
        finally:
            entry.in_flight -= 1
