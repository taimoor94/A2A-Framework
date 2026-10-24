"""Resilience primitives: circuit breaker, bulkhead, retry."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Literal, TypeVar

import httpx

T = TypeVar("T")
State = Literal["closed", "open", "half_open"]


class Busy(Exception):
    """Bulkhead full: no slot became free within the timeout."""


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        reset_after_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.failure_threshold = failure_threshold
        self.reset_after_s = reset_after_s
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None
        self._probe_started_at: float | None = None

    @property
    def state(self) -> State:
        if self._opened_at is None:
            return "closed"
        if self._clock() - self._opened_at >= self.reset_after_s:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        s = self.state
        if s == "closed":
            return True
        if s == "half_open":
            now = self._clock()
            started = self._probe_started_at
            # A probe older than reset_after_s is abandoned (cancelled/crashed caller).
            if started is None or now - started >= self.reset_after_s:
                self._probe_started_at = now
                return True
        return False

    def record_success(self) -> None:
        s = self.state
        if s == "closed":
            self._failures = 0
        elif s == "half_open" and self._probe_started_at is not None:
            self._failures = 0
            self._opened_at = None
            self._probe_started_at = None
        # open, or half_open without a probe: straggler from before the open; ignore

    def release_probe(self) -> None:
        """Give back a half-open probe whose call ended with no outcome (cancelled, etc.)."""
        if self.state == "half_open":
            self._probe_started_at = None

    def record_failure(self) -> None:
        s = self.state
        if s == "closed":
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._opened_at = self._clock()
        elif s == "half_open" and self._probe_started_at is not None:
            self._opened_at = self._clock()
            self._probe_started_at = None


class Bulkhead:
    def __init__(self, max_concurrent: int = 8):
        self.max_concurrent = max_concurrent
        self._sem = asyncio.Semaphore(max_concurrent)
        self._in_use = 0

    @property
    def in_use(self) -> int:
        return self._in_use

    @asynccontextmanager
    async def acquire(self, timeout_s: float) -> AsyncIterator[None]:
        try:
            async with asyncio.timeout(timeout_s):
                await self._sem.acquire()
        except TimeoutError:
            raise Busy(f"bulkhead full ({self.max_concurrent} concurrent)") from None
        self._in_use += 1
        try:
            yield
        finally:
            self._in_use -= 1
            self._sem.release()


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base: float = 0.2,
    cap: float = 2.0,
    retry_on: tuple[type[BaseException], ...] = (httpx.ConnectError, httpx.ConnectTimeout),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    rand: Callable[[], float] = random.random,
) -> T:
    n = 1
    while True:
        try:
            return await fn()
        except retry_on:
            if n >= attempts:
                raise
        n += 1
        await sleep(min(cap, base * 2 ** (n - 2)) * (0.5 + rand() / 2))
