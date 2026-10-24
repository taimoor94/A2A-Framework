import httpx
import pytest

from a2agw.consult.resilience import Bulkhead, Busy, CircuitBreaker, with_retry


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_breaker_opens_after_5_and_half_opens():
    clk = Clock()
    b = CircuitBreaker(clock=clk)
    for _ in range(4):
        b.record_failure()
    assert b.state == "closed" and b.allow()
    b.record_failure()
    assert b.state == "open" and not b.allow()
    clk.t += 29.9
    assert b.state == "open"
    clk.t += 0.2
    assert b.state == "half_open"
    assert b.allow()
    b.record_success()
    assert b.state == "closed"


def test_success_resets_consecutive_count():
    b = CircuitBreaker(clock=Clock())
    for _ in range(4):
        b.record_failure()
    b.record_success()
    for _ in range(4):
        b.record_failure()
    assert b.state == "closed"


def test_half_open_single_probe():
    clk = Clock()
    b = CircuitBreaker(clock=clk)
    for _ in range(5):
        b.record_failure()
    clk.t += 31
    assert b.allow() is True
    assert b.allow() is False
    assert b.allow() is False
    b.record_failure()
    assert b.state == "open" and not b.allow()
    clk.t += 29
    assert b.state == "open"  # new timestamp
    clk.t += 2
    assert b.allow() is True


def _open(clk):
    b = CircuitBreaker(clock=clk)
    for _ in range(5):
        b.record_failure()
    return b


def test_abandoned_probe_is_replaced():
    clk = Clock()
    b = _open(clk)
    clk.t += 31
    assert b.allow() is True
    assert b.allow() is False
    clk.t += 31  # probe caller vanished
    assert b.state == "half_open"
    assert b.allow() is True
    b.record_success()
    assert b.state == "closed"


def test_late_success_while_open_ignored():
    b = _open(Clock())
    b.record_success()
    assert b.state == "open" and not b.allow()


def test_late_failure_while_open_does_not_extend():
    clk = Clock()
    b = _open(clk)
    clk.t += 20
    b.record_failure()
    clk.t += 11  # 31s since opening
    assert b.state == "half_open"


async def test_bulkhead_busy_after_timeout():
    bh = Bulkhead(max_concurrent=1)
    async with bh.acquire(0.5):
        assert bh.in_use == 1
        with pytest.raises(Busy):
            async with bh.acquire(0.01):
                pass
    assert bh.in_use == 0
    async with bh.acquire(0.01):
        pass


async def test_bulkhead_releases_on_error():
    bh = Bulkhead(max_concurrent=1)
    with pytest.raises(ValueError):
        async with bh.acquire(0.1):
            raise ValueError
    assert bh.in_use == 0


async def test_retry_only_connect_errors():
    calls = 0

    async def fn():
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("slow")

    async def nosleep(_):
        raise AssertionError("must not sleep")

    with pytest.raises(httpx.ReadTimeout):
        await with_retry(fn, sleep=nosleep)
    assert calls == 1


async def test_retry_attempts_capped_and_backoff():
    calls = 0
    delays: list[float] = []

    async def fn():
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("no")

    async def sleep(d):
        delays.append(d)

    with pytest.raises(httpx.ConnectError):
        await with_retry(fn, sleep=sleep, rand=lambda: 1.0)
    assert calls == 3
    assert delays == pytest.approx([0.2, 0.4])


async def test_retry_succeeds_and_cap():
    n = 0
    delays: list[float] = []

    async def fn():
        nonlocal n
        n += 1
        if n < 4:
            raise httpx.ConnectTimeout("t")
        return "ok"

    async def sleep(d):
        delays.append(d)

    assert await with_retry(fn, attempts=4, base=1.0, cap=1.5, sleep=sleep, rand=lambda: 0.0) == "ok"
    assert delays == pytest.approx([0.5, 0.75, 0.75])


def test_release_probe_lets_next_caller_probe():
    clk = Clock()
    b = CircuitBreaker(clock=clk)
    for _ in range(5):
        b.record_failure()
    clk.t += 30
    assert b.allow()
    assert not b.allow()  # probe in flight
    b.release_probe()
    assert b.state == "half_open"
    assert b.allow()  # a new probe without waiting for the stale one to expire
    b.record_success()
    assert b.state == "closed"
    b.release_probe()  # no-op when closed
    assert b.state == "closed" and b.allow()
