import asyncio
import dataclasses
import time

import pytest

from a2agw.ops.bus import EventBus, GatewayEvent


def _ev(i: int) -> GatewayEvent:
    return GatewayEvent(kind="task.state", agent_id="agent", data={"i": i})


async def _consume(gen, n: int) -> list[GatewayEvent]:
    return [await gen.__anext__() for _ in range(n)]


def test_event_is_frozen_and_stamps_ts():
    before = time.time()
    ev = _ev(0)
    after = time.time()
    assert before <= ev.ts <= after
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.agent_id = "other"  # type: ignore[misc]


async def test_fanout_to_two_subscribers():
    bus = EventBus()
    a = bus.subscribe()
    b = bus.subscribe()
    ta = asyncio.create_task(_consume(a, 2))
    tb = asyncio.create_task(_consume(b, 2))
    await asyncio.sleep(0)  # both generators register their queues
    e1, e2 = _ev(1), _ev(2)
    bus.publish(e1)
    bus.publish(e2)
    assert await ta == [e1, e2]
    assert await tb == [e1, e2]
    assert bus.dropped == 0


async def test_slow_subscriber_drops_oldest_not_blocks():
    bus = EventBus()
    slow = bus.subscribe(maxsize=2)
    fast = bus.subscribe(maxsize=100)
    t_slow = asyncio.create_task(_consume(slow, 2))
    t_fast = asyncio.create_task(_consume(fast, 5))
    await asyncio.sleep(0)
    events = [_ev(i) for i in range(5)]
    for ev in events:
        bus.publish(ev)  # the slow subscriber is never awaited, so this cannot block
    # The slow queue holds only the newest two events; the three older ones were dropped.
    assert bus.dropped == 3
    assert await t_slow == events[3:]
    assert await t_fast == events


async def test_aclose_removes_subscriber():
    bus = EventBus()
    gen = bus.subscribe()
    task = asyncio.create_task(_consume(gen, 1))
    await asyncio.sleep(0)
    assert len(bus._subscribers) == 1
    e = _ev(1)
    bus.publish(e)
    assert await task == [e]
    await gen.aclose()
    assert len(bus._subscribers) == 0


async def test_cancelled_subscriber_is_removed():
    bus = EventBus()
    gen = bus.subscribe()
    task = asyncio.create_task(_consume(gen, 1))
    await asyncio.sleep(0)
    assert len(bus._subscribers) == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(bus._subscribers) == 0


async def test_recent_ring_buffer():
    bus = EventBus(recent_size=3)
    assert bus.recent() == []
    events = [_ev(i) for i in range(5)]
    for ev in events:
        bus.publish(ev)  # no subscribers: the ring buffer still records
    assert bus.recent() == events[2:]
    assert bus.recent(2) == events[3:]
    assert bus.recent(10) == events[2:]
    assert bus.recent(0) == []
