import asyncio
import dataclasses
import time

import pytest

from a2agw.ops.bus import EventBus, GatewayEvent


def _ev(i: int) -> GatewayEvent:
    return GatewayEvent(kind="task.state", agent_id="agent", data={"i": i})


async def _take(sub, n: int) -> list[GatewayEvent]:
    return [await sub.__anext__() for _ in range(n)]


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
    e1, e2 = _ev(1), _ev(2)
    bus.publish(e1)
    bus.publish(e2)
    assert await _take(a, 2) == [e1, e2]
    assert await _take(b, 2) == [e1, e2]
    assert bus.dropped == 0


async def test_slow_subscriber_drops_oldest_not_blocks():
    bus = EventBus()
    slow = bus.subscribe(maxsize=2)
    fast = bus.subscribe(maxsize=100)
    events = [_ev(i) for i in range(5)]
    for ev in events:
        bus.publish(ev)  # the slow subscriber is never awaited, so this cannot block
    # The slow queue holds only the newest two events; the three older ones were dropped.
    assert bus.dropped == 3
    assert await _take(slow, 2) == events[3:]
    assert await _take(fast, 5) == events


async def test_event_published_right_after_subscribe_is_delivered():
    bus = EventBus()
    sub = bus.subscribe()
    e = _ev(1)
    bus.publish(e)  # no await between subscribe and publish
    assert await sub.__anext__() == e


async def test_replay_then_live_no_gap_no_dup():
    bus = EventBus()
    e1, e2, e3 = _ev(1), _ev(2), _ev(3)
    bus.publish(e1)
    bus.publish(e2)
    snapshot, sub = bus.subscribe_with_replay(n=50)
    bus.publish(e3)
    assert snapshot == [e1, e2]
    assert await _take(sub, 1) == [e3]
    assert len(bus._subscribers) == 1
    await sub.aclose()


async def test_aclose_unregisters_and_stops_iteration():
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish(_ev(1))
    await sub.aclose()
    assert len(bus._subscribers) == 0
    with pytest.raises(StopAsyncIteration):
        await sub.__anext__()
    await sub.aclose()  # idempotent


async def test_aclose_wakes_pending_iteration():
    bus = EventBus()
    sub = bus.subscribe()
    pending = asyncio.create_task(sub.__anext__())
    await asyncio.sleep(0)  # the task is now waiting for an event
    await sub.aclose()
    with pytest.raises(StopAsyncIteration):
        await pending


async def test_async_with_unregisters():
    bus = EventBus()
    e = _ev(1)
    async with bus.subscribe() as sub:
        assert len(bus._subscribers) == 1
        bus.publish(e)
        assert await sub.__anext__() == e
    assert len(bus._subscribers) == 0

    with pytest.raises(RuntimeError):
        async with bus.subscribe():
            raise RuntimeError("boom")
    assert len(bus._subscribers) == 0


def test_maxsize_zero_rejected():
    bus = EventBus()
    with pytest.raises(ValueError):
        bus.subscribe(maxsize=0)
    with pytest.raises(ValueError):
        bus.subscribe_with_replay(maxsize=0)
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


async def test_close_all_ends_open_and_new_subscriptions():
    """Finding 8: close_all wakes every pending iteration; until reopen, new ones end at once."""
    bus = EventBus()
    a, b = bus.subscribe(), bus.subscribe()
    pending = [asyncio.create_task(anext(s, None)) for s in (a, b)]
    await asyncio.sleep(0)
    bus.close_all()
    assert await asyncio.wait_for(asyncio.gather(*pending), 1) == [None, None]
    assert bus._subscribers == set()
    late = bus.subscribe()
    assert await asyncio.wait_for(anext(late, None), 1) is None
    bus.reopen()
    live = bus.subscribe()
    ev = GatewayEvent("partner.call", "x", {})
    bus.publish(ev)
    assert await anext(live) == ev
    await live.aclose()
