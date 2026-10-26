from __future__ import annotations

import asyncio

import pytest

from a2agw.adapters._contexts import ContextRegistry


class State:
    def __init__(self, key: str) -> None:
        self.key = key


async def settle() -> None:
    """Let every ready task run (no timed sleep)."""
    for _ in range(20):
        await asyncio.sleep(0)


async def test_entry_made_once_and_kept_per_key():
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=8)
    async with reg.turn("a") as first:
        assert first.key == "a"
    async with reg.turn("a") as again:
        assert again is first
    assert "a" in reg and reg["a"] is first and len(reg) == 1
    assert "b" not in reg


async def test_eviction_cap_drops_least_recently_used():
    evicted: list[tuple[str, str]] = []
    reg: ContextRegistry[str, State] = ContextRegistry(
        State, max_size=2, on_evict=lambda k, v: evicted.append((k, v.key))
    )
    for key in ("a", "b", "c"):
        async with reg.turn(key):
            pass
    assert list(reg) == ["b", "c"] and evicted == [("a", "a")]
    async with reg.turn("b"):  # "b" becomes most recently used
        pass
    async with reg.turn("d"):
        pass
    assert list(reg) == ["b", "d"] and evicted[-1] == ("c", "c")


async def test_no_eviction_while_a_turn_is_in_flight():
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=1)
    release = asyncio.Event()
    entered = asyncio.Event()

    async def busy() -> None:
        async with reg.turn("busy"):
            entered.set()
            await release.wait()

    task = asyncio.create_task(busy())
    await entered.wait()
    for key in ("x", "y"):
        async with reg.turn(key):
            pass
    # Over the cap, but the busy context is kept; the idle ones went.
    assert list(reg) == ["busy", "y"]
    release.set()
    await task


async def test_no_eviction_of_a_context_with_a_queued_waiter():
    # A turn waiting on the lock counts as in flight: its context is not dropped while it
    # waits, nor in the moment between the holder releasing the lock and the waiter waking
    # (the lock is free then, but the waiter is about to run on this entry).
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=1)
    seen: list[State] = []

    async def wait() -> None:
        async with reg.turn("c") as st:
            seen.append(st)

    holding = reg.turn("c")
    seen.append(await holding.__aenter__())
    waiter = asyncio.create_task(wait())
    await settle()  # the waiter is queued on the lock
    async with reg.turn("other"):
        pass
    assert "c" in reg  # held, and awaited
    await holding.__aexit__(None, None, None)
    # The lock is released and the waiter woken, but it has not run yet (no await since).
    assert not waiter.done()
    async with reg.turn("other2"):
        pass
    assert "c" in reg
    await waiter
    assert len(seen) == 2 and seen[0] is seen[1] is reg["c"]  # the live entry, not an orphan
    async with reg.turn("other3"):
        pass
    assert "c" not in reg  # idle now: evictable


async def test_turns_on_one_key_are_serialised():
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=8)
    release = asyncio.Event()
    entered = asyncio.Event()
    order: list[str] = []

    async def one() -> None:
        async with reg.turn("k"):
            order.append("one-start")
            entered.set()
            await release.wait()
            order.append("one-end")

    async def two() -> None:
        async with reg.turn("k"):
            order.append("two")

    t1 = asyncio.create_task(one())
    await entered.wait()
    t2 = asyncio.create_task(two())
    async with reg.turn("elsewhere"):  # another key is not blocked
        order.append("elsewhere")
    await settle()
    assert order == ["one-start", "elsewhere"] and not t2.done()
    release.set()
    await asyncio.gather(t1, t2)
    assert order == ["one-start", "elsewhere", "one-end", "two"]


async def test_cancelled_waiter_releases_its_claim():
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=1)
    release = asyncio.Event()
    entered = asyncio.Event()

    async def hold() -> None:
        async with reg.turn("c"):
            entered.set()
            await release.wait()

    async def wait() -> None:
        async with reg.turn("c"):
            raise AssertionError("never entered")

    holder = asyncio.create_task(hold())
    await entered.wait()
    waiter = asyncio.create_task(wait())
    await settle()
    waiter.cancel()
    await asyncio.wait({waiter})
    release.set()
    await holder
    async with reg.turn("other"):
        pass
    assert list(reg) == ["other"]  # no claim leaked: "c" was idle and evictable


async def test_error_in_a_turn_releases_it():
    reg: ContextRegistry[str, State] = ContextRegistry(State, max_size=1)
    with pytest.raises(RuntimeError):
        async with reg.turn("c"):
            raise RuntimeError("boom")
    async with reg.turn("c"):  # the lock was released
        pass
    async with reg.turn("d"):
        pass
    assert list(reg) == ["d"]


def test_max_size_must_be_positive():
    with pytest.raises(ValueError, match="max_size"):
        ContextRegistry(State, max_size=0)


def test_context_key_is_per_caller_and_injective():
    from adapters.contract import make_ctx

    from a2agw.adapters._contexts import context_key, owner_id
    from a2agw.security.principal import Principal

    def key(owner: str | None, cid: str) -> str:
        ctx = make_ctx("x", context_id=cid)
        ctx.principal = None if owner is None else Principal(owner, "api_key", frozenset())
        return context_key(ctx)

    anon = make_ctx("x", context_id="c")
    assert owner_id(anon) == "anonymous" and key(None, "c") == "anonymous\x1fc"
    assert key("key:alice", "c") == "key:alice\x1fc"
    assert key("key:alice", "c") != key("key:bob", "c")
    # A separator inside the owner cannot make two pairs collide.
    assert key("a\x1fb", "c") != key("a", "b\x1fc")
    assert key("a\\x1fb", "c") != key("a\x1fb", "c")
