"""Inbound and outbound joined: cancellation cascade, restart cleanup and the re-entry guard."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from a2a.server.tasks import DatabaseTaskStore
from a2a.types import (
    CancelTaskRequest,
    SendMessageRequest,
    TaskState,
)
from cascade_support import Fn, msg, spec
from google.protobuf.json_format import MessageToDict

from a2agw.consult.tools import invoke, partner_tools
from a2agw.context.call_context import EXTENSION_URI, current_inbound_task, current_principal
from a2agw.core.events import Done, Reply

CANCELED = TaskState.Name(TaskState.TASK_STATE_CANCELED)
REJECTED = TaskState.Name(TaskState.TASK_STATE_REJECTED)


class Blocker:
    durable_sessions = False

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def run(self, ctx):
        self.started.set()
        await asyncio.Event().wait()
        yield Done(text="never")


async def echo(ctx):
    yield Done(text=f"echo: {ctx.text}")


async def until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.02)


# -- cancellation cascade --------------------------------------------------------------


async def test_cancel_inbound_cancels_partner_task(env):
    b = Blocker()
    seen: dict[str, Any] = {}
    consulted = asyncio.Event()

    async def a_run(ctx):
        seen["result"] = await host.client.consult("b", "go", wait_seconds=0.2)
        consulted.set()
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    await e.register("b")

    events = await e.send("a", "start", return_immediately=True)
    a_task = events[0].task.id
    await asyncio.wait_for(consulted.wait(), 5)
    b_task = seen["result"].task_id
    assert seen["result"].state == "working" and b_task

    await e.client("a").cancel_task(CancelTaskRequest(id=a_task))

    async def b_canceled() -> bool:
        rows, _ = await host.index.list(agent_id="b")
        return [r["state"] for r in rows if r["task_id"] == b_task] == [CANCELED]

    await until(b_canceled)
    check = await host.client.check("b", b_task)
    assert check.state == "canceled"
    [handle] = await host.handles.by_inbound(a_task)
    assert handle["state"] == CANCELED


def delay_first_response(app, agent_id: str, delay: float):
    """Holds the start of every POST response from ``agent_id`` for ``delay`` seconds."""

    async def wrapped(scope, receive, send):
        async def send_later(message):
            if (
                message["type"] == "http.response.start"
                and scope["method"] == "POST"
                and scope["path"].startswith(f"/agents/{agent_id}")
            ):
                await asyncio.sleep(delay)
            await send(message)

        await app(scope, receive, send_later)

    return wrapped


async def test_cancel_before_first_event_cancels_partner_task(env):
    """A is cancelled after B's task exists but before A has seen any response from B, so
    no handle is recorded yet: the cancelled consult itself must cancel B's task."""
    b = Blocker()

    async def a_run(ctx):
        await host.client.consult("b", "go", wait_seconds=5)
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    e.partner_hc._transport.apps["t"] = delay_first_response(host.app(), "b", 0.5)
    await e.register("b")

    events = await e.send("a", "start", return_immediately=True)
    a_task = events[0].task.id
    await asyncio.wait_for(b.started.wait(), 5)
    assert await host.handles.by_inbound(a_task) == []  # still inside the window
    await e.client("a").cancel_task(CancelTaskRequest(id=a_task))

    async def b_canceled() -> bool:
        rows, _ = await host.index.list(agent_id="b")
        return [r["state"] for r in rows] == [CANCELED]

    await until(b_canceled)
    [handle] = await host.handles.by_inbound(a_task)
    assert handle["state"] == CANCELED


async def test_cancel_before_first_event_with_slow_partner_persist(env, monkeypatch):
    """Regression (final review, finding 1): B persists its task only after A is cancelled,
    so a single ``list_tasks`` by context finds nothing. The cleanup must still cancel B's
    task (via B's own first response, or by retrying the lookup) and record the handle."""
    real_save = DatabaseTaskStore.save

    async def slow_save(self, task, *args, **kwargs):
        if self.task_model.__tablename__ == "tasks_b":
            await asyncio.sleep(0.3)
        return await real_save(self, task, *args, **kwargs)

    monkeypatch.setattr(DatabaseTaskStore, "save", slow_save)
    b = Blocker()

    async def a_run(ctx):
        await host.client.consult("b", "go", wait_seconds=5)
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    e.partner_hc._transport.apps["t"] = delay_first_response(host.app(), "b", 0.5)
    await e.register("b")

    events = await e.send("a", "start", return_immediately=True)
    a_task = events[0].task.id
    await asyncio.wait_for(b.started.wait(), 5)
    await e.client("a").cancel_task(CancelTaskRequest(id=a_task))

    async def b_canceled() -> bool:
        rows, _ = await host.index.list(agent_id="b")
        return [r["state"] for r in rows] == [CANCELED]

    await until(b_canceled)

    async def handle_canceled() -> bool:
        rows = await host.handles.by_inbound(a_task)
        return [r["state"] for r in rows] == [CANCELED]

    await until(handle_canceled)


async def test_shutdown_drains_cleanup_before_engine_dispose(env, monkeypatch):
    """Finding 2: a cancellation cleanup started just before shutdown still cancels the
    partner task and records its handle before the host disposes its engine."""
    p = Blocker()
    partner = await env(spec("p", p), db="partner.db")
    slow_p = delay_first_response(partner.host.app(), "p", 0.3)
    a = await env(spec("a", Fn(echo)), apps={"t": slow_p})
    host = a.host
    await host.partners.add_from_card("p", MessageToDict(partner.host.cards["p"]), "internal")

    t = asyncio.create_task(host.client.consult("p", "go", wait_seconds=5, inbound_task_id="in-s"))
    await asyncio.wait_for(p.started.wait(), 5)
    t.cancel()  # starts the cleanup ...
    await asyncio.sleep(0.02)
    t.cancel()  # ... and stops waiting for it: the cleanup runs in the background
    with pytest.raises(asyncio.CancelledError):
        await t
    assert host.client._cleanups

    at_dispose: dict[str, Any] = {}
    engine = host.engine
    real_dispose = type(engine).dispose

    async def dispose(self, *args, **kwargs):
        if self is engine:
            at_dispose["handles"] = await host.handles.by_inbound("in-s")
            at_dispose["cleanups"] = len(host.client._cleanups)
        return await real_dispose(self, *args, **kwargs)

    monkeypatch.setattr(type(engine), "dispose", dispose)
    await host.shutdown()
    assert at_dispose["cleanups"] == 0
    assert [h["state"] for h in at_dispose["handles"]] == [CANCELED]
    rows, _ = await partner.host.index.list(agent_id="p")
    assert [r["state"] for r in rows] == [CANCELED]


async def test_restart_cancels_outbound_of_failed_inbound(env, tmp_path):
    p = Blocker()
    partner = await env(spec("p", p), db="partner.db")
    consulted = asyncio.Event()
    partners_path = tmp_path / "partners.yaml"

    async def a_run(ctx):
        res = await a1.host.client.consult("p", "go", wait_seconds=0.2)
        assert res.state == "working"
        consulted.set()
        await asyncio.Event().wait()
        yield Done(text="never")

    a1 = await env(
        spec("a", Fn(a_run)), apps={"t": partner.host.app()}, partners_path=partners_path
    )
    await a1.host.partners.add_from_card("p", MessageToDict(partner.host.cards["p"]), "internal")
    assert partners_path.exists()
    events = await a1.send("a", "start", return_immediately=True)
    a_task = events[0].task.id
    await asyncio.wait_for(consulted.wait(), 5)
    [handle] = await a1.host.handles.by_inbound(a_task)
    await a1.host.shutdown()  # the gateway goes down with the inbound task still WORKING

    a2 = await env(spec("a", Fn(echo)), apps={"t": partner.host.app()}, partners_path=partners_path)
    report = a2.host.last_recovery
    assert report is not None
    assert report.failed == [a_task]
    assert report.outbound_cancelled == 1 and report.cancel_errors == []
    rows, _ = await partner.host.index.list(agent_id="p")
    assert [(r["task_id"], r["state"]) for r in rows] == [(handle["task_id"], CANCELED)]


# -- re-entry --------------------------------------------------------------------------


@pytest.mark.parametrize("allow", [False, True])
async def test_reentry_through_tools(env, allow):
    """A -> B -> A through the projected partner tools. Rejected unless A allows re-entry
    (under R6 the path-based cycle check catches it first)."""
    results: dict[str, Any] = {}

    def tool(name: str):
        return next(t for t in partner_tools(host.partners) if t.name == name)

    async def a_run(ctx):
        if ctx.text == "start":
            results["a"] = await invoke(
                tool("ask_b"), {"message": "help", "wait_seconds": 5}, host.client, None
            )
            yield Done(text="outer done")
        else:
            yield Done(text="nested ok")

    async def b_run(ctx):
        results["b"] = await invoke(
            tool("ask_a"), {"message": "nested", "wait_seconds": 5}, host.client, None
        )
        yield Done(text="b done")

    e = await env(spec("a", Fn(a_run), allow_reentry=allow), spec("b", Fn(b_run)))
    host = e.host
    await e.register("a", "b")

    events = await e.send("a", "start")
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert results["a"]["state"] == "completed"
    rejected, _ = await host.index.list(agent_id="a", state=REJECTED)
    if allow:
        assert results["b"]["state"] == "completed"
        assert results["b"]["text"] == "nested ok"
        assert rejected == []
    else:
        assert results["b"]["state"] == "rejected"
        assert len(rejected) == 1


@pytest.mark.parametrize("allow", [False, True])
async def test_reentry_via_origin_preserving_partner(env, allow):
    """P keeps the call context's origin but strips A from its path: only the origin shows
    that A is being entered again inside its own chain."""
    results: dict[str, Any] = {}

    async def a_run(ctx):
        if ctx.text == "start":
            results["a"] = await host.client.consult("p", "help", wait_seconds=5)
            yield Done(text="outer done")
        else:
            yield Done(text="nested ok")

    async def p_run(ctx):
        # A real call back takes a network round trip; here, wait until A has recorded its
        # handle for this task so A is visibly blocked downstream.
        async def recorded() -> bool:
            return await host.handles.get("p", ctx.task_id) is not None

        await until(recorded)
        cc = dict(ctx.metadata[EXTENSION_URI])
        cc["path"] = [x for x in cc["path"] if x != "a"]
        back = msg("nested")
        back.metadata.update({EXTENSION_URI: cc})
        results["sent_path"] = cc["path"]
        [ev] = [ev async for ev in e.client("a").send_message(SendMessageRequest(message=back))]
        results["nested"] = ev.task
        yield Done(text="p done")

    e = await env(spec("a", Fn(a_run), allow_reentry=allow), spec("p", Fn(p_run)))
    host = e.host
    await e.register("p")

    events = await e.send("a", "start")
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert results["a"].state == "completed"
    assert "a" not in results["sent_path"]
    nested = results["nested"]
    if allow:
        assert nested.status.state == TaskState.TASK_STATE_COMPLETED
    else:
        assert nested.status.state == TaskState.TASK_STATE_REJECTED
        assert nested.status.message.parts[0].text == "re-entry"


async def test_same_host_a_to_b_not_reentry(env):
    results: dict[str, Any] = {}

    async def a_run(ctx):
        results["b"] = await host.client.consult("b", "hi", wait_seconds=5)
        yield Done(text="a done")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)))
    host = e.host
    await e.register("b")
    events = await e.send("a", "start")
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert results["b"].state == "completed"
    assert results["b"].text == "echo: hi"


class Barrier:
    """Holds every caller until ``n`` have arrived, so the calls overlap. ``first_in`` lets a
    test send the next call only once the first is running (its origin is in the index)."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.arrived = 0
        self.first_in = asyncio.Event()
        self.all_in = asyncio.Event()

    async def wait(self) -> None:
        self.arrived += 1
        self.first_in.set()
        if self.arrived >= self.n:
            self.all_in.set()
        await asyncio.wait_for(self.all_in.wait(), 5)


async def test_parallel_fanout_same_agent_admitted(env):
    barrier = Barrier(2)
    results: dict[str, Any] = {}

    async def orch_run(ctx):
        one = asyncio.create_task(host.client.consult("leaf", "one", wait_seconds=5))
        await asyncio.wait_for(barrier.first_in.wait(), 5)
        two = await host.client.consult("leaf", "two", wait_seconds=5)
        results["leaf"] = [await one, two]
        yield Done(text="orch done")

    async def leaf_run(ctx):
        await barrier.wait()
        yield Done(text=f"leaf: {ctx.text}")

    e = await env(spec("orch", Fn(orch_run)), spec("leaf", Fn(leaf_run)))
    host = e.host
    await e.register("leaf")
    events = await e.send("orch", "start")
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert [r.state for r in results["leaf"]] == ["completed", "completed"]
    assert sorted(r.text for r in results["leaf"]) == ["leaf: one", "leaf: two"]
    rejected, _ = await host.index.list(state=REJECTED)
    assert rejected == []


async def test_diamond_admitted(env):
    """PM -> arch -> sec and PM -> rev -> sec in one origin, with both sec calls overlapping."""
    barrier = Barrier(2)
    results: dict[str, Any] = {}

    async def pm_run(ctx):
        results["pm"] = await asyncio.gather(
            host.client.consult("arch", "design", wait_seconds=5),
            host.client.consult("rev", "review", wait_seconds=5),
        )
        yield Done(text="pm done")

    def middle(name: str):
        async def run(ctx):
            if name == "rev":  # reach sec only while arch's call to it is running
                await asyncio.wait_for(barrier.first_in.wait(), 5)
            res = await host.client.consult("sec", name, wait_seconds=5)
            results[name] = res
            yield Done(text=f"{name}: {res.state}")

        return run

    async def sec_run(ctx):
        await barrier.wait()
        yield Done(text=f"sec ok for {ctx.text}")

    e = await env(
        spec("pm", Fn(pm_run)),
        spec("arch", Fn(middle("arch"))),
        spec("rev", Fn(middle("rev"))),
        spec("sec", Fn(sec_run)),
    )
    host = e.host
    await e.register("arch", "rev", "sec")
    events = await e.send("pm", "start")
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert results["arch"].state == "completed" and results["rev"].state == "completed"
    assert [r.text for r in results["pm"]] == ["arch: completed", "rev: completed"]
    rows, _ = await host.index.list(agent_id="sec")
    assert len({r["origin"] for r in rows}) == 1  # really one chain
    rejected, _ = await host.index.list(state=REJECTED)
    assert rejected == []


async def test_contextvars_supply_inbound_and_caller(env):
    seen: dict[str, Any] = {}

    class RecordingCredentials:
        async def headers(self, partner, caller):
            seen["caller"] = caller
            return {}

    async def a_run(ctx):
        seen["task_id"] = ctx.task_id
        seen["principal"] = ctx.principal
        res = await host.client.consult("b", "hi", wait_seconds=5)
        assert res.state == "completed"
        yield Done(text="a done")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)), credentials=RecordingCredentials())
    host = e.host
    await e.register("b")
    await e.send("a", "start")
    [handle] = await host.handles.by_inbound(seen["task_id"])
    assert handle["partner_id"] == "b"
    assert seen["principal"] is not None
    assert seen["caller"] == seen["principal"]


async def test_inbound_contextvars_not_leaked(env):
    inside = asyncio.Event()
    release = asyncio.Event()
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        seen["a"] = (current_inbound_task.get(), ctx.task_id)
        inside.set()
        await release.wait()
        yield Done(text="a done")

    async def b_run(ctx):  # an unrelated request running while A is inside its adapter
        seen["b"] = (current_inbound_task.get(), ctx.task_id)
        yield Done(text="b done")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    a_send = asyncio.create_task(e.send("a", "start"))
    await asyncio.wait_for(inside.wait(), 5)
    assert current_inbound_task.get() is None and current_principal.get() is None
    await e.send("b", "other")
    release.set()
    await a_send
    assert seen["a"][0] == seen["a"][1]
    assert seen["b"][0] == seen["b"][1] != seen["a"][1]
    assert current_inbound_task.get() is None and current_principal.get() is None


# -- admin -----------------------------------------------------------------------------


async def test_admin_partners_through_real_wiring(env):
    e = await env(spec("b", Fn(echo)), admin_without_auth=True)
    await e.register("b")
    res = await e.host.client.consult("b", "hi", wait_seconds=5)
    assert res.state == "completed"
    r = await e.hc.get("/a2agw/admin/partners")
    assert r.status_code == 200
    [row] = r.json()
    assert row["id"] == "b"
    assert row["tier"] == "internal"
    assert row["status"] == "active"
    assert row["breaker_state"] == "closed"
    assert row["in_flight"] == 0


# -- direct replies ---------------------------------------------------------------------


async def test_reentry_detected_for_direct_replies_agent(env):
    """As test_reentry_via_origin_preserving_partner, for an agent whose outer turn is still
    pending a direct reply (no A2A task yet): the index row written at admission still shows
    it blocked downstream."""
    results: dict[str, Any] = {}

    async def a_run(ctx):
        if ctx.text == "start":
            results["a"] = await host.client.consult("p", "help", wait_seconds=5)
            yield Reply("outer done")
        else:
            yield Reply("nested ok")

    async def p_run(ctx):
        async def recorded() -> bool:
            return await host.handles.get("p", ctx.task_id) is not None

        await until(recorded)
        cc = dict(ctx.metadata[EXTENSION_URI])
        cc["path"] = [x for x in cc["path"] if x != "a"]
        back = msg("nested")
        back.metadata.update({EXTENSION_URI: cc})
        [ev] = [ev async for ev in e.client("a").send_message(SendMessageRequest(message=back))]
        results["nested"] = ev
        yield Done(text="p done")

    e = await env(spec("a", Fn(a_run), direct_replies=True), spec("p", Fn(p_run)))
    host = e.host
    await e.register("p")

    [outer] = await e.send("a", "start")
    assert outer.WhichOneof("payload") == "message"
    assert results["a"].state == "completed"
    nested = results["nested"]
    assert nested.WhichOneof("payload") == "task"
    assert nested.task.status.state == TaskState.TASK_STATE_REJECTED
    assert nested.task.status.message.parts[0].text == "re-entry"


async def test_direct_reply_drops_index_row_and_cancels_partner_work(env):
    b = Blocker()
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        seen["a_task"] = ctx.task_id
        seen["result"] = await host.client.consult("b", "go", wait_seconds=0.2)
        yield Reply("answered without waiting for b")

    e = await env(spec("a", Fn(a_run), direct_replies=True), spec("b", b))
    host = e.host
    await e.register("b")

    [ev] = await e.send("a", "start")
    assert ev.WhichOneof("payload") == "message"
    assert seen["result"].state == "working"
    b_task = seen["result"].task_id

    async def b_canceled() -> bool:
        rows, _ = await host.index.list(agent_id="b")
        return [r["state"] for r in rows if r["task_id"] == b_task] == [CANCELED]

    await until(b_canceled)
    rows, _ = await host.index.list(agent_id="a")
    assert rows == []
    [handle] = await host.handles.by_inbound(seen["a_task"])
    assert handle["state"] == CANCELED
