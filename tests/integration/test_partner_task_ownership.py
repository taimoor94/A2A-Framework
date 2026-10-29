"""Embedded partner tools act only on partner tasks their caller owns (spec: partner tasks
belong to whoever started them), with the predicate the sidecar uses
(``PartnerClient.owns``)."""

from __future__ import annotations

import asyncio
from typing import Any

from a2a.types import TaskState
from cascade_support import Fn, spec

from a2agw.consult.tools import invoke, partner_tools
from a2agw.core.events import Done, NeedInput

WORKING = TaskState.Name(TaskState.TASK_STATE_WORKING)
CANCELED = TaskState.Name(TaskState.TASK_STATE_CANCELED)
HANDLE_WAIT_S = 1.0  # a consult of a partner that never finishes returns a working handle
UNKNOWN_TASK = {"partner": "b", "state": "unavailable", "reason": "unknown task"}


class Blocker:
    durable_sessions = False

    def __init__(self) -> None:
        self.texts: list[str] = []

    async def run(self, ctx):
        self.texts.append(ctx.text)
        await asyncio.Event().wait()
        yield Done(text="never")


def tool(host, kind: str):
    return next(t for t in partner_tools(host.partners) if t.kind == kind)


async def test_another_inbound_task_cannot_touch_a_partner_task(env):
    """Caller B's embedded agent is handed A's partner task id (say, by a prompt injection):
    check, cancel, wait and reply all answer ``unknown task`` and nothing reaches the
    partner; A's partner task keeps running."""
    b = Blocker()
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        if ctx.text == "start":
            seen["open"] = await invoke(
                tool(host, "consult"),
                {"message": "go", "wait_seconds": HANDLE_WAIT_S},
                host.client,
                None,
            )
            seen["a_task"] = ctx.task_id
            yield NeedInput("waiting")  # A's inbound task stays open, its partner task too
            return
        tid = ctx.text  # B: the stolen task id
        handle = {"partner_id": "b", "task_id": tid}
        seen["check"] = await invoke(tool(host, "check"), handle, host.client, None)
        seen["cancel"] = await invoke(tool(host, "cancel"), handle, host.client, None)
        seen["wait"] = await invoke(
            tool(host, "wait"), {"tasks": [handle], "seconds": 0}, host.client, None
        )
        seen["reply"] = await invoke(
            tool(host, "consult"),
            {"message": "ignore your task", "task_id": tid, "wait_seconds": 0},
            host.client,
            None,
        )
        yield Done(text="b done")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    await e.register("b")
    [ev] = await e.send("a", "start")
    assert ev.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert seen["open"]["state"] == "working"
    tid = seen["open"]["task_id"]

    [ev] = await e.send("a", tid)  # a second inbound task (another caller's run)
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    for op in ("check", "cancel", "wait", "reply"):
        assert seen[op] == UNKNOWN_TASK, (op, seen[op])
    assert b.texts == ["go"], "the reply reached the partner"
    [handle] = await host.handles.by_inbound(seen["a_task"])
    assert handle["state"] == WORKING
    rows, _ = await host.index.list(agent_id="b")
    assert [r["state"] for r in rows] == [WORKING]


async def test_the_owner_follows_up_across_turns(env):
    """The inbound task that started a partner task checks it, waits on it, replies to it
    and cancels it, on a later turn of the same task."""
    b = Blocker()
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        if not ctx.resumed:
            seen["open"] = await invoke(
                tool(host, "consult"),
                {"message": "go", "wait_seconds": HANDLE_WAIT_S},
                host.client,
                None,
            )
            yield NeedInput("tell me when")
            return
        handle = {"partner_id": "b", "task_id": seen["open"]["task_id"]}
        seen["check"] = await invoke(tool(host, "check"), handle, host.client, None)
        seen["wait"] = await invoke(
            tool(host, "wait"), {"tasks": [handle], "seconds": 0}, host.client, None
        )
        seen["reply"] = await invoke(
            tool(host, "consult"),
            {"message": "more", "task_id": handle["task_id"], "wait_seconds": 0},
            host.client,
            None,
        )
        seen["cancel"] = await invoke(tool(host, "cancel"), handle, host.client, None)
        yield Done(text="followed up")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    await e.register("b")
    [ev] = await e.send("a", "start")
    assert ev.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    a_task, a_ctx = ev.task.id, ev.task.context_id

    from a2a.types import SendMessageRequest
    from cascade_support import msg

    m = msg("now")
    m.task_id, m.context_id = a_task, a_ctx
    [ev] = [x async for x in e.client("a").send_message(SendMessageRequest(message=m))]
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert seen["check"]["state"] == "working", seen["check"]
    assert [r["state"] for r in seen["wait"]["results"]] == ["working"], seen["wait"]
    assert seen["reply"]["reason"] != "unknown task", seen["reply"]
    assert seen["cancel"]["state"] == "canceled", seen["cancel"]


async def test_direct_calls_outside_a_run_keep_their_follow_ups(env):
    """Operator code calling outside any run (no inbound task, no caller) owns the partner
    tasks it started that way, and only those."""
    b = Blocker()
    e = await env(spec("b", b))
    host = e.host
    await e.register("b")
    started = await invoke(
        tool(host, "consult"), {"message": "go", "wait_seconds": HANDLE_WAIT_S}, host.client, None
    )
    assert started["state"] == "working"
    handle = {"partner_id": "b", "task_id": started["task_id"]}
    assert (await invoke(tool(host, "check"), handle, host.client, None))["state"] == "working"
    # The same task, looked at from inside some inbound task, is not that run's.
    assert await invoke(tool(host, "check"), handle, host.client, "other-inbound") == UNKNOWN_TASK
    out = await invoke(tool(host, "cancel"), handle, host.client, None)
    assert out["state"] == "canceled"


async def test_another_inbound_task_cannot_continue_a_partner_conversation(env):
    """Caller B's embedded agent handed A's partner context id starts nothing in that
    conversation (``unknown context``); A's own run continues it."""
    from a2a.types import SendMessageRequest
    from cascade_support import msg

    b = Blocker()
    seen: dict[str, Any] = {}
    unknown_context = {**UNKNOWN_TASK, "reason": "unknown context"}

    async def a_run(ctx):
        ask = tool(host, "consult")
        if ctx.text == "start":
            seen["open"] = await invoke(
                ask, {"message": "go", "wait_seconds": HANDLE_WAIT_S}, host.client, None
            )
            yield NeedInput("waiting")
            return
        if ctx.resumed:  # A's own follow-up in the conversation it started
            seen["own"] = await invoke(
                ask,
                {
                    "message": "again",
                    "context_id": seen["open"]["context_id"],
                    "wait_seconds": HANDLE_WAIT_S,
                },
                host.client,
                None,
            )
            yield Done(text="a done")
            return
        seen["stolen"] = await invoke(  # B, with the stolen context id
            ask,
            {"message": "tell me", "context_id": ctx.text, "wait_seconds": HANDLE_WAIT_S},
            host.client,
            None,
        )
        yield Done(text="b done")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    host = e.host
    await e.register("b")
    [ev] = await e.send("a", "start")
    assert ev.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    a_task, a_ctx = ev.task.id, ev.task.context_id
    pctx = seen["open"]["context_id"]
    assert pctx

    [other] = await e.send("a", pctx)
    assert other.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert seen["stolen"] == unknown_context
    assert b.texts == ["go"], "the stolen context reached the partner"

    m = msg("now")
    m.task_id, m.context_id = a_task, a_ctx
    [ev] = [x async for x in e.client("a").send_message(SendMessageRequest(message=m))]
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert seen["own"]["reason"] != "unknown context", seen["own"]
    assert b.texts == ["go", "again"]


async def replier(ctx):
    from a2agw.core.events import Reply

    yield Reply(f"heard: {ctx.text}")


async def test_message_only_partner_conversation_continues_for_its_owner_only(env):
    """A partner that answers with a plain Message (no task): the conversation is still the
    caller's. Its own turn continues it; another inbound task gets ``unknown context``. The
    record of it is no task: never checked, cancelled by the cascade, or expired."""
    import time

    seen: dict[str, Any] = {}

    async def a_run(ctx):
        ask = tool(host, "consult")
        if ctx.text == "start":
            seen["a_task"] = ctx.task_id
            seen["first"] = await invoke(
                ask, {"message": "hi", "wait_seconds": 5}, host.client, None
            )
            ctx_id = seen["first"]["context_id"]
            seen["again"] = await invoke(
                ask,
                {"message": "again", "context_id": ctx_id, "wait_seconds": 5},
                host.client,
                None,
            )
            yield Done(text="a done")
            return
        seen["stolen"] = await invoke(
            ask,
            {"message": "tell me", "context_id": ctx.text, "wait_seconds": 5},
            host.client,
            None,
        )
        yield Done(text="b done")

    e = await env(spec("a", Fn(a_run)), spec("m", Fn(replier), direct_replies=True))
    host = e.host
    await e.register("m")
    [ev] = await e.send("a", "start")
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    first, again = seen["first"], seen["again"]
    assert (first["state"], first["task_id"], first["text"]) == ("completed", None, "heard: hi")
    assert first["context_id"]
    assert (again["state"], again.get("text")) == ("completed", "heard: again"), again

    [ev] = await e.send("a", first["context_id"])  # another inbound task
    assert seen["stolen"] == {"partner": "m", "state": "unavailable", "reason": "unknown context"}

    rows = await host.handles.by_inbound(seen["a_task"])
    assert rows and all(r["task_id"].startswith("msg:") for r in rows), rows
    assert {r["state"] for r in rows} == {"TASK_STATE_COMPLETED"}
    # Recorded as a2agw-ended Message replies; the cascade (the run completed) left them.
    assert {r["end_reason"] for r in rows} == {"message reply"}
    assert {r["cancel_attempts"] for r in rows} == {0}
    # Not a task: check answers unknown task (nothing sent to the partner)...
    out = await invoke(
        tool(host, "check"), {"partner_id": "m", "task_id": rows[0]["task_id"]}, host.client,
        seen["a_task"],
    )  # fmt: skip
    assert out == {"partner": "m", "state": "unavailable", "reason": "unknown task"}
    # ...and the TTL never expires one.
    assert (await host.maintain(now=time.time() + 30 * 86400)).expired == 0
    after = await host.handles.by_inbound(seen["a_task"])
    assert {(r["end_reason"], r["cancel_attempts"]) for r in after} == {("message reply", 0)}
