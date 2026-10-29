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
