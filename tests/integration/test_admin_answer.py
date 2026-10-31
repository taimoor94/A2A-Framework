"""An operator answers an input-required task through the admin API."""

from __future__ import annotations

import asyncio

from a2a.types import GetTaskRequest, TaskState
from cascade_support import Fn, spec
from google.protobuf.json_format import MessageToDict

from a2agw.core.events import Done, NeedAuth, NeedInput

A = "/a2agw/admin"
CSRF = {"X-A2AGW-Admin": "1"}
COMPLETED = "TASK_STATE_COMPLETED"


class Asker:
    """LangGraph-style: interrupt with a question, then finish with the answer it got."""

    durable_sessions = False

    def __init__(self) -> None:
        self.seen: list[dict] = []

    async def run(self, ctx):
        self.seen.append({"text": ctx.text, "metadata": dict(ctx.metadata or {})})
        if not ctx.resumed:
            yield NeedInput(question="which colour?")
            return
        yield Done(text=f"painting it {ctx.text}")


async def until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.02)


async def _state(host, task_id: str) -> str:
    rows, _ = await host.index.list(limit=50)
    return next(r["state"] for r in rows if r["task_id"] == task_id)


async def test_operator_answer_resumes_input_required_task(env):
    asker = Asker()
    e = await env(spec("a", asker), admin_without_auth=True)
    events = await e.send("a", "paint the fence")
    task = events[-1].task
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    detail = (await e.hc.get(f"{A}/tasks/a/{task.id}")).json()
    assert detail["pending_prompt"] == "which colour?"

    r = await e.hc.post(f"{A}/tasks/a/{task.id}/answer", headers=CSRF, json={"text": "blue"})
    assert r.status_code == 200, r.text
    assert r.json()["state"] in {"TASK_STATE_WORKING", COMPLETED}

    async def done() -> bool:  # the owner's view (the index is written first)
        got = await e.client("a").get_task(GetTaskRequest(id=task.id))
        return got.status.state == TaskState.TASK_STATE_COMPLETED

    await until(done)
    # The task is still the owner's: the owner reads it, with the answer in its history.
    final = await e.client("a").get_task(GetTaskRequest(id=task.id))
    assert final.status.state == TaskState.TASK_STATE_COMPLETED
    assert [p.text for a in final.artifacts for p in a.parts] == ["painting it blue"]
    assert "blue" in [p.text for m in final.history for p in m.parts]
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "task.answer"})
    assert [(r["actor"], r["agent_id"], r["task_id"], r["outcome"]) for r in rows] == [
        ("anonymous", "a", task.id, "ok")
    ]
    # Not waiting any more: a second answer is refused.
    again = await e.hc.post(f"{A}/tasks/a/{task.id}/answer", headers=CSRF, json={"text": "red"})
    assert again.status_code == 409
    assert again.json() == {"error": "task is not waiting for input"}


async def test_answer_refused_for_auth_required(env):
    async def needs_auth(ctx):
        yield NeedAuth(scheme="oauth2", detail="sign in to the CRM")

    e = await env(spec("a", Fn(needs_auth)), admin_without_auth=True)
    task = (await e.send("a", "go"))[-1].task
    assert task.status.state == TaskState.TASK_STATE_AUTH_REQUIRED
    r = await e.hc.post(f"{A}/tasks/a/{task.id}/answer", headers=CSRF, json={"text": "pw"})
    assert r.status_code == 409 and r.json() == {"error": "task is not waiting for input"}
    assert await _state(e.host, task.id) == "TASK_STATE_AUTH_REQUIRED"
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "task.answer"})
    assert [r["outcome"] for r in rows] == ["refused"]


async def test_answer_metadata_names_operator(env):
    asker = Asker()
    e = await env(spec("a", asker), admin_without_auth=True)
    task = (await e.send("a", "paint the fence"))[-1].task
    r = await e.hc.post(f"{A}/tasks/a/{task.id}/answer", headers=CSRF, json={"text": "green"})
    assert r.status_code == 200

    async def done() -> bool:  # the owner's view (the index is written first)
        got = await e.client("a").get_task(GetTaskRequest(id=task.id))
        return got.status.state == TaskState.TASK_STATE_COMPLETED

    await until(done)
    assert asker.seen[-1] == {"text": "green", "metadata": {"a2agw.answered_by": "anonymous"}}
    final = await e.client("a").get_task(GetTaskRequest(id=task.id))
    answers = [
        MessageToDict(m.metadata) for m in final.history if any(p.text == "green" for p in m.parts)
    ]
    assert answers == [{"a2agw.answered_by": "anonymous"}]


async def test_answer_body_checked(env):
    e = await env(spec("a", Asker()), admin_without_auth=True)
    task = (await e.send("a", "x"))[-1].task
    url = f"{A}/tasks/a/{task.id}/answer"
    for body, field in (
        ({}, "text"),
        ({"text": 5}, "text"),
        ({"text": "x" * (32 * 1024 + 1)}, "text"),
        ({"text": "a\x00b"}, "text"),
        ({"text": "a", "extra": 1}, "extra"),
        ([1], "body"),
    ):
        r = await e.hc.post(url, headers=CSRF, json=body)
        assert r.status_code == 400, body
        assert r.json() == {"error": "bad request", "field": field}
    assert await _state(e.host, task.id) == "TASK_STATE_INPUT_REQUIRED"


async def test_concurrent_answers_resume_the_task_once(env):
    """A double click: two answers at once. One resumes the task, the other is refused."""
    asker = Asker()
    e = await env(spec("a", asker), admin_without_auth=True)
    task = (await e.send("a", "paint the fence"))[-1].task
    url = f"{A}/tasks/a/{task.id}/answer"
    r1, r2 = await asyncio.gather(
        e.hc.post(url, headers=CSRF, json={"text": "blue"}),
        e.hc.post(url, headers=CSRF, json={"text": "red"}),
    )
    assert sorted([r1.status_code, r2.status_code]) == [200, 409]
    refused = r1 if r1.status_code == 409 else r2
    assert refused.json() == {"error": "task is not waiting for input"}

    async def done() -> bool:
        got = await e.client("a").get_task(GetTaskRequest(id=task.id))
        return got.status.state == TaskState.TASK_STATE_COMPLETED

    await until(done)
    await asyncio.sleep(0.2)  # a second resume, if any, would have run by now
    assert [s["metadata"] for s in asker.seen].count({"a2agw.answered_by": "anonymous"}) == 1
    final = await e.client("a").get_task(GetTaskRequest(id=task.id))
    answered = [m for m in final.history if MessageToDict(m.metadata).get("a2agw.answered_by")]
    assert len(answered) == 1
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "task.answer"})
    assert sorted(r["outcome"] for r in rows) == ["ok", "refused"]
    assert e.host.answers_in_flight == set()
