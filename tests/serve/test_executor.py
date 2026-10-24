"""AdapterExecutor, driven end to end through DefaultRequestHandler, Starlette and the SDK client."""

from __future__ import annotations

import asyncio
import logging
import uuid

from a2a.server.routes import DefaultServerCallContextBuilder
from a2a.types import (
    CancelTaskRequest,
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    StreamResponse,
    Task,
    TaskState,
)
from google.protobuf.json_format import MessageToDict

from a2agw.context.call_context import CallContext, current_call
from a2agw.core.events import ArtifactChunk, Done, NeedInput, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.security.principal import Principal, PrincipalUser

ST = TaskState.Name


class AliceContextBuilder(DefaultServerCallContextBuilder):
    """Authenticates every request as the API-key principal ``key:alice``."""

    def build_user(self, request):
        return PrincipalUser(Principal(id="key:alice", kind="api_key", scopes=frozenset()))


def user_msg(text: str, *, task_id: str = "", context_id: str = "", metadata=None) -> Message:
    msg = Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text=text)],
        task_id=task_id,
        context_id=context_id,
    )
    if metadata is not None:
        msg.metadata.update(metadata)
    return msg


def _task_id(ev: StreamResponse) -> str:
    kind = ev.WhichOneof("payload")
    return ev.task.id if kind == "task" else getattr(ev, kind).task_id


async def send(client, msg: Message, **config) -> tuple[list[StreamResponse], Task]:
    req = SendMessageRequest(message=msg)
    if config:
        req.configuration.CopyFrom(SendMessageConfiguration(**config))
    events = [ev async for ev in client.send_message(req)]
    task = await client.get_task(GetTaskRequest(id=_task_id(events[0])))
    return events, task


def status_text(task: Task) -> str:
    return "\n".join(p.text for p in task.status.message.parts)


class EchoAdapter:
    durable_sessions = False

    def __init__(self) -> None:
        self.seen: list[InboundContext] = []
        self.calls: list[CallContext | None] = []

    async def run(self, ctx: InboundContext):
        self.seen.append(ctx)
        self.calls.append(current_call.get())
        yield Done(text=f"echo: {ctx.text}")


async def test_text_echo_completes_streaming_and_blocking(make_server):
    adapter = EchoAdapter()
    h = await make_server(adapter)

    for streaming in (True, False):
        client = h.client(streaming=streaming)
        events, task = await send(client, user_msg("hello"))
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        [artifact] = task.artifacts
        assert artifact.name == "result"
        assert [p.text for p in artifact.parts] == ["echo: hello"]
        kinds = [ev.WhichOneof("payload") for ev in events]
        if streaming:
            assert "artifact_update" in kinds
            assert events[-1].status_update.status.state == TaskState.TASK_STATE_COMPLETED
        else:
            assert kinds == ["task"]
            assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED

    # The adapter ran with the gateway's own call context set on current_call.
    assert len(adapter.seen) == 2
    for ctx, cc in zip(adapter.seen, adapter.calls, strict=True):
        assert ctx.agent_id == "echo" and ctx.resumed is False
        assert ctx.call is not None and cc == ctx.call
        assert cc.path == ("echo",) and cc.hop == 1 and cc.deadline is not None


async def test_chunks_and_status_map_to_artifacts(make_server):
    class Chunky:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("thinking")
            yield ArtifactChunk([Part(text="a")], name="out", artifact_id="art-1", last=False)
            yield ArtifactChunk([Part(text="b")], artifact_id="art-1", append=True, last=True)

    h = await make_server(Chunky())
    client = h.client(streaming=True)
    events, task = await send(client, user_msg("go"))
    # The iterator ended without a terminal event: treated as complete.
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    [artifact] = task.artifacts
    assert (artifact.artifact_id, artifact.name) == ("art-1", "out")
    assert [p.text for p in artifact.parts] == ["a", "b"]
    statuses = [ev.status_update for ev in events if ev.WhichOneof("payload") == "status_update"]
    assert any(
        s.status.state == TaskState.TASK_STATE_WORKING
        and [p.text for p in s.status.message.parts] == ["thinking"]
        for s in statuses
    )


async def test_need_input_then_resume_completes(make_server):
    class Asker:
        durable_sessions = False

        def __init__(self) -> None:
            self.resumed: list[bool] = []

        async def run(self, ctx):
            self.resumed.append(ctx.resumed)
            if not ctx.resumed:
                yield NeedInput("what is your name?")
                yield Done("unreachable")  # must not run: NeedInput stops the run
            else:
                yield Done(f"hi {ctx.text}")

    adapter = Asker()
    h = await make_server(adapter)
    client = h.client(streaming=False)

    _, first = await send(client, user_msg("start"))
    assert first.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    assert status_text(first) == "what is your name?"

    _, second = await send(client, user_msg("ada", task_id=first.id, context_id=first.context_id))
    assert second.id == first.id
    assert second.status.state == TaskState.TASK_STATE_COMPLETED
    assert [p.text for p in second.artifacts[0].parts] == ["hi ada"]
    assert adapter.resumed == [False, True]


async def test_adapter_exception_fails_without_leaking(make_server, caplog):
    class Boom:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("starting")
            raise RuntimeError("db password=hunter2")

    h = await make_server(Boom())
    client = h.client(streaming=False)
    with caplog.at_level(logging.ERROR, logger="a2agw.serve.executor"):
        _, task = await send(client, user_msg("x"))
    assert task.status.state == TaskState.TASK_STATE_FAILED
    assert status_text(task) == "internal error"
    assert "hunter2" not in str(task)
    assert "hunter2" in caplog.text  # details are logged server-side


def _cc_metadata(**overrides) -> dict:
    cc = CallContext(origin="o-1", root_agent="caller", path=("caller",), hop=1)
    md = cc.to_metadata()
    md[next(iter(md))].update(overrides)
    return md


async def _assert_rejected(h, metadata, reason: str) -> None:
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("hi", metadata=metadata))
    assert task.status.state == TaskState.TASK_STATE_REJECTED
    assert status_text(task) == reason
    assert h.spec.adapter.seen == []
    rows, _ = await h.index.list(agent_id=h.spec.id)
    assert [r["state"] for r in rows] == [ST(TaskState.TASK_STATE_REJECTED)]


async def test_hop_limit_rejects(make_server):
    h = await make_server(EchoAdapter())
    await _assert_rejected(h, _cc_metadata(hop=8), "hop limit exceeded")


async def test_cycle_rejects(make_server):
    h = await make_server(EchoAdapter())
    await _assert_rejected(h, _cc_metadata(path=["caller", "echo"]), "cycle detected")


async def test_cycle_allowed_with_reentry(make_server):
    adapter = EchoAdapter()
    h = await make_server(adapter, allow_reentry=True)
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("hi", metadata=_cc_metadata(path=["caller", "echo"])))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    cc = adapter.calls[0]
    assert cc.origin == "o-1" and cc.hop == 2 and cc.path == ("caller", "echo", "echo")


async def test_deadline_and_budget_reject(make_server):
    h = await make_server(EchoAdapter())
    await _assert_rejected(h, _cc_metadata(deadline=1.0), "deadline exceeded")
    h2 = await make_server(EchoAdapter(), id="echo2")
    await _assert_rejected(h2, _cc_metadata(max_calls=1, calls_used=5), "budget exceeded")


async def test_malformed_call_context_rejects_without_echo(make_server):
    h = await make_server(EchoAdapter())
    await _assert_rejected(h, _cc_metadata(origin=["<script>"]), "invalid call context")


async def test_cancel_running_task(make_server, caplog):
    started = asyncio.Event()
    stopped = asyncio.Event()

    class Hanger:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("working")
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
            yield Done("unreachable")

    h = await make_server(Hanger())
    hooked: list[str] = []

    async def on_cancel(task_id: str) -> None:
        hooked.append(task_id)
        raise RuntimeError("cascade failed")  # logged and swallowed

    h.executor.on_cancel = on_cancel
    client = h.client(streaming=False)
    events, _ = await send(client, user_msg("run"), return_immediately=True)
    task_id = _task_id(events[0])
    await asyncio.wait_for(started.wait(), timeout=1.0)

    with caplog.at_level(logging.ERROR, logger="a2agw.serve.executor"):
        cancelled = await client.cancel_task(CancelTaskRequest(id=task_id))
    assert cancelled.status.state == TaskState.TASK_STATE_CANCELED
    await asyncio.wait_for(stopped.wait(), timeout=1.0)
    assert hooked == [task_id]
    assert "on_cancel hook failed" in caplog.text

    task = await client.get_task(GetTaskRequest(id=task_id))
    assert task.status.state == TaskState.TASK_STATE_CANCELED
    assert h.executor._running == {}
    rows, _ = await h.index.list(agent_id="echo")
    assert rows[0]["state"] == ST(TaskState.TASK_STATE_CANCELED)
    assert h.bus.recent()[-1].data["state"] == ST(TaskState.TASK_STATE_CANCELED)


async def test_usage_accumulates_in_metadata(make_server):
    class Meter:
        durable_sessions = False

        async def run(self, ctx):
            yield Usage(tokens_in=10, tokens_out=5, cost=0.25)
            yield Status("halfway")
            yield Usage(tokens_in=1, tokens_out=2, cost=0.5)
            yield Done("ok")

    h = await make_server(Meter())
    client = h.client(streaming=True)
    _, task = await send(client, user_msg("count"))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    usage = MessageToDict(task.metadata)["a2agw.usage"]
    assert usage == {"tokens_in": 11, "tokens_out": 7, "cost": 0.75}


async def test_index_and_bus_updated(make_server):
    class Talker:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("secret status text")
            yield Done("secret final text")

    h = await make_server(Talker(), context_builder=AliceContextBuilder())
    client = h.client(streaming=True)
    _, task = await send(client, user_msg("secret input text"))

    rows, _ = await h.index.list(agent_id="echo")
    [row] = rows
    assert row["task_id"] == task.id
    assert row["owner"] == "key:alice"
    assert row["context_id"] == task.context_id
    assert row["state"] == ST(TaskState.TASK_STATE_COMPLETED)
    assert row["origin"]

    events = h.bus.recent()
    assert {ev.kind for ev in events} == {"task.state"}
    assert {ev.agent_id for ev in events} == {"echo"}
    assert [ev.data["state"] for ev in events] == [
        ST(TaskState.TASK_STATE_SUBMITTED),
        ST(TaskState.TASK_STATE_WORKING),
        ST(TaskState.TASK_STATE_COMPLETED),
    ]
    for ev in events:
        assert ev.data == {
            "task_id": task.id,
            "context_id": task.context_id,
            "state": ev.data["state"],
        }
    assert "secret" not in repr(events)


async def test_anonymous_owner(make_server):
    h = await make_server(EchoAdapter())
    client = h.client(streaming=False)
    await send(client, user_msg("hi"))
    rows, _ = await h.index.list(agent_id="echo")
    assert rows[0]["owner"] == "anonymous"
    assert h.spec.adapter.seen[0].principal is None


async def test_usage_totals_survive_resume(make_server):
    class MeterAsker:
        durable_sessions = False

        async def run(self, ctx):
            yield Usage(tokens_in=3, tokens_out=1, cost=0.5)
            if not ctx.resumed:
                yield NeedInput("more?")
            else:
                yield Done("ok")

    h = await make_server(MeterAsker())
    client = h.client(streaming=False)
    _, first = await send(client, user_msg("a"))
    assert MessageToDict(first.metadata)["a2agw.usage"] == {
        "tokens_in": 3,
        "tokens_out": 1,
        "cost": 0.5,
    }
    _, second = await send(client, user_msg("b", task_id=first.id, context_id=first.context_id))
    assert second.status.state == TaskState.TASK_STATE_COMPLETED
    assert MessageToDict(second.metadata)["a2agw.usage"] == {
        "tokens_in": 6,
        "tokens_out": 2,
        "cost": 1.0,
    }
