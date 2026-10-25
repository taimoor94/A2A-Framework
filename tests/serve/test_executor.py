"""AdapterExecutor, driven end to end through DefaultRequestHandler, Starlette and the SDK client."""

from __future__ import annotations

import asyncio
import logging
import uuid

from a2a.server.agent_execution import RequestContext
from a2a.server.context import ServerCallContext
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
from a2agw.core.events import ArtifactChunk, Done, NeedInput, Reply, Status, Usage
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
    [row] = (await h.index.list(agent_id="echo"))[0]
    origin = row["origin"]
    assert origin

    _, second = await send(client, user_msg("ada", task_id=first.id, context_id=first.context_id))
    assert second.id == first.id
    assert second.status.state == TaskState.TASK_STATE_COMPLETED
    assert [p.text for p in second.artifacts[0].parts] == ["hi ada"]
    assert adapter.resumed == [False, True]
    [row] = (await h.index.list(agent_id="echo"))[0]
    assert row["origin"] == origin  # the resumed turn kept the task's origin


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
            yield Usage(tokens_in=4, tokens_out=2, cost=0.125)  # only persisted by CANCELED
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
    assert MessageToDict(task.metadata)["a2agw.usage"] == {
        "tokens_in": 4,
        "tokens_out": 2,
        "cost": 0.125,
    }
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


# -- terminal-state and cancellation hardening -------------------------------------------


class FakeQueue:
    def __init__(self) -> None:
        self.events: list = []

    async def enqueue_event(self, event) -> None:
        self.events.append(event)


def _states(h) -> list[str]:
    return [ev.data["state"] for ev in h.bus.recent()]


async def _index_state(h) -> str:
    [row] = (await h.index.list(agent_id=h.spec.id))[0]
    return row["state"]


async def test_adapter_raises_cancelled_fails_task(make_server):
    class SelfCancel:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("s")
            raise asyncio.CancelledError  # not requested by anyone

    h = await make_server(SelfCancel())
    client = h.client(streaming=False)
    _, task = await asyncio.wait_for(send(client, user_msg("x")), timeout=2.0)
    assert task.status.state == TaskState.TASK_STATE_FAILED
    assert status_text(task) == "internal error"
    assert await _index_state(h) == ST(TaskState.TASK_STATE_FAILED)
    assert h.executor._running == {}


async def test_aclose_raises_after_done_stays_completed(make_server, caplog):
    class BadCleanup:
        durable_sessions = False

        async def run(self, ctx):
            try:
                yield Done("ok")
            finally:
                raise RuntimeError("cleanup boom")

    h = await make_server(BadCleanup())
    client = h.client(streaming=False)
    with caplog.at_level(logging.ERROR, logger="a2agw.serve.executor"):
        _, task = await send(client, user_msg("x"))
    completed = ST(TaskState.TASK_STATE_COMPLETED)
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert await _index_state(h) == completed
    assert _states(h)[-1] == completed
    assert ST(TaskState.TASK_STATE_FAILED) not in _states(h)
    assert "adapter cleanup failed" in caplog.text


async def test_double_cancel_hook_once(make_server):
    started = asyncio.Event()

    class Hanger:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("s")
            started.set()
            await asyncio.Event().wait()

    h = await make_server(Hanger())
    hooked: list[str] = []

    async def on_cancel(task_id: str) -> None:
        hooked.append(task_id)

    h.executor.on_cancel = on_cancel
    client = h.client(streaming=False)
    events, _ = await send(client, user_msg("x"), return_immediately=True)
    task_id = _task_id(events[0])
    await asyncio.wait_for(started.wait(), timeout=1.0)

    await asyncio.gather(
        client.cancel_task(CancelTaskRequest(id=task_id)),
        client.cancel_task(CancelTaskRequest(id=task_id)),
        return_exceptions=True,
    )
    # A late direct call (as the SDK makes while its consumer lags) is a no-op too.
    queue = FakeQueue()
    ctx = RequestContext(ServerCallContext(), task_id=task_id, context_id="c")
    await h.executor.cancel(ctx, queue)

    assert queue.events == []
    assert hooked == [task_id]
    assert _states(h).count(ST(TaskState.TASK_STATE_CANCELED)) == 1
    task = await client.get_task(GetTaskRequest(id=task_id))
    assert task.status.state == TaskState.TASK_STATE_CANCELED


async def test_cancel_after_complete_is_noop(make_server):
    h = await make_server(EchoAdapter())
    hooked: list[str] = []

    async def on_cancel(task_id: str) -> None:
        hooked.append(task_id)

    h.executor.on_cancel = on_cancel
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("x"))
    # The store has not caught up yet (task=None): the executor's own record decides.
    queue = FakeQueue()
    ctx = RequestContext(ServerCallContext(), task_id=task.id, context_id=task.context_id)
    await h.executor.cancel(ctx, queue)

    assert queue.events == []
    assert hooked == []
    assert await _index_state(h) == ST(TaskState.TASK_STATE_COMPLETED)
    assert _states(h)[-1] == ST(TaskState.TASK_STATE_COMPLETED)


async def test_cancel_before_adapter_starts(make_server):
    adapter = EchoAdapter()
    h = await make_server(adapter)
    hooked: list[str] = []

    async def on_cancel(task_id: str) -> None:
        hooked.append(task_id)

    h.executor.on_cancel = on_cancel
    real_upsert = h.index.upsert
    reached, release = asyncio.Event(), asyncio.Event()

    async def slow_upsert(*args, **kwargs):
        if args[4] == ST(TaskState.TASK_STATE_SUBMITTED):
            reached.set()
            await release.wait()  # hold execute() inside admission
        await real_upsert(*args, **kwargs)

    h.index.upsert = slow_upsert
    queue = FakeQueue()
    ctx = RequestContext(ServerCallContext(), SendMessageRequest(message=user_msg("x")))
    executing = asyncio.create_task(h.executor.execute(ctx, queue))
    await asyncio.wait_for(reached.wait(), timeout=1.0)
    cancelling = asyncio.create_task(h.executor.cancel(ctx, queue))
    release.set()
    await asyncio.wait_for(asyncio.gather(executing, cancelling), timeout=2.0)

    assert adapter.seen == []
    assert hooked == [ctx.task_id]
    assert await _index_state(h) == ST(TaskState.TASK_STATE_CANCELED)
    assert _states(h) == [ST(TaskState.TASK_STATE_SUBMITTED), ST(TaskState.TASK_STATE_CANCELED)]
    kinds = [type(e).__name__ for e in queue.events]
    assert kinds == ["Task", "TaskStatusUpdateEvent"]
    assert queue.events[-1].status.state == TaskState.TASK_STATE_CANCELED


async def test_cancel_parked_input_required_task(make_server):
    class Asker:
        durable_sessions = False

        async def run(self, ctx):
            yield NeedInput("q")

    h = await make_server(Asker())
    hooked: list[str] = []

    async def on_cancel(task_id: str) -> None:
        hooked.append(task_id)

    h.executor.on_cancel = on_cancel
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("x"))
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED

    cancelled = await client.cancel_task(CancelTaskRequest(id=task.id))
    assert cancelled.status.state == TaskState.TASK_STATE_CANCELED
    assert hooked == [task.id]
    assert await _index_state(h) == ST(TaskState.TASK_STATE_CANCELED)
    assert _states(h)[-1] == ST(TaskState.TASK_STATE_CANCELED)


async def test_cancel_then_execute_resumed_task_does_not_run(make_server):
    class Asker:
        durable_sessions = False

        def __init__(self) -> None:
            self.runs = 0

        async def run(self, ctx):
            self.runs += 1
            if not ctx.resumed:
                yield NeedInput("q")
            else:
                yield Done("ran after cancel")

    adapter = Asker()
    h = await make_server(adapter)
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("x"))
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED

    # The cancel lands while the handler is still setting up the resumed turn.
    resume = user_msg("y", task_id=task.id, context_id=task.context_id)
    ctx = RequestContext(
        ServerCallContext(),
        SendMessageRequest(message=resume),
        task_id=task.id,
        context_id=task.context_id,
        task=task,
    )
    queue = FakeQueue()
    await h.executor.cancel(ctx, queue)
    states_after_cancel = _states(h)
    assert states_after_cancel[-1] == ST(TaskState.TASK_STATE_CANCELED)

    await h.executor.execute(ctx, queue)

    assert adapter.runs == 1
    assert await _index_state(h) == ST(TaskState.TASK_STATE_CANCELED)
    assert _states(h) == states_after_cancel  # no WORKING/COMPLETED after CANCELED
    assert [type(e).__name__ for e in queue.events] == ["TaskStatusUpdateEvent"]
    assert h.executor._active == {}


async def test_cancel_is_bounded_when_adapter_ignores_it(make_server, caplog):
    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()

    class Stubborn:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("s")
            started.set()
            while True:
                try:
                    await release.wait()
                    break
                except asyncio.CancelledError:
                    continue  # swallows the cancellation
            try:
                yield Done("late")
            finally:
                finished.set()

    h = await make_server(Stubborn())
    h.executor.cancel_wait_s = 0.05
    client = h.client(streaming=False)
    events, _ = await send(client, user_msg("x"), return_immediately=True)
    task_id = _task_id(events[0])
    await asyncio.wait_for(started.wait(), timeout=1.0)

    with caplog.at_level(logging.WARNING, logger="a2agw.serve.executor"):
        cancelled = await asyncio.wait_for(
            client.cancel_task(CancelTaskRequest(id=task_id)), timeout=2.0
        )
    assert cancelled.status.state == TaskState.TASK_STATE_CANCELED
    assert "did not stop" in caplog.text
    release.set()  # let the stubborn adapter finish; its Done must be ignored
    await asyncio.wait_for(finished.wait(), timeout=1.0)
    assert await _index_state(h) == ST(TaskState.TASK_STATE_CANCELED)
    assert ST(TaskState.TASK_STATE_COMPLETED) not in _states(h)


# -- direct message replies (A2A TCK DM-MSG-001) ------------------------------------------


class ScriptAdapter:
    durable_sessions = False

    def __init__(self, *events) -> None:
        self.events = events

    async def run(self, ctx: InboundContext):
        for ev in self.events:
            yield ev


async def test_direct_reply_returns_a_message_and_creates_no_task(make_server):
    h = await make_server(ScriptAdapter(Reply("hello")), direct_replies=True)
    for streaming in (True, False):
        events = [
            ev
            async for ev in h.client(streaming=streaming).send_message(
                SendMessageRequest(message=user_msg("hi"))
            )
        ]
        assert [ev.WhichOneof("payload") for ev in events] == ["message"]
        reply = events[0].message
        assert reply.role == Role.ROLE_AGENT
        assert [p.text for p in reply.parts] == ["hello"]
        assert reply.task_id == "" and reply.context_id
    rows, _ = await h.index.list(agent_id="echo")
    assert rows == []  # no task was ever created


async def test_direct_replies_still_run_task_flows(make_server):
    h = await make_server(ScriptAdapter(Status("thinking"), Done(text="ok")), direct_replies=True)
    events, task = await send(h.client(streaming=True), user_msg("hi"))
    assert events[0].WhichOneof("payload") == "task"
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    seen = [
        ST(ev.status_update.status.state)
        for ev in events
        if ev.WhichOneof("payload") == "status_update"
    ]
    assert seen[0] == "TASK_STATE_WORKING" and seen[-1] == "TASK_STATE_COMPLETED"
    [row] = (await h.index.list(agent_id="echo"))[0]
    assert row["state"] == "TASK_STATE_COMPLETED"


async def test_direct_replies_task_created_for_adapter_with_no_events(make_server):
    h = await make_server(ScriptAdapter(), direct_replies=True)
    _, task = await send(h.client(streaming=False), user_msg("hi"))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED


async def test_reply_without_direct_replies_completes_the_task(make_server):
    h = await make_server(ScriptAdapter(Reply("hello")))
    events, task = await send(h.client(streaming=False), user_msg("hi"))
    assert events[0].WhichOneof("payload") == "task"
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert status_text(task) == "hello"


async def test_reply_after_task_events_completes_the_task(make_server):
    h = await make_server(ScriptAdapter(Status("working"), Reply("hello")), direct_replies=True)
    _, task = await send(h.client(streaming=True), user_msg("hi"))
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert status_text(task) == "hello"


async def test_direct_replies_done_with_text_creates_task_first(make_server):
    h = await make_server(ScriptAdapter(Done(text="ok")), direct_replies=True)
    for streaming in (True, False):
        events, task = await send(h.client(streaming=streaming), user_msg("hi"))
        assert events[0].WhichOneof("payload") == "task"
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        assert [p.text for a in task.artifacts for p in a.parts] == ["ok"]


async def test_direct_replies_rejection_creates_task(make_server):
    h = await make_server(ScriptAdapter(Reply("never")), direct_replies=True)
    bad = user_msg("hi", metadata={"https://a2agw.dev/ext/call-context/v1": "garbage"})
    _, task = await send(h.client(streaming=False), bad)
    assert task.status.state == TaskState.TASK_STATE_REJECTED


async def test_follow_up_without_context_id_resumes_in_task_context(make_server):
    """A follow-up naming only the taskId stays in the task's context (TCK history tests)."""
    seen: list[InboundContext] = []

    class Asker:
        durable_sessions = False

        async def run(self, ctx: InboundContext):
            seen.append(ctx)
            if not ctx.resumed:
                yield NeedInput("more?")
            else:
                yield Done(text="thanks")

    h = await make_server(Asker())
    client = h.client(streaming=False)
    _, task = await send(client, user_msg("start"))
    assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    _, task2 = await send(client, user_msg("more", task_id=task.id))
    assert task2.status.state == TaskState.TASK_STATE_COMPLETED
    assert task2.context_id == task.context_id
    assert [c.context_id for c in seen] == [task.context_id, task.context_id]
