from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import subprocess
import sys
from collections.abc import Iterable, Sequence
from typing import Any

import pytest

pytest.importorskip("ag2")

from adapters.contract import (
    FakePartnerClient,
    assert_cancellable,
    assert_failure_maps,
    assert_isolated_callers,
    assert_multi_turn,
    assert_projection,
    assert_text_stream,
    caller,
    drive,
    make_ctx,
    output_text,
)
from ag2 import Agent, MemoryStream
from ag2.events import (
    BaseEvent,
    ModelMessage,
    ModelMessageChunk,
    ModelRequest,
    ModelResponse,
    TextInput,
    ToolCallEvent,
    ToolCallsEvent,
    ToolResultsEvent,
)
from ag2.events import (
    Usage as AG2Usage,
)
from ag2.testing import TestConfig, TrackingConfig
from ag2.tools.final import FunctionTool

import a2agw.adapters.ag2 as ag2_mod
from a2agw.adapters.ag2 import AG2Adapter, as_ag2_tools
from a2agw.consult.tools import UNTRUSTED_NOTE, strip_extensions
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import ArtifactChunk, Done, Status, Usage


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test here may reach the network: name resolution and outbound connections fail,
    and no provider key is visible."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("an AG2 test tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# -- a scripted fake model ----------------------------------------------------------------


def chunks(*parts: str) -> tuple:
    return ("chunks", parts)  # streamed as ``ModelMessageChunk``s, then the whole response


def call(name: str, args: dict[str, Any], *, call_id: str = "call-1") -> ToolCallEvent:
    return ToolCallEvent(name, id=call_id, arguments=json.dumps(args))


ECHO = ("echo",)  # answers "heard: <every user message the model was given>"
BLOCK = ("block",)  # waits until cancelled


def gate(event: asyncio.Event) -> tuple:
    return ("gate", event)  # signals ``started``, waits for ``event``, then echoes


def user_texts(messages: Iterable[BaseEvent]) -> list[str]:
    return [
        p.content
        for m in messages
        if isinstance(m, ModelRequest)
        for p in m.parts
        if isinstance(p, TextInput)
    ]


class FakeConfig(TestConfig):
    """A ``TestConfig`` whose script runs across turns (``TestConfig`` restarts its script
    for every turn, as each turn creates a new client) and that can also echo the
    conversation, stream chunks or block. Plain strings, tool calls and exceptions behave as
    in ``TestConfig``; calls past the script echo. Each model call is recorded (messages and
    tools) and reports ``usage`` (input, output) tokens when non-zero."""

    def __init__(self, *steps: Any, usage: tuple[int, int] = (0, 0), provider: str = "fake"):
        super().__init__()
        self.steps = list(steps)
        self.usage = usage
        self.provider_name = provider
        self.calls: list[tuple[list[BaseEvent], list[Any]]] = []
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    def create(self) -> FakeClient:  # type: ignore[override]
        return FakeClient(self)


class FakeClient:
    def __init__(self, config: FakeConfig) -> None:
        self.config = config

    def _response(self, message: ModelMessage | None = None, **kw: Any) -> ModelResponse:
        i, o = self.config.usage
        usage = AG2Usage(prompt_tokens=i, completion_tokens=o, total_tokens=i + o)
        return ModelResponse(message, usage=usage, provider=self.config.provider_name, **kw)

    async def __call__(
        self, messages: Sequence[BaseEvent], context: Any, *, tools: Iterable[Any] = (), **kw: Any
    ) -> ModelResponse:
        cfg = self.config
        cfg.calls.append((list(messages), list(tools)))
        step = cfg.steps.pop(0) if cfg.steps else ECHO
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, ToolCallEvent):
            return self._response(tool_calls=ToolCallsEvent([step]))
        if isinstance(step, ModelResponse):  # spelled out (e.g. text with tool calls)
            return step
        if isinstance(step, str):
            message = ModelMessage(step)
            await context.send(message)
            return self._response(message)
        if step[0] == "block":
            cfg.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cfg.stopped.set()
        if step[0] == "gate":
            cfg.started.set()
            await step[1].wait()
        if step[0] == "chunks":
            for part in step[1]:
                await context.send(ModelMessageChunk(part))
            message = ModelMessage("".join(step[1]))
            await context.send(message)
            return self._response(message)
        message = ModelMessage("heard: " + ", ".join(user_texts(messages)))
        await context.send(message)
        return self._response(message)


def make_agent(config: Any, tools: Iterable[Any] = ()) -> Agent:
    return Agent("helper", "Be helpful.", config=config, tools=list(tools))


# -- inbound ------------------------------------------------------------------------------


async def test_reply_completes():
    # ``TestConfig`` replies in one piece (no chunks): the reply is the ``Done`` text.
    evs = await drive(AG2Adapter(make_agent(TestConfig("Hello there"))), "hi")
    assert_text_stream(evs, "Hello there")
    assert evs == [Done("Hello there")]


async def test_streams_chunks():
    config = FakeConfig(chunks("Hel", "lo", " world"))
    evs = await drive(AG2Adapter(make_agent(config)), "hi")
    assert_text_stream(evs, "Hello world")
    assert sum(1 for e in evs if isinstance(e, ArtifactChunk)) == 3
    assert evs[-1] == Done()  # the streamed text is not repeated
    assert user_texts(config.calls[0][0]) == ["hi"]


async def test_history_per_context():
    adapter = AG2Adapter(make_agent(FakeConfig()))
    assert output_text(await drive(adapter, "a1", context_id="c-a")) == "heard: a1"
    assert output_text(await drive(adapter, "b1", context_id="c-b")) == "heard: b1"
    assert output_text(await drive(adapter, "a2", context_id="c-a")) == "heard: a1, a2"
    # One AG2 stream (the conversation) per caller and context.
    assert list(adapter._contexts) == ["anonymous\x1fc-b", "anonymous\x1fc-a"]
    stream = adapter._contexts["anonymous\x1fc-a"]
    assert isinstance(stream, MemoryStream)
    assert user_texts(await stream.history.get_events()) == ["a1", "a2"]
    await assert_multi_turn(AG2Adapter(make_agent(FakeConfig())), "apples", "pears", "apples")


async def test_isolated_callers():
    await assert_isolated_callers(AG2Adapter(make_agent(FakeConfig())), "apples", "pears", "apples")


async def test_history_limit():
    # Two messages per turn here (the request and the reply).
    adapter = AG2Adapter(make_agent(FakeConfig()), history_limit=4)
    for n in (1, 2, 3):
        await drive(adapter, f"m{n}")
    evs = await drive(adapter, "m4")
    assert output_text(evs) == "heard: m2, m3, m4"  # m1 was trimmed after the third turn
    events = list(await adapter._contexts["anonymous\x1fc1"].history.get_events())
    assert isinstance(events[0], ModelRequest)
    assert user_texts(events) == ["m3", "m4"]
    with pytest.raises(ValueError, match="history_limit"):
        AG2Adapter(make_agent(FakeConfig()), history_limit=0)


async def test_history_limit_keeps_tool_calls_with_their_turn():
    client = FakePartnerClient()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), "done", "plain")
    adapter = AG2Adapter(make_agent(config, as_ag2_tools(client.tools(), client)), history_limit=3)
    await drive(adapter, "t1")  # request, tool-call response, reply (+ tool events)
    await drive(adapter, "t2")
    events = list(await adapter._contexts["anonymous\x1fc1"].history.get_events())
    # The cut lands on a request: never between a tool call and its result.
    assert isinstance(events[0], ModelRequest) and user_texts(events) == ["t2"]
    assert not any(isinstance(e, ToolResultsEvent) for e in events)


async def test_turns_on_one_context_are_serialised():
    release = asyncio.Event()
    config = FakeConfig(gate(release))
    adapter = AG2Adapter(make_agent(config))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(config.started.wait(), 2)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # not blocked
    assert output_text(other) == "heard: elsewhere"
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and len(config.calls) == 2  # "two" waits for "one"
    release.set()
    await one
    assert output_text(await two) == "heard: one, two"


async def test_idle_contexts_evicted(monkeypatch):
    assert ag2_mod.MAX_SESSIONS == 10_000
    monkeypatch.setattr(ag2_mod, "MAX_SESSIONS", 2)
    release = asyncio.Event()
    config = FakeConfig(gate(release))
    adapter = AG2Adapter(make_agent(config))
    busy = asyncio.create_task(drive(adapter, "busy", context_id="c-busy"))
    await asyncio.wait_for(config.started.wait(), 2)
    for cid in ("c-1", "c-2", "c-3"):
        await drive(adapter, "x", context_id=cid)
    # The in-flight context is kept; the oldest idle ones went, with their history.
    assert list(adapter._contexts) == ["anonymous\x1fc-busy", "anonymous\x1fc-3"]
    release.set()
    await busy
    assert output_text(await drive(adapter, "again", context_id="c-1")) == "heard: again"


async def test_stream_factory_and_durable_sessions():
    agent = make_agent(FakeConfig())
    assert AG2Adapter(agent).durable_sessions is False
    with pytest.raises(ValueError, match="stream_factory"):
        AG2Adapter(agent, durable_sessions=True)
    keys: list[str] = []
    streams: dict[str, MemoryStream] = {}

    def factory(key: str) -> MemoryStream:
        keys.append(key)
        return streams.setdefault(key, MemoryStream())

    adapter = AG2Adapter(agent, stream_factory=factory, durable_sessions=True, history_limit=2)
    for text in ("x", "y"):
        await drive(adapter, text, principal=caller("key:alice"))
    assert keys == ["key:alice\x1fc1"]  # made once per key, then kept in the registry
    # A given stream is the caller's: never trimmed (history_limit is for default streams).
    assert user_texts(await streams["key:alice\x1fc1"].history.get_events()) == ["x", "y"]
    # Another caller on the same context gets a stream of its own key.
    await drive(adapter, "z", principal=caller("key:bob"))
    assert keys == ["key:alice\x1fc1", "key:bob\x1fc1"]
    assert user_texts(await streams["key:bob\x1fc1"].history.get_events()) == ["z"]
    assert user_texts(await streams["key:alice\x1fc1"].history.get_events()) == ["x", "y"]


async def test_tool_reaches_partner_client():
    client = FakePartnerClient()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), chunks("pinger ", "said pong"))
    adapter = AG2Adapter(make_agent(config, as_ag2_tools(client.tools(), client)))
    evs = await drive(adapter, "ping the pinger")
    assert Status("calling ask_pinger") in evs
    assert evs.index(Status("calling ask_pinger")) < next(
        i for i, e in enumerate(evs) if isinstance(e, ArtifactChunk)
    )
    assert_text_stream(evs, "pinger said pong")
    assert [c["message"] for c in client.consults] == ["hi"]
    # The model's second call is given the envelope as the tool result.
    [results] = [m for m in config.calls[1][0] if isinstance(m, ToolResultsEvent)]
    [result] = results.results
    envelope = json.loads(result.result.parts[0].content)
    assert (envelope["state"], envelope["text"]) == ("completed", "pong:hi")


def narrated_call(text: str) -> ModelResponse:
    return ModelResponse(
        ModelMessage(text), tool_calls=ToolCallsEvent([call("ask_pinger", {"message": "hi"})])
    )


async def test_narration_before_tool_calls_is_status():
    client = FakePartnerClient()
    tools = as_ag2_tools(client.tools(), client)
    # A model that does not stream: the narration is a status, the answer the Done text.
    config = FakeConfig(narrated_call("Let me ask the pinger."), "pinger said pong")
    evs = await drive(AG2Adapter(make_agent(config, tools)), "ping")
    assert evs == [
        Status("Let me ask the pinger."),
        Status("calling ask_pinger"),
        Done("pinger said pong"),
    ]
    # Handled the same way after the turn has streamed: the first response streams its
    # narration with the call; a later one-piece narration is still a status.
    streaming = FakeConfig(narrated_call("asking again"), "done")

    class StreamedCall(FakeClient):
        async def __call__(self, messages: Any, context: Any, **kw: Any) -> ModelResponse:
            if self.config.calls:
                return await super().__call__(messages, context, **kw)
            self.config.calls.append((list(messages), []))
            await context.send(ModelMessageChunk("Looking. "))
            first = call("ask_pinger", {"message": "a"}, call_id="c0")
            return self._response(ModelMessage("Looking. "), tool_calls=ToolCallsEvent([first]))

    streaming.create = lambda: StreamedCall(streaming)  # type: ignore[method-assign]
    evs = await drive(AG2Adapter(make_agent(streaming, tools)), "ping")
    assert [e for e in evs if isinstance(e, Status)] == [
        Status("calling ask_pinger"),
        Status("asking again"),
        Status("calling ask_pinger"),
    ]
    assert_text_stream([e for e in evs if not isinstance(e, Status)], "Looking. done")


async def test_unstreamed_reply_after_tool_call_is_done_text():
    client = FakePartnerClient()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), "pinger said pong")
    adapter = AG2Adapter(make_agent(config, as_ag2_tools(client.tools(), client)))
    evs = await drive(adapter, "ping")
    assert evs == [Status("calling ask_pinger"), Done("pinger said pong")]


async def test_tools_reach_the_model():
    # What the model is actually given, through ``TrackingConfig``: a future AG2 that
    # ignored the explicit schema (and inferred one from the function) fails here.
    client = FakePartnerClient()
    ptools = client.tools()
    config = TrackingConfig(TestConfig("ok"))
    await drive(AG2Adapter(make_agent(config, as_ag2_tools(ptools, client))), "hi")
    [model_call] = config.calls
    functions = [s.function for s in model_call.tools]
    assert [f.name for f in functions] == [p.name for p in ptools]
    for f, p in zip(functions, ptools, strict=True):
        assert f.description.endswith(UNTRUSTED_NOTE)
        assert f.description.count(UNTRUSTED_NOTE) == 1
        assert f.parameters == strip_extensions(p.parameters)
        assert "x-max-json-bytes" not in json.dumps(f.parameters)


async def test_usage_reported():
    evs = await drive(AG2Adapter(make_agent(FakeConfig("ok", usage=(7, 3)))), "hi")
    assert evs[-2:] == [Usage(tokens_in=7, tokens_out=3), Done("ok")]
    # Summed over every model call of the turn (tool call + answer).
    client = FakePartnerClient()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), "done", usage=(5, 2))
    evs = await drive(AG2Adapter(make_agent(config, as_ag2_tools(client.tools(), client))), "x")
    assert [e for e in evs if isinstance(e, Usage)] == [Usage(tokens_in=10, tokens_out=4)]
    # Nothing to report: no Usage event.
    evs = await drive(AG2Adapter(make_agent(FakeConfig("ok"))), "hi")
    assert not any(isinstance(e, Usage) for e in evs)


async def test_anthropic_cache_tokens_count_as_input():
    class Cached(FakeClient):
        def _response(self, message: ModelMessage | None = None, **kw: Any) -> ModelResponse:
            usage = AG2Usage(
                prompt_tokens=4,
                completion_tokens=2,
                cache_read_input_tokens=10,
                cache_creation_input_tokens=3,
            )
            return ModelResponse(message, usage=usage, provider=self.config.provider_name, **kw)

    # Anthropic and Bedrock Converse report cache reads and writes apart from the input;
    # OpenAI and Gemini ("google") include cached tokens in it.
    for provider, tokens_in in (("anthropic", 17), ("bedrock", 17), ("openai", 4), ("google", 4)):
        config = FakeConfig("ok", provider=provider)
        config.create = lambda config=config: Cached(config)  # type: ignore[method-assign]
        evs = await drive(AG2Adapter(make_agent(config)), "hi")
        assert Usage(tokens_in=tokens_in, tokens_out=2) in evs, provider


async def test_failure_propagates():
    adapter = AG2Adapter(make_agent(TestConfig(RuntimeError("model exploded"))))
    await assert_failure_maps(adapter, match="model exploded")


async def test_cancellable():
    config = FakeConfig(BLOCK)
    await assert_cancellable(
        AG2Adapter(make_agent(config)), started=config.started, stopped=config.stopped
    )


async def test_closing_the_stream_stops_the_run():
    config = FakeConfig(("chunks-then-block",))

    class Streaming(FakeClient):
        async def __call__(self, messages: Any, context: Any, **kw: Any) -> ModelResponse:
            try:
                for part in ("one", "two"):
                    await context.send(ModelMessageChunk(part))
                await asyncio.Event().wait()
            finally:
                config.stopped.set()
            raise AssertionError("unreachable")

    config.create = lambda: Streaming(config)  # type: ignore[method-assign]
    gen = AG2Adapter(make_agent(config)).run(make_ctx("x"))
    first = await anext(gen)  # "one" (held back until "two" arrived)
    assert isinstance(first, ArtifactChunk)
    await gen.aclose()  # the executor stops reading (e.g. the task was canceled)
    # AG2 drives the turn in a task of its own; closing the turn must cancel it right away.
    # Left to the garbage collector, the model call would still be running here.
    assert config.stopped.is_set()


async def test_cancel_mid_tool_closes_the_call():
    started, never = asyncio.Event(), asyncio.Event()

    class Hanging(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            started.set()
            await never.wait()

    client = Hanging()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}))
    adapter = AG2Adapter(make_agent(config, as_ag2_tools(client.tools(), client)))
    task = asyncio.create_task(drive(adapter, "go"))
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The cancelled turn's tool call is answered, so the history stays valid for providers
    # (an unanswered tool call is rejected on the next turn).
    events = list(await adapter._contexts["anonymous\x1fc1"].history.get_events())
    [results] = [e for e in events if isinstance(e, ToolResultsEvent)]
    assert [r.parent_id for r in results.results] == ["call-1"]
    assert "not completed" in results.results[0].result.parts[0].content
    assert output_text(await drive(adapter, "again")) == "heard: go, again"


async def test_dangling_tool_call_is_repaired_before_the_next_turn():
    # A history whose last turn left a tool call unanswered (its repair never ran, e.g. the
    # process died): providers reject that, so the next turn answers it first.
    stream = MemoryStream()
    dangling = call("ask_pinger", {"message": "hi"}, call_id="lost")
    await stream.history.replace(
        [ModelRequest([TextInput("old")]), ModelResponse(tool_calls=ToolCallsEvent([dangling]))]
    )
    config = FakeConfig()
    adapter = AG2Adapter(make_agent(config), stream_factory=lambda _key: stream)
    assert output_text(await drive(adapter, "new")) == "heard: old, new"
    [(messages, _)] = config.calls
    [results] = [m for m in messages if isinstance(m, ToolResultsEvent)]
    assert [r.parent_id for r in results.results] == ["lost"]
    assert messages.index(results) < max(
        i for i, m in enumerate(messages) if isinstance(m, ModelRequest)
    )
    # Idempotent: a healed (or valid) history is not rewritten again.
    await drive(adapter, "again")
    events = list(await stream.history.get_events())
    assert sum(isinstance(e, ToolResultsEvent) for e in events) == 1


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), "ok")
    agent = make_agent(config, as_ag2_tools(client.tools(), client))
    # AG2 drives the turn in a task started inside the turn: it inherits the contextvars.
    with use_inbound("inbound-1", None):
        await drive(AG2Adapter(agent), "go")
    assert seen == ["inbound-1"]


# -- outbound -----------------------------------------------------------------------------


async def run_tool(tool: FunctionTool, args: Any) -> str:
    raw = args if isinstance(args, str) else json.dumps(args)
    result = await tool(ToolCallEvent(tool.name, arguments=raw), None)  # type: ignore[arg-type]
    return result.result.parts[0].content


async def test_projection_contract():
    client = FakePartnerClient()
    tools = as_ag2_tools(client.tools(), client)
    assert all(isinstance(t, FunctionTool) for t in tools)
    await assert_projection(tools, run_tool, client=client)
    # Explicit nulls for optional arguments are dropped before validation.
    ok = json.loads(await run_tool(tools[0], {"message": "yo", "task_id": None}))
    assert ok["state"] == "completed" and client.consults[-1]["task_id"] is None
    # Invalid or malformed arguments are answered, not raised.
    bad = json.loads(await run_tool(tools[0], {"message": "hi", "bogus": 1}))
    assert bad["state"] == "rejected"
    assert json.loads(await run_tool(tools[0], "{not json"))["state"] == "rejected"
    assert json.loads(await run_tool(tools[0], "[1]"))["state"] == "rejected"


def test_projected_tool_schemas():
    client = FakePartnerClient()
    ptools = client.tools()
    tools = as_ag2_tools(ptools, client)
    assert [t.name for t in tools] == [p.name for p in ptools]
    for t, p in zip(tools, ptools, strict=True):
        fn = t.schema.function
        assert fn.description.count(UNTRUSTED_NOTE) == 1
        assert fn.parameters == strip_extensions(p.parameters)
        assert fn.parameters["required"] == p.parameters["required"]
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched


async def test_add_tool_and_with_middleware_copies_share_the_client():
    client = FakePartnerClient()
    [first, *_] = as_ag2_tools(client.tools(), client)
    seen: list[str] = []

    async def hook(inner: Any, event: ToolCallEvent, context: Any) -> Any:
        seen.append(event.name)
        return await inner(event, context)

    wrapped = first.with_middleware(hook)  # a deep copy
    assert wrapped is not first and isinstance(wrapped, FunctionTool)
    config = FakeConfig(call("ask_pinger", {"message": "hi"}), "ok")
    agent = make_agent(config)
    agent.add_tool(wrapped)  # copied again
    assert agent.tools[0] is not wrapped
    assert output_text(await drive(AG2Adapter(agent), "go")) == "ok"
    assert seen == ["ask_pinger"]
    assert [c["message"] for c in client.consults] == ["hi"]


async def test_agent_copies_share_the_client():
    # AG2 deep-copies every tool it is given; the copies must still call the one client.
    client = FakePartnerClient()
    [first, *_] = as_ag2_tools(client.tools(), client)
    agent = make_agent(FakeConfig(), [first])
    [copied] = agent.tools
    assert copied is not first
    await run_tool(copied, {"message": "hi"})
    assert [c["message"] for c in client.consults] == ["hi"]


async def test_contract_kit():
    adapter = AG2Adapter(make_agent(FakeConfig(chunks("Hel", "lo"))))
    assert_text_stream(await drive(adapter, "hi"), "Hello")
    await assert_multi_turn(AG2Adapter(make_agent(FakeConfig())), "apples", "pears", "apples")
    await assert_isolated_callers(AG2Adapter(make_agent(FakeConfig())), "apples", "pears", "apples")
    await assert_failure_maps(
        AG2Adapter(make_agent(TestConfig(RuntimeError("model exploded")))), match="exploded"
    )
    config = FakeConfig(BLOCK)
    await assert_cancellable(
        AG2Adapter(make_agent(config)), started=config.started, stopped=config.stopped
    )
    client = FakePartnerClient()
    await assert_projection(as_ag2_tools(client.tools(), client), run_tool, client=client)


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    spec = AgentSpec(
        id="ag2",
        name="AG2",
        description="An AG2 agent",
        skills=[SkillSpec(id="ag2", name="AG2", description="Echoes")],
        adapter=AG2Adapter(make_agent(FakeConfig(chunks("served ", "fine"), usage=(4, 2)))),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["ag2"]
        )
        msg = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="x")])
        events = [ev async for ev in client.send_message(SendMessageRequest(message=msg))]
        task = events[-1].task
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        assert "".join(p.text for a in task.artifacts for p in a.parts) == "served fine"
    finally:
        await host.shutdown()
        await hc.aclose()


# -- packaging ----------------------------------------------------------------------------


def test_missing_extra_message(monkeypatch):
    # ``import ag2...`` raises ImportError (submodules already loaded included).
    for name in [m for m in sys.modules if m == "ag2" or m.startswith("ag2.")]:
        monkeypatch.setitem(sys.modules, name, None)
    spec = importlib.util.spec_from_file_location("_ag2_probe", ag2_mod.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[ag2\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_ag2():
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m == 'ag2' or m.startswith('ag2.')])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import ag2_example

    assert await ag2_example.main() == "echo: hello from A2A"


async def test_owned_tasks_only():
    # Partner tasks belong to whoever started them: a foreign task id answers "unknown task".
    from adapters.contract import FakePartnerClient, assert_owned_tasks_only

    client = FakePartnerClient()
    await assert_owned_tasks_only(as_ag2_tools(client.tools(), client), run_tool, client)
