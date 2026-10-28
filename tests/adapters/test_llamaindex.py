from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import subprocess
import sys
import typing
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest

pytest.importorskip("llama_index.core")

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
from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent
from llama_index.core.base.llms.types import ChatResponse, ToolCallBlock
from llama_index.core.bridge.pydantic import PrivateAttr
from llama_index.core.llms import ChatMessage
from llama_index.core.llms.mock import MockFunctionCallingLLM
from llama_index.core.memory import ChatMemoryBuffer
from llama_index.core.tools import FunctionTool
from llama_index.core.workflow import Context, StartEvent, StopEvent, Workflow, step

import a2agw.adapters.llamaindex as li_mod
from a2agw.adapters.llamaindex import LlamaIndexAdapter, as_llamaindex_tools
from a2agw.consult.tools import UNTRUSTED_NOTE, strip_extensions
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import ArtifactChunk, Done, Status

# LlamaIndex's workflow classes walk their members with ``inspect.getmembers`` (at
# construction), touching pydantic's deprecated instance attributes: library noise, not ours.
pytestmark = [
    pytest.mark.filterwarnings(
        "ignore::pydantic.warnings.PydanticDeprecatedSince20:inspect",
        "ignore::pydantic.warnings.PydanticDeprecatedSince211:inspect",
    ),
]


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test here may reach the network (LlamaIndex can fetch tokenizers and NLTK data):
    name resolution and outbound connections fail, and no provider key is visible."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a LlamaIndex test tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)


# -- a scripted fake model ----------------------------------------------------------------


def chunks(*parts: str) -> tuple:
    return ("chunks", parts)  # streamed as deltas


def call(name: str, args: dict[str, Any], *, call_id: str = "call-1") -> tuple:
    return ("call", name, args, call_id)  # one tool call


ECHO = ("echo",)  # answers "heard: <every user message the model was given>"
BLOCK = ("block",)  # waits until cancelled


def gate(event: asyncio.Event) -> tuple:
    return ("gate", event)  # signals ``started``, waits for ``event``, then echoes


def user_texts(messages: Sequence[ChatMessage]) -> list[str]:
    return [m.content or "" for m in messages if m.role == "user"]


class Script:
    """What the fake model answers, across turns (calls past the script echo). Records the
    messages of each model call and the tool declarations it was given."""

    def __init__(self, *steps: Any) -> None:
        self.steps = list(steps)
        self.calls: list[list[ChatMessage]] = []
        self.declared: list[list[dict[str, Any]]] = []
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    async def stream(self, messages: Sequence[ChatMessage]) -> AsyncIterator[ChatResponse]:
        self.calls.append(list(messages))
        step = self.steps.pop(0) if self.steps else ECHO
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, str):
            step = chunks(step)
        if step[0] == "block":
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.stopped.set()
        if step[0] == "gate":
            self.started.set()
            await step[1].wait()
        if step[0] == "call":
            _, name, args, call_id = step
            block = ToolCallBlock(tool_call_id=call_id, tool_name=name, tool_kwargs=args)
            yield ChatResponse(message=ChatMessage(role="assistant", blocks=[block]), delta="")
            return
        parts = step[1] if step[0] == "chunks" else ["heard: " + ", ".join(user_texts(messages))]
        text = ""
        for part in parts:
            text += part
            yield ChatResponse(message=ChatMessage(role="assistant", content=text), delta=part)


class ScriptedLLM(MockFunctionCallingLLM):
    """A ``FunctionCallingLLM`` playing a ``Script``. Tools are declared to it the way the
    OpenAI integration declares them (``metadata.to_openai_tool``)."""

    _script: Script = PrivateAttr()

    def __init__(self, script: Script) -> None:
        super().__init__()
        self._script = script

    def _prepare_chat_with_tools(
        self, tools: Sequence[Any], user_msg: Any = None, chat_history: Any = None, **kw: Any
    ) -> dict[str, Any]:
        declared = [t.metadata.to_openai_tool(skip_length_check=True) for t in tools]
        self._script.declared.append(declared)
        return {"messages": list(chat_history or []), "tools": tools}

    async def astream_chat(self, messages: Sequence[ChatMessage], **kw: Any) -> Any:
        return self._script.stream(messages)

    async def achat(self, messages: Sequence[ChatMessage], **kw: Any) -> ChatResponse:
        last = None
        async for last in self._script.stream(messages):
            pass
        assert last is not None
        return last


def make_agent(script: Script, tools: Sequence[Any] = (), **kw: Any) -> FunctionAgent:
    return FunctionAgent(
        name="helper", system_prompt="Be helpful.", llm=ScriptedLLM(script), tools=list(tools), **kw
    )


# -- inbound ------------------------------------------------------------------------------


async def test_streams_text():
    script = Script(chunks("Hel", "lo", " world"))
    evs = await drive(LlamaIndexAdapter(make_agent(script)), "hi")
    assert_text_stream(evs, "Hello world")
    assert sum(1 for e in evs if isinstance(e, ArtifactChunk)) == 3
    assert evs[-1] == Done()  # the streamed text is not repeated
    assert user_texts(script.calls[0]) == ["hi"]


async def test_unstreamed_reply_is_done_text():
    agent = make_agent(Script("Hello there"), streaming=False)
    evs = await drive(LlamaIndexAdapter(agent), "hi")
    assert evs == [Done("Hello there")]


async def test_context_memory():
    adapter = LlamaIndexAdapter(make_agent(Script()))
    assert output_text(await drive(adapter, "a1", context_id="c-a")) == "heard: a1"
    assert output_text(await drive(adapter, "b1", context_id="c-b")) == "heard: b1"
    assert output_text(await drive(adapter, "a2", context_id="c-a")) == "heard: a1, a2"
    # One conversation (workflow Context + memory) per caller and context; the Context is
    # reused across turns.
    assert list(adapter._contexts) == ["anonymous\x1fc-b", "anonymous\x1fc-a"]
    session = adapter._contexts["anonymous\x1fc-a"]
    assert isinstance(session.context, Context)
    assert user_texts(await session.memory.aget_all()) == ["a1", "a2"]
    await assert_multi_turn(LlamaIndexAdapter(make_agent(Script())), "apples", "pears", "apples")


async def test_context_is_reused_across_turns():
    adapter = LlamaIndexAdapter(make_agent(Script()))
    await drive(adapter, "one")
    first = adapter._contexts["anonymous\x1fc1"].context
    await drive(adapter, "two")
    assert adapter._contexts["anonymous\x1fc1"].context is first


async def test_agent_workflow_memory():
    script = Script()
    helper = FunctionAgent(
        name="helper", description="Helps.", system_prompt="Be helpful.", llm=ScriptedLLM(script)
    )
    adapter = LlamaIndexAdapter(AgentWorkflow(agents=[helper], root_agent="helper"))
    assert output_text(await drive(adapter, "x1")) == "heard: x1"
    assert output_text(await drive(adapter, "x2")) == "heard: x1, x2"


async def test_isolated_callers():
    await assert_isolated_callers(
        LlamaIndexAdapter(make_agent(Script())), "apples", "pears", "apples"
    )


async def test_history_trimmed(monkeypatch):
    monkeypatch.setattr(li_mod, "MAX_HISTORY_MESSAGES", 4)  # two turns of request + reply
    adapter = LlamaIndexAdapter(make_agent(Script()))
    for n in (1, 2, 3):
        await drive(adapter, f"m{n}")
    assert output_text(await drive(adapter, "m4")) == "heard: m2, m3, m4"
    messages = await adapter._contexts["anonymous\x1fc1"].memory.aget_all()
    assert messages[0].role == "user" and user_texts(messages) == ["m3", "m4"]


async def test_history_trim_keeps_tool_calls_with_their_turn(monkeypatch):
    monkeypatch.setattr(li_mod, "MAX_HISTORY_MESSAGES", 3)
    client = FakePartnerClient()
    script = Script(call("ask_pinger", {"message": "hi"}), "done", "plain")
    tools = as_llamaindex_tools(client.tools(), client)
    adapter = LlamaIndexAdapter(make_agent(script, tools))
    await drive(adapter, "t1")  # user, assistant (tool call), tool, assistant
    await drive(adapter, "t2")
    messages = await adapter._contexts["anonymous\x1fc1"].memory.aget_all()
    # The cut lands on a user message: never between a tool call and its result.
    assert [m.role for m in messages] == ["user", "assistant"]
    assert user_texts(messages) == ["t2"]


async def test_turns_on_one_context_are_serialised():
    release = asyncio.Event()
    script = Script(gate(release))
    adapter = LlamaIndexAdapter(make_agent(script))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(script.started.wait(), 2)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # not blocked
    assert output_text(other) == "heard: elsewhere"
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and len(script.calls) == 2  # "two" waits for "one"
    release.set()
    await one
    assert output_text(await two) == "heard: one, two"


async def test_idle_contexts_evicted(monkeypatch):
    assert li_mod.MAX_SESSIONS == 10_000
    monkeypatch.setattr(li_mod, "MAX_SESSIONS", 2)
    release = asyncio.Event()
    script = Script(gate(release))
    adapter = LlamaIndexAdapter(make_agent(script))
    busy = asyncio.create_task(drive(adapter, "busy", context_id="c-busy"))
    await asyncio.wait_for(script.started.wait(), 2)
    for cid in ("c-1", "c-2", "c-3"):
        await drive(adapter, "x", context_id=cid)
    # The in-flight context is kept; the oldest idle ones went, with their memory.
    assert list(adapter._contexts) == ["anonymous\x1fc-busy", "anonymous\x1fc-3"]
    release.set()
    await busy
    assert output_text(await drive(adapter, "again", context_id="c-1")) == "heard: again"


async def test_memory_factory_and_durable_sessions():
    agent = make_agent(Script())
    assert LlamaIndexAdapter(agent).durable_sessions is False
    with pytest.raises(ValueError, match="memory_factory"):
        LlamaIndexAdapter(agent, durable_sessions=True)
    keys: list[str] = []
    memories: dict[str, ChatMemoryBuffer] = {}

    def factory(key: str) -> ChatMemoryBuffer:
        keys.append(key)
        return memories.setdefault(key, ChatMemoryBuffer.from_defaults())

    adapter = LlamaIndexAdapter(agent, memory_factory=factory, durable_sessions=True)
    assert adapter.durable_sessions is True
    for text in ("x", "y"):
        await drive(adapter, text, principal=caller("key:alice"))
    assert keys == ["key:alice\x1fc1"]  # made once per key, then kept in the registry
    assert user_texts(await memories["key:alice\x1fc1"].aget_all()) == ["x", "y"]
    await drive(adapter, "z", principal=caller("key:bob"))
    assert keys == ["key:alice\x1fc1", "key:bob\x1fc1"]
    assert user_texts(await memories["key:bob\x1fc1"].aget_all()) == ["z"]


def test_rejects_plain_workflows():
    class Plain(Workflow):
        @step
        async def go(self, ev: StartEvent) -> StopEvent:
            return StopEvent(result="x")

    with pytest.raises(TypeError, match="agent workflows"):
        LlamaIndexAdapter(Plain())


async def test_tool_call_reaches_partner_client():
    client = FakePartnerClient()
    script = Script(call("ask_pinger", {"message": "hi"}), chunks("pinger ", "said pong"))
    adapter = LlamaIndexAdapter(make_agent(script, as_llamaindex_tools(client.tools(), client)))
    evs = await drive(adapter, "ping the pinger")
    assert Status("calling ask_pinger") in evs
    assert evs.index(Status("calling ask_pinger")) < next(
        i for i, e in enumerate(evs) if isinstance(e, ArtifactChunk)
    )
    assert_text_stream(evs, "pinger said pong")
    assert [c["message"] for c in client.consults] == ["hi"]
    # The model's second call is given the envelope as the tool result.
    [result] = [m for m in script.calls[1] if m.role == "tool"]
    assert result.additional_kwargs["tool_call_id"] == "call-1"
    envelope = json.loads(result.content)
    assert (envelope["state"], envelope["text"]) == ("completed", "pong:hi")


async def test_tools_reach_the_model():
    # What the model is actually given (declared as the OpenAI integration declares tools):
    # a LlamaIndex that rebuilt the schema from the pydantic fields fails here.
    client = FakePartnerClient()
    ptools = client.tools()
    script = Script("ok")
    await drive(LlamaIndexAdapter(make_agent(script, as_llamaindex_tools(ptools, client))), "hi")
    [declared] = script.declared
    functions = [d["function"] for d in declared]
    assert [d["type"] for d in declared] == ["function"] * len(ptools)
    assert [f["name"] for f in functions] == [p.name for p in ptools]
    for f, p in zip(functions, ptools, strict=True):
        assert f["description"].endswith(UNTRUSTED_NOTE)
        assert f["description"].count(UNTRUSTED_NOTE) == 1
        assert f["parameters"] == strip_extensions(p.parameters)
        assert "x-max-json-bytes" not in json.dumps(f["parameters"])


async def test_failure_propagates():
    adapter = LlamaIndexAdapter(make_agent(Script(RuntimeError("model exploded"))))
    await assert_failure_maps(adapter, match="model exploded")


async def test_failed_turn_leaves_the_conversation_usable():
    script = Script(RuntimeError("model exploded"))
    adapter = LlamaIndexAdapter(make_agent(script))
    with pytest.raises(RuntimeError):
        await drive(adapter, "first")
    assert output_text(await drive(adapter, "second")) == "heard: first, second"


async def test_cancellable():
    script = Script(BLOCK)
    await assert_cancellable(
        LlamaIndexAdapter(make_agent(script)), started=script.started, stopped=script.stopped
    )


def _workflow_tasks() -> list[asyncio.Task]:
    current = asyncio.current_task()
    return [t for t in asyncio.all_tasks() if t is not current and not t.done()]


async def test_closing_the_stream_stops_the_run():
    script = Script()

    async def streaming_then_block(messages: Sequence[ChatMessage]) -> AsyncIterator[Any]:
        try:
            for part in ("one", "two"):
                yield ChatResponse(message=ChatMessage(role="assistant", content=part), delta=part)
            await asyncio.Event().wait()
        finally:
            script.stopped.set()

    script.stream = streaming_then_block  # type: ignore[method-assign]
    before = set(_workflow_tasks())
    gen = LlamaIndexAdapter(make_agent(script)).run(make_ctx("x"))
    first = await anext(gen)  # "one" (held back until "two" arrived)
    assert isinstance(first, ArtifactChunk)
    await gen.aclose()  # the executor stops reading (e.g. the task was canceled)
    # The workflow runs its steps in tasks of its own; closing the turn must cancel the run
    # right away. Left alone, the model call would still be running here.
    assert script.stopped.is_set()
    assert set(_workflow_tasks()) <= before  # no workflow task left behind


async def test_cancel_mid_tool_starts_a_fresh_context():
    started, never = asyncio.Event(), asyncio.Event()

    class Hanging(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            started.set()
            await never.wait()

    client = Hanging()
    script = Script(call("ask_pinger", {"message": "hi"}))
    adapter = LlamaIndexAdapter(make_agent(script, as_llamaindex_tools(client.tools(), client)))
    task = asyncio.create_task(drive(adapter, "go"))
    await asyncio.wait_for(started.wait(), 2)
    old = adapter._contexts["anonymous\x1fc1"].context
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert adapter._contexts["anonymous\x1fc1"].context is not old
    # The next turn keeps the conversation (both user messages) but not the cut-short run's
    # half-finished tool call, which providers would reject without its result.
    assert output_text(await drive(adapter, "again")) == "heard: go, again"
    assert not any(m.role in ("assistant", "tool") for m in script.calls[-1])


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    script = Script(call("ask_pinger", {"message": "hi"}), "ok")
    agent = make_agent(script, as_llamaindex_tools(client.tools(), client))
    # The workflow's step tasks start inside the turn: they inherit the contextvars.
    with use_inbound("inbound-1", None):
        await drive(LlamaIndexAdapter(agent), "go")
    assert seen == ["inbound-1"]


# -- outbound -----------------------------------------------------------------------------


async def run_tool(tool: FunctionTool, args: dict[str, Any]) -> str:
    return (await tool.acall(**args)).content


async def test_projection_contract():
    client = FakePartnerClient()
    tools = as_llamaindex_tools(client.tools(), client)
    assert all(isinstance(t, FunctionTool) for t in tools)
    await assert_projection(tools, run_tool, client=client)
    # Explicit nulls for optional arguments are dropped before validation.
    ok = json.loads(await run_tool(tools[0], {"message": "yo", "task_id": None}))
    assert ok["state"] == "completed" and client.consults[-1]["task_id"] is None
    # ``invoke`` validates against the original schema: unknown, missing or ill-typed
    # arguments, and the gateway-only ``x-`` limits the model never sees, are answered.
    assert json.loads(await run_tool(tools[0], {"message": "hi", "bogus": 1}))["state"] == (
        "rejected"
    )
    assert json.loads(await run_tool(tools[0], {}))["state"] == "rejected"
    assert json.loads(await run_tool(tools[0], {"message": 5}))["state"] == "rejected"
    big = {"message": "hi", "data": {"blob": "x" * 40_000}}
    assert json.loads(await run_tool(tools[0], big))["state"] == "rejected"


def test_projected_tool_schemas():
    client = FakePartnerClient()
    ptools = client.tools()
    tools = as_llamaindex_tools(ptools, client)
    assert [t.metadata.name for t in tools] == [p.name for p in ptools]
    for t, p in zip(tools, ptools, strict=True):
        stripped = strip_extensions(p.parameters)
        assert t.metadata.description.count(UNTRUSTED_NOTE) == 1
        # Every way LlamaIndex reads the parameters gives the stripped schema verbatim.
        assert t.metadata.get_parameters_dict() == stripped
        assert json.loads(t.metadata.fn_schema_str) == stripped
        assert t.metadata.fn_schema.model_json_schema() == stripped
        assert t.metadata.to_openai_tool(skip_length_check=True)["function"]["parameters"] == (
            stripped
        )
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched
    # The pydantic fields (for code that inspects them) follow the schema: required vs
    # optional, enums, nested objects and arrays.
    fields = tools[0].metadata.fn_schema.model_fields
    assert set(fields) == set(ptools[0].parameters["properties"])
    assert fields["message"].is_required() and fields["message"].annotation is str
    assert not fields["task_id"].is_required() and fields["task_id"].default is None
    assert (
        typing.get_args(fields["classification"].annotation)[0]
        == typing.Literal["public", "internal", "confidential", "restricted"]
    )
    assert typing.get_args(fields["data"].annotation)[0] == dict[str, Any]
    wait = next(t for t in tools if t.metadata.name == "a2a_wait").metadata.fn_schema
    assert wait.model_fields["tasks"].annotation == list[dict[str, Any]]


async def test_contract_kit():
    adapter = LlamaIndexAdapter(make_agent(Script(chunks("Hel", "lo"))))
    assert_text_stream(await drive(adapter, "hi"), "Hello")
    await assert_multi_turn(LlamaIndexAdapter(make_agent(Script())), "apples", "pears", "apples")
    await assert_isolated_callers(
        LlamaIndexAdapter(make_agent(Script())), "apples", "pears", "apples"
    )
    await assert_failure_maps(
        LlamaIndexAdapter(make_agent(Script(RuntimeError("model exploded")))), match="exploded"
    )
    script = Script(BLOCK)
    await assert_cancellable(
        LlamaIndexAdapter(make_agent(script)), started=script.started, stopped=script.stopped
    )
    client = FakePartnerClient()
    await assert_projection(as_llamaindex_tools(client.tools(), client), run_tool, client=client)


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    spec = AgentSpec(
        id="li",
        name="LlamaIndex",
        description="A LlamaIndex agent",
        skills=[SkillSpec(id="li", name="LlamaIndex", description="Echoes")],
        adapter=LlamaIndexAdapter(make_agent(Script(chunks("served ", "fine")))),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["li"]
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
    # ``import llama_index.core...`` raises ImportError (submodules already loaded included).
    for name in [m for m in sys.modules if m == "llama_index" or m.startswith("llama_index.")]:
        monkeypatch.setitem(sys.modules, name, None)
    spec = importlib.util.spec_from_file_location("_li_probe", li_mod.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[llamaindex\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_llamaindex():
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m.split('.')[0] in ('llama_index', 'workflows')])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import llamaindex_example

    assert await llamaindex_example.main() == "echo: hello from A2A"
