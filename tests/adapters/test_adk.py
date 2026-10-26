from __future__ import annotations

import asyncio
import importlib.util
import json
import socket
import subprocess
import sys
from collections.abc import AsyncGenerator
from typing import Any

import pytest

pytest.importorskip("google.adk")

from adapters.contract import (
    FakePartnerClient,
    assert_cancellable,
    assert_failure_maps,
    assert_multi_turn,
    assert_projection,
    assert_text_stream,
    drive,
    make_ctx,
    output_text,
)
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.sessions import InMemorySessionService
from google.adk.tools import FunctionTool
from google.genai import types
from pydantic import PrivateAttr

import a2agw.adapters.adk as adk_mod
from a2agw.adapters.adk import AdkAdapter, as_adk_tools
from a2agw.consult.tools import UNTRUSTED_NOTE
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import ArtifactChunk, Done, Failed, Status, Usage
from a2agw.security.principal import Principal


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test here may reach the network or Google credentials: name resolution and
    outbound connections fail, and no Google credential variable is visible."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("an ADK test tried to use the network")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for var in (
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_GENAI_USE_VERTEXAI",
    ):
        monkeypatch.delenv(var, raising=False)


# -- a scripted fake model ----------------------------------------------------------------


def text(*chunks: str) -> tuple:
    return ("text", chunks)  # streamed as partial responses, then the aggregate


def whole(answer: str) -> tuple:
    return ("whole", answer)  # one complete response, no partials (a non-streaming model)


def call(name: str, args: dict[str, Any]) -> tuple:
    return ("call", name, args)


def thought(idea: str, answer: str) -> tuple:
    return ("thought", idea, answer)


def error(code: str) -> tuple:
    return ("error", code)


ECHO = ("echo",)  # answers "heard: <every user message so far>"
BLOCK = ("block",)  # waits until cancelled
RAISE = ("raise",)


def gate(event: asyncio.Event) -> tuple:
    return ("gate", event)  # signals ``started``, waits for ``event``, then echoes


def _user_texts(request: LlmRequest) -> list[str]:
    return [
        p.text
        for c in request.contents
        if c.role == "user"
        for p in c.parts or ()
        if p.text is not None
    ]


def _content(*parts: types.Part) -> types.Content:
    return types.Content(role="model", parts=list(parts))


class FakeLlm(BaseLlm):
    """A ``BaseLlm`` playing scripted steps: streamed text, one complete response, a function
    call, a thought, an error response, an echo of the conversation, a block or a raise.
    Calls past the script echo. Every response that completes a model call carries
    ``usage`` (input, output) tokens."""

    model: str = "fake"
    _steps: list[tuple] = PrivateAttr(default_factory=list)
    _usage: tuple[int, int] = PrivateAttr(default=(0, 0))
    _requests: list[LlmRequest] = PrivateAttr(default_factory=list)
    _streams: list[bool] = PrivateAttr(default_factory=list)
    _started: asyncio.Event = PrivateAttr(default_factory=asyncio.Event)
    _stopped: asyncio.Event = PrivateAttr(default_factory=asyncio.Event)

    def __init__(self, *steps: tuple, usage: tuple[int, int] = (0, 0)) -> None:
        super().__init__()
        self._steps = list(steps)
        self._usage = usage

    @property
    def requests(self) -> list[LlmRequest]:
        return self._requests

    @property
    def started(self) -> asyncio.Event:
        return self._started

    @property
    def stopped(self) -> asyncio.Event:
        return self._stopped

    def _done(self, content: types.Content | None = None, **kw: Any) -> LlmResponse:
        i, o = self._usage
        usage = None
        if i or o:
            usage = types.GenerateContentResponseUsageMetadata(
                prompt_token_count=i, candidates_token_count=o, total_token_count=i + o
            )
        return LlmResponse(content=content, usage_metadata=usage, turn_complete=True, **kw)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self._requests.append(llm_request)
        self._streams.append(stream)
        step = self._steps.pop(0) if self._steps else ECHO
        if step[0] == "block":
            self._started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self._stopped.set()
        if step[0] == "gate":
            self._started.set()
            await step[1].wait()
        if step[0] == "raise":
            raise RuntimeError("model exploded")
        if step[0] == "call":
            fc = types.FunctionCall(id="fc-1", name=step[1], args=step[2])
            yield self._done(_content(types.Part(function_call=fc)))
            return
        if step[0] == "whole":
            yield self._done(_content(types.Part(text=step[1])))
            return
        if step[0] == "error":
            yield self._done(error_code=step[1], error_message="blocked: secret detail")
            return
        if step[0] == "thought":
            idea = types.Part(text=step[1], thought=True)
            yield LlmResponse(content=_content(idea), partial=True)
            yield LlmResponse(content=_content(types.Part(text=step[2])), partial=True)
            yield self._done(
                _content(types.Part(text=step[1], thought=True), types.Part(text=step[2]))
            )
            return
        chunks = step[1] if step[0] == "text" else ("heard: ", ", ".join(_user_texts(llm_request)))
        for chunk in chunks:
            yield LlmResponse(content=_content(types.Part(text=chunk)), partial=True)
        yield self._done(_content(types.Part(text="".join(chunks))))


def make_agent(model: FakeLlm, tools: list[Any] | None = None) -> LlmAgent:
    return LlmAgent(name="helper", instruction="Be helpful.", model=model, tools=tools or [])


def principal(pid: str) -> Principal:
    return Principal(id=pid, kind="api_key", scopes=frozenset())


# -- inbound ------------------------------------------------------------------------------


async def test_streams_text():
    model = FakeLlm(text("Hel", "lo", " world"))
    evs = await drive(AdkAdapter(make_agent(model)), "hi")
    assert_text_stream(evs, "Hello world")
    # Streamed chunk by chunk; the aggregated final response does not repeat the text.
    assert sum(1 for e in evs if isinstance(e, ArtifactChunk)) == 3
    assert evs[-1] == Done()
    assert model._streams == [True]  # the run asks the model to stream (SSE)
    assert _user_texts(model.requests[0]) == ["hi"]


async def test_complete_response_without_partials_streams_once():
    evs = await drive(AdkAdapter(make_agent(FakeLlm(whole("all at once")))), "hi")
    assert_text_stream(evs, "all at once")


async def test_thoughts_are_not_output():
    evs = await drive(AdkAdapter(make_agent(FakeLlm(thought("hmm", "answer")))), "hi")
    assert_text_stream(evs, "answer")


async def test_session_per_context():
    service = InMemorySessionService()
    adapter = AdkAdapter(make_agent(FakeLlm()), app_name="app", session_service=service)
    await drive(adapter, "a1", context_id="c-a")
    await drive(adapter, "b1", context_id="c-b")
    evs = await drive(adapter, "a2", context_id="c-a")
    assert output_text(evs) == "heard: a1, a2"
    # One ADK session per A2A context, made on first use, under the anonymous user.
    sessions = {s.id for s in (await service.list_sessions(app_name="app")).sessions}
    assert sessions == {"c-a", "c-b"}
    session = await service.get_session(app_name="app", user_id="anonymous", session_id="c-a")
    assert session is not None
    await assert_multi_turn(AdkAdapter(make_agent(FakeLlm())), "apples", "pears", "apples")


async def test_sessions_are_per_caller():
    service = InMemorySessionService()
    adapter = AdkAdapter(make_agent(FakeLlm()), session_service=service)

    async def turn(text: str, pid: str) -> str:
        ctx = make_ctx(text, context_id="shared")
        ctx.principal = principal(pid)
        return output_text([ev async for ev in adapter.run(ctx)])

    assert await turn("alice-1", "key:alice") == "heard: alice-1"
    # The same context id from another caller is another user's session: no shared history.
    assert await turn("bob-1", "key:bob") == "heard: bob-1"
    assert await turn("alice-2", "key:alice") == "heard: alice-1, alice-2"
    for user in ("key:alice", "key:bob"):
        s = await service.get_session(app_name="a2agw", user_id=user, session_id="shared")
        assert s is not None


async def test_turns_on_one_context_are_serialised():
    release = asyncio.Event()
    model = FakeLlm(gate(release))
    adapter = AdkAdapter(make_agent(model))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(model.started.wait(), 2)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # not blocked
    assert output_text(other) == "heard: elsewhere"
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and len(model.requests) == 2  # "two" waits for "one"
    release.set()
    await one
    assert output_text(await two) == "heard: one, two"


async def test_idle_contexts_evicted_with_their_session(monkeypatch):
    monkeypatch.setattr(adk_mod, "MAX_SESSIONS", 2)
    release = asyncio.Event()
    model = FakeLlm(gate(release))
    adapter = AdkAdapter(make_agent(model))
    busy = asyncio.create_task(drive(adapter, "busy", context_id="c-busy"))
    await asyncio.wait_for(model.started.wait(), 2)
    for cid in ("c-1", "c-2", "c-3"):
        await drive(adapter, "x", context_id=cid)
    # The in-flight context is kept; the oldest idle ones went, with their default session.
    assert list(adapter._contexts) == [("anonymous", "c-busy"), ("anonymous", "c-3")]
    service = adapter.session_service
    assert set(service.sessions["a2agw"]["anonymous"]) == {"c-busy", "c-3"}
    release.set()
    await busy
    evs = await drive(adapter, "again", context_id="c-1")
    assert output_text(evs) == "heard: again"  # a fresh session


async def test_a_given_session_service_is_never_pruned(monkeypatch):
    monkeypatch.setattr(adk_mod, "MAX_SESSIONS", 1)
    service = InMemorySessionService()
    adapter = AdkAdapter(make_agent(FakeLlm()), session_service=service, durable_sessions=True)
    for cid in ("c-1", "c-2"):
        await drive(adapter, "x", context_id=cid)
    assert list(adapter._contexts) == [("anonymous", "c-2")]
    assert set(service.sessions["a2agw"]["anonymous"]) == {"c-1", "c-2"}  # the caller's
    evs = await drive(adapter, "y", context_id="c-1")
    assert output_text(evs) == "heard: x, y"


def test_durable_sessions_need_a_session_service():
    agent = make_agent(FakeLlm())
    assert AdkAdapter(agent).durable_sessions is False
    assert isinstance(AdkAdapter(agent).session_service, InMemorySessionService)
    with pytest.raises(ValueError, match="session_service"):
        AdkAdapter(agent, durable_sessions=True)
    service = InMemorySessionService()
    adapter = AdkAdapter(agent, session_service=service, durable_sessions=True)
    assert adapter.durable_sessions is True and adapter.session_service is service


async def test_function_call_reaches_partner_client():
    client = FakePartnerClient()
    model = FakeLlm(call("ask_pinger", {"message": "hi"}), text("pinger said pong"))
    adapter = AdkAdapter(make_agent(model, as_adk_tools(client.tools(), client)))
    evs = await drive(adapter, "ping the pinger")
    assert Status("calling ask_pinger") in evs
    assert evs.index(Status("calling ask_pinger")) < next(
        i for i, e in enumerate(evs) if isinstance(e, ArtifactChunk)
    )
    assert_text_stream(evs, "pinger said pong")
    assert [c["message"] for c in client.consults] == ["hi"]
    # The model's second call sees the envelope as the function response.
    [response] = [
        p.function_response.response
        for c in model.requests[1].contents
        for p in c.parts or ()
        if p.function_response
    ]
    assert (response["state"], response["text"]) == ("completed", "pong:hi")


async def test_usage_reported():
    model = FakeLlm(text("ok"), usage=(7, 3))
    evs = await drive(AdkAdapter(make_agent(model)), "hi")
    assert evs[-2:] == [Usage(tokens_in=7, tokens_out=3), Done()]
    # Summed over every model call of the run (function call + answer).
    client = FakePartnerClient()
    model = FakeLlm(call("ask_pinger", {"message": "hi"}), text("done"), usage=(5, 2))
    evs = await drive(AdkAdapter(make_agent(model, as_adk_tools(client.tools(), client))), "x")
    assert [e for e in evs if isinstance(e, Usage)] == [Usage(tokens_in=10, tokens_out=4)]
    # Nothing to report: no Usage event.
    evs = await drive(AdkAdapter(make_agent(FakeLlm(text("ok")))), "hi")
    assert not any(isinstance(e, Usage) for e in evs)


async def test_error_response_fails():
    evs = await drive(AdkAdapter(make_agent(FakeLlm(error("SAFETY")))), "hi")
    assert evs[-1] == Failed("agent error")
    assert not any(isinstance(e, Done) for e in evs)
    await assert_failure_maps(AdkAdapter(make_agent(FakeLlm(error("SAFETY")))), match="agent error")


async def test_failure_propagates():
    await assert_failure_maps(AdkAdapter(make_agent(FakeLlm(RAISE))), match="model exploded")


async def test_cancellable():
    model = FakeLlm(BLOCK)
    await assert_cancellable(
        AdkAdapter(make_agent(model)), started=model.started, stopped=model.stopped
    )


async def test_closing_the_stream_stops_the_run():
    class Streaming(FakeLlm):
        async def generate_content_async(
            self, llm_request: LlmRequest, stream: bool = False
        ) -> AsyncGenerator[LlmResponse, None]:
            try:
                for chunk in ("one", "two"):
                    yield LlmResponse(content=_content(types.Part(text=chunk)), partial=True)
                await asyncio.Event().wait()
            finally:
                self._stopped.set()

    model = Streaming()
    gen = AdkAdapter(make_agent(model)).run(make_ctx("x"))
    first = await anext(gen)  # "one" (held back until "two" arrived)
    assert isinstance(first, ArtifactChunk)
    await gen.aclose()  # the executor stops reading (e.g. the task was canceled)
    # ADK runs the agent in a background task; closing ``run_async`` right away cancels it.
    # Left to the garbage collector, the model call would still be running here.
    assert model.stopped.is_set()


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    model = FakeLlm(call("ask_pinger", {"message": "hi"}), text("ok"))
    agent = make_agent(model, as_adk_tools(client.tools(), client))
    # ADK runs the agent in a task it starts inside the turn, so it inherits the inbound
    # contextvars.
    with use_inbound("inbound-1", None):
        await drive(AdkAdapter(agent), "go")
    assert seen == ["inbound-1"]


async def test_no_telemetry_export_set_up():
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    await drive(AdkAdapter(make_agent(FakeLlm(text("ok")))), "hi")
    # ADK only uses the global OTel API; it never installs a provider or exporter of its
    # own (that is ``google.adk.telemetry.setup``, used by the ``adk`` CLI's server).
    assert trace.get_tracer_provider() is provider
    assert "google.adk.telemetry.setup" not in sys.modules


# -- outbound -----------------------------------------------------------------------------


async def run_tool(tool: FunctionTool, args: dict[str, Any]) -> Any:
    return await tool.run_async(args=args, tool_context=None)  # type: ignore[arg-type]


async def test_projection_contract():
    client = FakePartnerClient()
    tools = as_adk_tools(client.tools(), client)
    await assert_projection(tools, run_tool, client=client)
    # Explicit nulls for optional arguments are dropped before validation.
    ok = await run_tool(tools[0], {"message": "yo", "task_id": None})
    assert ok["state"] == "completed" and client.consults[-1]["task_id"] is None
    # Invalid arguments are answered, not raised.
    bad = await run_tool(tools[0], {"message": "hi", "bogus": 1})
    assert bad["state"] == "rejected"


def test_projected_tool_declarations():
    client = FakePartnerClient()
    ptools = client.tools()
    tools = as_adk_tools(ptools, client)
    assert [t.name for t in tools] == [p.name for p in ptools]
    for t, p in zip(tools, ptools, strict=True):
        assert isinstance(t, FunctionTool)
        decl = t._get_declaration()
        assert decl.name == p.name
        assert decl.description.endswith(UNTRUSTED_NOTE)
        assert decl.description.count(UNTRUSTED_NOTE) == 1
        schema = decl.parameters_json_schema
        assert "x-max-json-bytes" not in json.dumps(schema)
        assert schema["required"] == p.parameters["required"]
        assert decl.parameters is None  # the JSON schema as is, not converted
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched


async def test_contract_kit():
    adapter = AdkAdapter(make_agent(FakeLlm(text("Hello"))))
    assert_text_stream(await drive(adapter, "hi"), "Hello")
    await assert_multi_turn(AdkAdapter(make_agent(FakeLlm())), "apples", "pears", "apples")
    await assert_failure_maps(AdkAdapter(make_agent(FakeLlm(RAISE))), match="model exploded")
    model = FakeLlm(BLOCK)
    await assert_cancellable(
        AdkAdapter(make_agent(model)), started=model.started, stopped=model.stopped
    )
    client = FakePartnerClient()
    await assert_projection(as_adk_tools(client.tools(), client), run_tool, client=client)


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    spec = AgentSpec(
        id="adk",
        name="ADK",
        description="A Google ADK agent",
        skills=[SkillSpec(id="adk", name="ADK", description="Echoes")],
        adapter=AdkAdapter(make_agent(FakeLlm(text("served ", "fine"), usage=(4, 2)))),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["adk"]
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
    # ``import google.adk...`` raises ImportError (submodules already loaded included).
    for name in [m for m in sys.modules if m == "google.adk" or m.startswith("google.adk.")]:
        monkeypatch.setitem(sys.modules, name, None)
    spec = importlib.util.spec_from_file_location("_adk_probe", adk_mod.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[adk\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_adk():
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m.startswith(('google.adk', 'google.genai'))])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import adk_example

    assert await adk_example.main() == "echo: hello from A2A"
