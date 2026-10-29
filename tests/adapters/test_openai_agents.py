from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("agents")

from adapters.contract import (
    FakePartnerClient,
    assert_cancellable,
    assert_failure_maps,
    assert_isolated_callers,
    assert_multi_turn,
    assert_projection,
    assert_text_stream,
    drive,
    make_ctx,
    output_text,
)
from agents import Agent, FunctionTool
from agents.models.interface import Model
from agents.tool_context import ToolContext
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseTextDeltaEvent,
    ResponseUsage,
)
from openai.types.responses.response_usage import InputTokensDetails, OutputTokensDetails

import a2agw.adapters.openai_agents as oa
from a2agw.adapters.openai_agents import OpenAIAgentsAdapter, as_openai_tools
from a2agw.consult.tools import UNTRUSTED_NOTE
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import Done, Status, Usage

# -- a scripted fake model ----------------------------------------------------------------


def text(*chunks: str) -> tuple:
    return ("text", chunks)


def tool(name: str, args: dict[str, Any]) -> tuple:
    return ("tool", name, args)


ECHO = ("echo",)  # answers "heard: <every user message so far>"
BLOCK = ("block",)  # waits until cancelled
RAISE = ("raise",)


def gate(event: asyncio.Event) -> tuple:
    return ("gate", event)  # signals ``started``, waits for ``event``, then echoes


def _user_texts(items: Any) -> list[str]:
    if isinstance(items, str):
        return [items]
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("role") == "user":
            content = it.get("content")
            if isinstance(content, str):
                out.append(content)
            else:
                out += [c.get("text", "") for c in content or () if isinstance(c, dict)]
    return out


class FakeModel(Model):
    """``agents.models.interface.Model`` that streams scripted steps: text deltas, one
    function call, an echo of the conversation, a block, or an error. Extra calls echo."""

    def __init__(self, *steps: tuple, usage: tuple[int, int] = (0, 0)) -> None:
        self.steps = list(steps)
        self.usage = usage
        self.inputs: list[Any] = []
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    def _response(self, output: list[Any]) -> Response:
        i, o = self.usage
        return Response(
            id="resp-fake",
            created_at=0,
            model="fake",
            object="response",
            output=output,
            tool_choice="auto",
            tools=[],
            top_p=None,
            parallel_tool_calls=False,
            status="completed",
            usage=ResponseUsage(
                input_tokens=i,
                output_tokens=o,
                total_tokens=i + o,
                input_tokens_details=InputTokensDetails(cached_tokens=0, cache_write_tokens=0),
                output_tokens_details=OutputTokensDetails(reasoning_tokens=0),
            ),
        )

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("the adapter streams")

    async def stream_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        *,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    ) -> AsyncIterator[Any]:
        self.inputs.append(input)
        step = self.steps.pop(0) if self.steps else ECHO
        if step[0] == "block":
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.stopped.set()
        if step[0] == "gate":
            self.started.set()
            await step[1].wait()
        if step[0] == "raise":
            raise RuntimeError("model exploded")
        if step[0] == "tool":
            call = ResponseFunctionToolCall(
                id="fc-1",
                call_id="call-1",
                type="function_call",
                name=step[1],
                arguments=json.dumps(step[2]),
            )
            yield ResponseCompletedEvent(
                type="response.completed", response=self._response([call]), sequence_number=0
            )
            return
        chunks = step[1] if step[0] == "text" else ("heard: ", ", ".join(_user_texts(input)))
        for n, chunk in enumerate(chunks):
            yield ResponseTextDeltaEvent(
                type="response.output_text.delta",
                item_id="msg-1",
                output_index=0,
                content_index=0,
                delta=chunk,
                logprobs=[],
                sequence_number=n,
            )
        msg = ResponseOutputMessage(
            id="msg-1",
            type="message",
            role="assistant",
            status="completed",
            content=[
                ResponseOutputText(
                    text="".join(chunks), type="output_text", annotations=[], logprobs=[]
                )
            ],
        )
        yield ResponseCompletedEvent(
            type="response.completed", response=self._response([msg]), sequence_number=len(chunks)
        )


def make_agent(model: FakeModel, tools: list[FunctionTool] | None = None) -> Agent:
    return Agent(name="helper", instructions="Be helpful.", model=model, tools=tools or [])


# -- inbound ------------------------------------------------------------------------------


async def test_streams_text():
    evs = await drive(OpenAIAgentsAdapter(make_agent(FakeModel(text("Hel", "lo", " world")))), "hi")
    assert_text_stream(evs, "Hello world")
    assert sum(1 for e in evs if hasattr(e, "parts")) == 3  # streamed, not buffered
    assert evs[-1] == Done()


async def test_multi_turn_session_memory():
    await assert_multi_turn(
        OpenAIAgentsAdapter(make_agent(FakeModel())), "apples", "pears", "apples"
    )


async def test_custom_session_factory_keyed_by_context():
    from agents import SQLiteSession

    made: dict[str, SQLiteSession] = {}

    def factory(context_id: str) -> SQLiteSession:
        return made.setdefault(context_id, SQLiteSession(context_id))

    adapter = OpenAIAgentsAdapter(make_agent(FakeModel()), session_factory=factory)
    await drive(adapter, "first", context_id="ctx-a")
    assert list(made) == ["anonymous\x1fctx-a"]  # the factory gets the caller+context key
    items = await made["anonymous\x1fctx-a"].get_items()
    assert _user_texts(items) == ["first"]
    for s in made.values():
        s.close()


def test_durable_sessions_flag():
    agent = make_agent(FakeModel())
    assert OpenAIAgentsAdapter(agent).durable_sessions is False
    assert OpenAIAgentsAdapter(agent, durable_sessions=True).durable_sessions is True


async def test_memory_session_keeps_last_items_from_a_user_message():
    s = oa.MemorySession("c", max_items=4)
    await s.add_items([{"role": "user", "content": "u1"}, {"type": "function_call_output"}])
    await s.add_items([{"role": "assistant", "content": "a1"}, {"role": "user", "content": "u2"}])
    await s.add_items([{"type": "function_call_output"}, {"role": "assistant", "content": "a2"}])
    # The last 4 start with an orphan tool output; the kept history starts at "u2".
    assert await s.get_items() == [
        {"role": "user", "content": "u2"},
        {"type": "function_call_output"},
        {"role": "assistant", "content": "a2"},
    ]
    assert oa.MemorySession("c").max_items == oa.MAX_SESSION_ITEMS == 200


async def test_default_session_bounded_over_many_turns(monkeypatch):
    adapter = OpenAIAgentsAdapter(make_agent(FakeModel()))
    await drive(adapter, "first", context_id="c-long")
    adapter._contexts["anonymous\x1fc-long"].session.max_items = 6  # 2 items per turn: 3 turns kept
    for n in range(5):
        await drive(adapter, f"turn{n}", context_id="c-long")
    evs = await drive(adapter, "last", context_id="c-long")
    assert output_text(evs) == "heard: turn2, turn3, turn4, last"


async def test_turns_on_one_context_are_serialised():
    release = asyncio.Event()
    model = FakeModel(gate(release))
    adapter = OpenAIAgentsAdapter(make_agent(model))
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(model.started.wait(), 2)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # not blocked
    assert output_text(other) == "heard: elsewhere"
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and len(model.inputs) == 2  # "two" waits for "one"
    release.set()
    await one
    # "two" ran after "one" was saved, so it sees it.
    assert output_text(await two) == "heard: one, two"


async def test_idle_contexts_evicted_with_their_lock(monkeypatch):
    monkeypatch.setattr(oa, "MAX_SESSIONS", 2)
    release = asyncio.Event()
    model = FakeModel(gate(release))
    adapter = OpenAIAgentsAdapter(make_agent(model))
    busy = asyncio.create_task(drive(adapter, "busy", context_id="c-busy"))
    await asyncio.wait_for(model.started.wait(), 2)
    for cid in ("c-1", "c-2", "c-3"):
        await drive(adapter, "x", context_id=cid)
    # The in-flight context is kept; the oldest idle ones went, lock and session together.
    assert list(adapter._contexts) == ["anonymous\x1fc-busy", "anonymous\x1fc-3"]
    release.set()
    await busy
    evs = await drive(adapter, "again", context_id="c-1")
    assert output_text(evs) == "heard: again"  # a fresh session


async def test_tool_call_reaches_partner_client():
    client = FakePartnerClient()
    model = FakeModel(tool("ask_pinger", {"message": "hi"}), text("pinger said pong"))
    adapter = OpenAIAgentsAdapter(make_agent(model, as_openai_tools(client.tools(), client)))
    evs = await drive(adapter, "ping the pinger")
    assert Status("calling ask_pinger") in evs
    assert evs.index(Status("calling ask_pinger")) < next(
        i for i, e in enumerate(evs) if hasattr(e, "parts")
    )
    assert_text_stream(evs, "pinger said pong")
    assert [c["message"] for c in client.consults] == ["hi"]
    # The model's second call sees the JSON envelope as the tool output.
    [result] = [i for i in model.inputs[1] if i.get("type") == "function_call_output"]
    envelope = json.loads(result["output"])
    assert (envelope["state"], envelope["text"]) == ("completed", "pong:hi")


async def test_projection_contract():
    client = FakePartnerClient()
    tools = as_openai_tools(client.tools(), client)

    async def call(t: FunctionTool, args: dict) -> Any:
        raw = json.dumps(args)
        ctx = ToolContext(context=None, tool_name=t.name, tool_call_id="c1", tool_arguments=raw)
        return await t.on_invoke_tool(ctx, raw)

    await assert_projection(tools, call, client=client)
    # Arguments that are not a JSON object are answered, not raised.
    bad = json.loads(await tools[0].on_invoke_tool(None, "not json"))  # type: ignore[arg-type]
    assert bad["state"] == "rejected"
    # Explicit nulls for optional arguments are dropped before validation.
    ok = json.loads(await call(tools[0], {"message": "yo", "task_id": None}))
    assert ok["state"] == "completed" and client.consults[-1]["task_id"] is None


def test_projected_tool_fields():
    client = FakePartnerClient()
    ptools = client.tools()
    tools = as_openai_tools(ptools, client)
    assert [t.name for t in tools] == [p.name for p in ptools]
    for t, p in zip(tools, ptools, strict=True):
        assert isinstance(t, FunctionTool)
        assert t.description.endswith(UNTRUSTED_NOTE)
        assert t.description.count(UNTRUSTED_NOTE) == 1
        # Strict mode would make every argument required and close ``data``: see the module.
        assert t.strict_json_schema is False
        assert "x-max-json-bytes" not in json.dumps(t.params_json_schema)
        assert t.params_json_schema["required"] == p.parameters["required"]
        assert t.params_json_schema is not p.parameters
    ask = tools[0].params_json_schema
    assert ask["required"] == ["message"] and ask["additionalProperties"] is False
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched


async def test_usage_reported():
    model = FakeModel(text("ok"), usage=(7, 3))
    evs = await drive(OpenAIAgentsAdapter(make_agent(model)), "hi")
    assert [e for e in evs if isinstance(e, Usage)] == [Usage(tokens_in=7, tokens_out=3)]
    assert evs[-2:] == [Usage(tokens_in=7, tokens_out=3), Done()]
    # Usage summed over every model call of the run (tool call + answer).
    client = FakePartnerClient()
    model = FakeModel(tool("ask_pinger", {"message": "hi"}), text("done"), usage=(5, 2))
    agent = make_agent(model, as_openai_tools(client.tools(), client))
    evs = await drive(OpenAIAgentsAdapter(agent), "hi")
    assert [e for e in evs if isinstance(e, Usage)] == [Usage(tokens_in=10, tokens_out=4)]


async def test_no_usage_when_zero():
    evs = await drive(OpenAIAgentsAdapter(make_agent(FakeModel(text("ok")))), "hi")
    assert not any(isinstance(e, Usage) for e in evs)


async def test_failure_propagates():
    await assert_failure_maps(
        OpenAIAgentsAdapter(make_agent(FakeModel(RAISE))), match="model exploded"
    )


async def test_cancellable():
    model = FakeModel(BLOCK)
    await assert_cancellable(
        OpenAIAgentsAdapter(make_agent(model)), started=model.started, stopped=model.stopped
    )


async def test_closing_the_stream_cancels_the_run(monkeypatch):
    runs = []
    run_streamed = oa.Runner.run_streamed

    def spy(*args: Any, **kwargs: Any) -> Any:
        runs.append(run_streamed(*args, **kwargs))
        return runs[-1]

    monkeypatch.setattr(oa.Runner, "run_streamed", spy)
    client = FakePartnerClient()
    model = FakeModel(tool("ask_pinger", {"message": "hi"}), BLOCK)
    agent = make_agent(model, as_openai_tools(client.tools(), client))
    gen = OpenAIAgentsAdapter(agent).run(make_ctx("x"))
    assert await anext(gen) == Status("calling ask_pinger")
    [result] = runs
    assert not result.run_loop_task.done()
    await gen.aclose()  # the executor stops reading (e.g. the task was canceled)
    # The SDK's background run loop ends too. Unread, it would wait forever for its events
    # to be consumed before the next model call.
    await asyncio.wait({result.run_loop_task}, timeout=2)
    assert result.run_loop_task.done()
    assert len(model.inputs) == 1


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    model = FakeModel(tool("ask_pinger", {"message": "hi"}), text("ok"))
    agent = make_agent(model, as_openai_tools(client.tools(), client))
    with use_inbound("inbound-1", None):
        await drive(OpenAIAgentsAdapter(agent), "go")
    assert seen == ["inbound-1"]


async def test_max_turns_passed():
    client = FakePartnerClient()
    model = FakeModel(*[tool("ask_pinger", {"message": "hi"})] * 3)
    agent = make_agent(model, as_openai_tools(client.tools(), client))
    with pytest.raises(Exception, match="(?i)max turns"):
        await drive(OpenAIAgentsAdapter(agent, max_turns=2), "loop")


async def test_final_output_without_deltas_is_done_text():
    class Quiet(FakeModel):
        async def stream_response(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
            async for ev in super().stream_response(*args, **kwargs):
                if not isinstance(ev, ResponseTextDeltaEvent):
                    yield ev

    evs = await drive(OpenAIAgentsAdapter(make_agent(Quiet(text("all", " at once")))), "hi")
    assert_text_stream(evs, "all at once")
    assert output_text(evs) == "all at once"


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    spec = AgentSpec(
        id="oa",
        name="OA",
        description="An OpenAI Agents SDK agent",
        skills=[SkillSpec(id="oa", name="OA", description="Echoes")],
        adapter=OpenAIAgentsAdapter(make_agent(FakeModel(text("served ", "fine"), usage=(4, 2)))),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["oa"]
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
    monkeypatch.setitem(sys.modules, "agents", None)  # ``import agents`` raises ImportError
    spec = importlib.util.spec_from_file_location("_oa_probe", oa.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[openai\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_agents():
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m.split('.')[0] in ('agents', 'openai')])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import openai_agents_example

    assert await openai_agents_example.main() == "echo: hello from A2A"


async def test_isolated_callers():
    # Another caller sending the same contextId does not continue this one's conversation.
    adapter = OpenAIAgentsAdapter(make_agent(FakeModel()))
    await assert_isolated_callers(adapter, "apples", "pears", "apples")


async def test_owned_tasks_only():
    # Partner tasks belong to whoever started them: a foreign task id answers "unknown task".
    from adapters.contract import FakePartnerClient, assert_owned_tasks_only

    client = FakePartnerClient()

    async def call(t, args):
        raw = json.dumps(args)
        ctx = ToolContext(context=None, tool_name=t.name, tool_call_id="c1", tool_arguments=raw)
        return await t.on_invoke_tool(ctx, raw)

    await assert_owned_tasks_only(as_openai_tools(client.tools(), client), call, client)
