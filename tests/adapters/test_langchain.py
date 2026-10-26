from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid

import httpx
import pytest

pytest.importorskip("langchain_core")

from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from adapters.contract import (
    FakePartnerClient,
    assert_cancellable,
    assert_failure_maps,
    assert_multi_turn,
    assert_projection,
    assert_text_stream,
    drive,
)
from google.protobuf.json_format import MessageToDict
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, AIMessageChunk
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import StructuredTool
from streaming_asgi import StreamingASGITransport

from a2agw.adapters.callable import agent
from a2agw.adapters.langchain import RunnableAdapter, as_langchain_tools
from a2agw.consult.tools import UNTRUSTED_NOTE, partner_tools
from a2agw.core.events import ArtifactChunk, Usage
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


def ctx(text: str = "hi") -> InboundContext:
    m = Message(message_id="m", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message("x", m, task_id="t", context_id="ctx-1")


async def collect(adapter: RunnableAdapter, text: str = "hi") -> list:
    return [e async for e in adapter.run(ctx(text))]


def text_of(c: ArtifactChunk) -> str:
    return "".join(p.text for p in c.parts)


async def test_runnable_lambda_streams_and_completes():
    evs = await collect(RunnableAdapter(RunnableLambda(lambda t: f"echo:{t}")), "yo")
    assert len(evs) == 1
    c = evs[0]
    assert text_of(c) == "echo:yo"
    assert (c.artifact_id, c.name, c.append, c.last) == ("output", "output", False, True)


async def test_async_generator_chunks_have_last_flag():
    async def gen(t):
        for w in ("a", "b", "c"):
            yield w

    evs = await collect(RunnableAdapter(RunnableLambda(gen)))
    assert [text_of(c) for c in evs] == ["a", "b", "c"]
    assert [c.append for c in evs] == [False, True, True]
    assert [c.last for c in evs] == [False, False, True]


async def test_input_key_and_thread_id_config():
    seen = {}

    def fn(inp, config):
        seen["inp"] = inp
        seen["thread"] = config["configurable"]["thread_id"]
        return inp["q"].upper()

    evs = await collect(RunnableAdapter(RunnableLambda(fn), input_key="q"), "abc")
    assert seen == {"inp": {"q": "abc"}, "thread": "ctx-1"}
    assert text_of(evs[0]) == "ABC"


async def test_fake_chat_model_usage_reported():
    model = GenericFakeChatModel(messages=iter([AIMessage(content="hello big world")]))
    evs = await collect(RunnableAdapter(model))
    chunks = [e for e in evs if isinstance(e, ArtifactChunk)]
    assert "".join(text_of(c) for c in chunks) == "hello big world"
    assert chunks[-1].last is True and all(not c.last for c in chunks[:-1])
    # the fake model reports no usage, so none is emitted
    assert not any(isinstance(e, Usage) for e in evs)


async def test_usage_summed_across_chunks_and_block_content():
    def usage(i, o):
        return {"input_tokens": i, "output_tokens": o, "total_tokens": i + o}

    async def gen(t):
        yield AIMessageChunk(content="He", usage_metadata=usage(5, 0))
        yield AIMessageChunk(
            content=[{"type": "text", "text": "llo"}, {"type": "tool_use", "id": "x"}],
            usage_metadata=usage(0, 3),
        )
        yield AIMessageChunk(content="", usage_metadata=usage(1, 2))

    evs = await collect(RunnableAdapter(RunnableLambda(gen)))
    assert "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk)) == "Hello"
    assert evs[-1] == Usage(tokens_in=6, tokens_out=5)
    assert sum(isinstance(e, Usage) for e in evs) == 1


async def test_dict_output_becomes_result_data_artifact():
    evs = await collect(RunnableAdapter(RunnableLambda(lambda t: {"answer": 42, "tags": ["a"]})))
    assert len(evs) == 1
    c = evs[0]
    assert (c.artifact_id, c.name, c.last) == ("result", "result", True)
    assert MessageToDict(c.parts[0])["data"] == {"answer": 42, "tags": ["a"]}


async def test_unsupported_chunk_raises():
    with pytest.raises(TypeError):
        await collect(RunnableAdapter(RunnableLambda(lambda t: 42)))


def test_durable_sessions_flag():
    assert RunnableAdapter(RunnableLambda(str), durable_sessions=True).durable_sessions is True
    assert RunnableAdapter(RunnableLambda(str)).durable_sessions is False


def test_core_does_not_import_langchain():
    code = (
        "import sys, a2agw, a2agw.serve.host;"
        "bad=[m for m in sys.modules if m.split('.')[0] in ('langchain_core','langchain','langgraph')];"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


# -- tools --------------------------------------------------------------------------------


@pytest.fixture
async def world(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")

    @agent("pinger", "Pinger", "Answers pings")
    def pinger(c):
        return f"pong:{c.text}"

    lc = AgentSpec(
        id="lc",
        name="LC",
        description="A LangChain agent",
        skills=[SkillSpec(id="lc", name="LC", description="A LangChain agent")],
        adapter=RunnableAdapter(RunnableLambda(lambda t: f"lc says {t}")),
    )
    transport = StreamingASGITransport({})
    partner_hc = httpx.AsyncClient(transport=transport, base_url="http://t")
    host = AgentHost(
        "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", partner_http=partner_hc
    )
    host.add(pinger)
    host.add(lc)
    transport.apps["t"] = host.app()
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        yield host, hc
    finally:
        await host.shutdown()
        await hc.aclose()
        await partner_hc.aclose()


async def test_tools_have_schema_and_untrusted_note(world):
    host, _ = world
    await host.partners.add_from_card("pinger", MessageToDict(host.cards["pinger"]), "internal")
    ptools = partner_tools(host.partners)
    tools = as_langchain_tools(ptools, host.client)
    assert len(tools) == len(ptools) >= 1
    for t, p in zip(tools, ptools, strict=True):
        assert isinstance(t, StructuredTool)
        assert t.name == p.name
        assert t.description.endswith("\n\n" + UNTRUSTED_NOTE)
        assert t.args_schema == p.parameters
        assert t.handle_tool_error is True
        assert t.tool_call_schema is not None


async def test_tool_invocation_hits_partner(world):
    host, _ = world
    await host.partners.add_from_card("pinger", MessageToDict(host.cards["pinger"]), "internal")
    tools = {t.name: t for t in as_langchain_tools(partner_tools(host.partners), host.client)}
    out = await tools["ask_pinger"].ainvoke({"message": "ping", "wait_seconds": 5})
    assert isinstance(out, str)
    res = json.loads(out)
    assert res["state"] == "completed"
    assert "pong:ping" in res["text"]


async def test_tool_invalid_args_answered_not_raised(world):
    host, _ = world
    await host.partners.add_from_card("pinger", MessageToDict(host.cards["pinger"]), "internal")
    tools = {t.name: t for t in as_langchain_tools(partner_tools(host.partners), host.client)}
    out = json.loads(await tools["ask_pinger"].ainvoke({"wait_seconds": 5}))
    assert out["state"] == "rejected"


async def test_runnable_agent_served_end_to_end(world):
    host, hc = world
    client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(host.cards["lc"])
    req = SendMessageRequest(
        message=Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="x")])
    )
    events = [ev async for ev in client.send_message(req)]
    task = events[-1].task
    assert task.status.state == TaskState.TASK_STATE_COMPLETED
    assert "lc says x" in "".join(p.text for a in task.artifacts for p in a.parts)


async def test_multi_delta_dict_chain_merged():
    from langchain_core.runnables import RunnablePassthrough

    chain = RunnableLambda(lambda t: {"a": t}) | RunnablePassthrough.assign(
        b=lambda d: "y", c=lambda d: "z"
    )
    evs = await collect(RunnableAdapter(chain), "x")
    [c] = [e for e in evs if isinstance(e, ArtifactChunk)]
    assert c.name == "result"
    assert MessageToDict(c.parts[0])["data"] == {"a": "x", "b": "y", "c": "z"}


async def test_contract_kit():
    seen: dict[str, list[str]] = {}

    async def remembering(text, config):
        history = seen.setdefault(config["configurable"]["thread_id"], [])
        history.append(text)
        yield "heard: "
        yield ", ".join(history)

    def boom(text):
        raise RuntimeError("boom")

    started, stopped = asyncio.Event(), asyncio.Event()

    async def block(text):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    adapter = RunnableAdapter(RunnableLambda(remembering))
    assert_text_stream(await drive(adapter, "hi"), "heard: hi")
    await assert_multi_turn(adapter, "apples", "pears", "apples")
    await assert_failure_maps(RunnableAdapter(RunnableLambda(boom)), match="boom")
    await assert_cancellable(
        RunnableAdapter(RunnableLambda(block)), started=started, stopped=stopped
    )
    client = FakePartnerClient()
    tools = as_langchain_tools(client.tools(), client)
    await assert_projection(tools, lambda t, args: t.ainvoke(args), client=client)
