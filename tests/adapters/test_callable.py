from __future__ import annotations

import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from google.protobuf.json_format import MessageToDict
from streaming_asgi import StreamingASGITransport

from a2agw.adapters.callable import CallableAdapter, agent, as_functions
from a2agw.consult.tools import UNTRUSTED_NOTE, partner_tools
from a2agw.core.events import (
    ArtifactChunk,
    Done,
    NeedInput,
    Status,
)
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


def ctx(text: str = "hi") -> InboundContext:
    m = Message(message_id="m", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message("x", m, task_id="t", context_id="c")


async def collect(adapter: CallableAdapter, text: str = "hi") -> list:
    return [e async for e in adapter.run(ctx(text))]


def chunk_text(c: ArtifactChunk) -> str:
    return "".join(p.text for p in c.parts)


async def test_str_return_completes():
    assert await collect(CallableAdapter(lambda c: f"got {c.text}")) == [Done(text="got hi")]


async def test_async_str_return():
    async def fn(c):
        return "async"

    assert await collect(CallableAdapter(fn)) == [Done(text="async")]


async def test_none_completes_without_text():
    assert await collect(CallableAdapter(lambda c: None)) == [Done()]


async def test_event_return_passes_through():
    assert await collect(CallableAdapter(lambda c: NeedInput("which?"))) == [NeedInput("which?")]


async def test_sync_function_runs_in_thread():
    import threading

    main = threading.get_ident()
    seen = []

    def fn(c):
        seen.append(threading.get_ident())
        return "ok"

    await collect(CallableAdapter(fn))
    assert seen and seen[0] != main


async def test_sync_generator_streams_with_last_flag():
    def fn(c):
        yield Status("working")
        yield "a"
        yield "b"
        yield "c"

    evs = await collect(CallableAdapter(fn))
    assert evs[0] == Status("working")
    chunks = evs[1:]
    assert [chunk_text(c) for c in chunks] == ["a", "b", "c"]
    assert [c.append for c in chunks] == [False, True, True]
    assert [c.last for c in chunks] == [False, False, True]
    assert all(c.artifact_id == "output" and c.name == "output" for c in chunks)


async def test_async_generator_streams_artifacts():
    async def fn(c):
        yield "one"
        yield "two"
        yield Done(text="fin")

    evs = await collect(CallableAdapter(fn))
    assert [type(e) for e in evs] == [ArtifactChunk, ArtifactChunk, Done]
    assert [(chunk_text(e), e.append, e.last) for e in evs[:2]] == [
        ("one", False, False),
        ("two", True, False),
    ]


async def test_non_str_event_flushes_buffer_first():
    async def fn(c):
        yield "a"
        yield Status("mid")
        yield "b"

    evs = await collect(CallableAdapter(fn))
    assert isinstance(evs[0], ArtifactChunk) and evs[0].last is False
    assert evs[1] == Status("mid")
    assert chunk_text(evs[2]) == "b" and evs[2].append is True and evs[2].last is True


async def test_need_input_from_callable():
    async def fn(c):
        yield NeedInput("which city?")

    assert await collect(CallableAdapter(fn)) == [NeedInput("which city?")]


async def test_bad_return_type_raises():
    with pytest.raises(TypeError):
        await collect(CallableAdapter(lambda c: 42))


async def test_exception_propagates():
    def fn(c):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await collect(CallableAdapter(fn))


def test_durable_sessions_flag():
    assert CallableAdapter(lambda c: None, durable_sessions=True).durable_sessions is True
    assert CallableAdapter(lambda c: None).durable_sessions is False


def test_decorator_builds_spec():
    @agent("echo-bot", allow_reentry=True)
    def echo_bot(ctx):
        """Echoes input.

        More detail.
        """
        return ctx.text

    assert isinstance(echo_bot, AgentSpec)
    assert echo_bot.id == "echo-bot"
    assert echo_bot.name == "Echo Bot"
    assert echo_bot.description == "Echoes input."
    assert echo_bot.allow_reentry is True
    assert isinstance(echo_bot.adapter, CallableAdapter)
    [skill] = echo_bot.skills
    assert (skill.id, skill.name, skill.description) == ("echo-bot", "Echo Bot", "Echoes input.")


def test_decorator_explicit_and_skill_dicts():
    @agent(
        "a",
        "Name",
        "Desc",
        skills=[{"id": "s1", "name": "S1", "description": "d"}],
        durable_sessions=True,
    )
    def fn(ctx):
        return None

    assert fn.name == "Name" and fn.description == "Desc"
    assert fn.skills == [SkillSpec(id="s1", name="S1", description="d")]
    assert fn.adapter.durable_sessions is True


def test_decorator_requires_description():
    with pytest.raises(ValueError):

        @agent("a")
        def no_doc(ctx):
            return None


# -- end to end --------------------------------------------------------------------------


async def test_as_functions_call_partner(tmp_path, monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    out: dict = {}

    @agent("pinger", "Pinger", "Answers pings")
    def pinger(c):
        return f"pong:{c.text}"

    @agent("caller", "Caller", "Consults pinger")
    async def caller(c):
        fns = {f.__name__: f for f in out["fns"]}
        res = await fns["ask_pinger"](message="ping", wait_seconds=5)
        out["res"] = res
        return res["text"]

    transport = StreamingASGITransport({})
    partner_hc = httpx.AsyncClient(transport=transport, base_url="http://t")
    host = AgentHost(
        "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", partner_http=partner_hc
    )
    host.add(pinger)
    host.add(caller)
    transport.apps["t"] = host.app()
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        await host.partners.add_from_card("pinger", MessageToDict(host.cards["pinger"]), "internal")
        tools = partner_tools(host.partners)
        out["fns"] = as_functions(tools, host.client)
        fn = next(f for f in out["fns"] if f.__name__ == "ask_pinger")
        assert fn.__qualname__ == "ask_pinger"
        assert fn.__doc__.endswith("\n\n" + UNTRUSTED_NOTE)
        assert fn.json_schema == fn.tool.parameters

        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["caller"]
        )
        req = SendMessageRequest(
            message=Message(
                message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="go")]
            )
        )
        events = [ev async for ev in client.send_message(req)]
        task = events[-1].task
        assert task.status.state == TaskState.TASK_STATE_COMPLETED
        assert out["res"]["state"] == "completed"
        assert "pong:ping" in out["res"]["text"]
    finally:
        await host.shutdown()
        await hc.aclose()
        await partner_hc.aclose()
