from __future__ import annotations

import asyncio
import types
import uuid
from typing import Annotated, Any, TypedDict

import httpx
import pytest

pytest.importorskip("langgraph.graph")

from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from adapters.contract import (
    assert_cancellable,
    assert_failure_maps,
    assert_isolated_callers,
    assert_multi_turn,
    assert_text_stream,
    drive,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

from a2agw.adapters.langgraph import GraphAdapter
from a2agw.core.events import ArtifactChunk, Done, Failed, NeedInput, Usage
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class State(TypedDict):
    messages: Annotated[list, add_messages]


def ctx(text: str = "hi", *, resumed: bool = False, context_id: str = "ctx-1") -> InboundContext:
    m = Message(message_id="m", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message("x", m, task_id="t", context_id=context_id, resumed=resumed)


async def collect(adapter: GraphAdapter, c: InboundContext) -> list:
    return [e async for e in adapter.run(c)]


def text_of(c: ArtifactChunk) -> str:
    return "".join(p.text for p in c.parts)


def echo_graph(checkpointer=None):
    def node(state: State):
        return {"messages": [AIMessage(content=f"echo:{state['messages'][-1].content}")]}

    g = StateGraph(State)
    g.add_node("echo", node)
    g.add_edge(START, "echo")
    g.add_edge("echo", END)
    return g.compile(checkpointer=checkpointer)


def ask_graph(checkpointer):
    def ask(state: State):
        answer = interrupt("which db?")
        return {"messages": [AIMessage(content=f"using {answer}")]}

    g = StateGraph(State)
    g.add_node("ask", ask)
    g.add_edge(START, "ask")
    g.add_edge("ask", END)
    return g.compile(checkpointer=checkpointer)


async def test_graph_completes():
    evs = await collect(GraphAdapter(echo_graph()), ctx("yo"))
    # LangGraph's messages mode also emits whole AI messages returned by plain nodes.
    assert [type(e) for e in evs] == [ArtifactChunk, Done]
    assert text_of(evs[0]) == "echo:yo" and evs[0].last is True
    assert evs[1] == Done()


async def test_done_text_falls_back_to_last_ai_message_in_updates():
    evs = await collect(GraphAdapter(echo_graph(), stream_nodes={"nowhere"}), ctx("yo"))
    assert evs == [Done(text="echo:yo")]


async def test_interrupt_maps_to_input_required_and_resume():
    adapter = GraphAdapter(ask_graph(InMemorySaver()))
    evs = await collect(adapter, ctx("start"))
    assert evs == [NeedInput(question="which db?")]
    evs = await collect(adapter, ctx("postgres", resumed=True))
    assert [text_of(e) for e in evs if isinstance(e, ArtifactChunk)] == ["using postgres"]
    assert evs[-1] == Done()


async def test_structured_interrupt_value_is_json():
    def ask(state: State):
        interrupt({"q": "which?", "n": 1})
        return {}

    g = StateGraph(State)
    g.add_node("ask", ask)
    g.add_edge(START, "ask")
    adapter = GraphAdapter(g.compile(checkpointer=InMemorySaver()))
    evs = await collect(adapter, ctx())
    assert evs == [NeedInput(question='{"q": "which?", "n": 1}')]


async def test_interrupt_without_checkpointer_fails_fast():
    evs = await collect(GraphAdapter(ask_graph(None)), ctx())
    assert len(evs) == 1 and isinstance(evs[0], Failed)
    assert "no checkpointer" in evs[0].error


async def test_legacy_bare_context_checkpoint_is_resumed():
    # A task paused before threads were keyed by caller and context: its checkpoint is under
    # the bare contextId. Inbound tasks are owner-scoped, so the resumed task is this caller's.
    saver = InMemorySaver()
    graph = ask_graph(saver)
    legacy = {"configurable": {"thread_id": "ctx-1"}}
    await graph.ainvoke({"messages": [("user", "start")]}, config=legacy)
    assert (await graph.aget_state(legacy)).interrupts  # paused under the old key
    adapter = GraphAdapter(graph)
    evs = await collect(adapter, ctx("postgres", resumed=True))
    assert [text_of(e) for e in evs if isinstance(e, ArtifactChunk)] == ["using postgres"]
    assert evs[-1] == Done()
    assert not (await graph.aget_state(legacy)).interrupts  # resumed in place
    # Only a resumed turn looks there: a new message starts on the caller's own thread.
    legacy2 = {"configurable": {"thread_id": "ctx-2"}}
    await graph.ainvoke({"messages": [("user", "start")]}, config=legacy2)
    evs = await collect(adapter, ctx("fresh", context_id="ctx-2"))
    assert evs == [NeedInput(question="which db?")]
    assert (await graph.aget_state(legacy2)).interrupts


async def test_resume_on_completed_thread_runs_as_fresh_input():
    adapter = GraphAdapter(echo_graph(InMemorySaver()))
    await collect(adapter, ctx("one"))
    evs = await collect(adapter, ctx("two", resumed=True))
    assert "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk)) == "echo:two"


async def test_resume_with_no_checkpoint_runs_as_fresh_input():
    evs = await collect(
        GraphAdapter(echo_graph(InMemorySaver())), ctx("hello", resumed=True, context_id="new")
    )
    assert "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk)) == "echo:hello"


async def test_resume_without_checkpointer_runs_as_fresh_input():
    evs = await collect(GraphAdapter(echo_graph(None)), ctx("hello", resumed=True))
    assert "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk)) == "echo:hello"


async def test_state_read_error_with_real_saver_propagates(monkeypatch, caplog):
    """Finding 4: a failing checkpointer read must fail the task, not silently restart the
    paused thread from fresh input."""
    graph = ask_graph(InMemorySaver())
    adapter = GraphAdapter(graph)
    await collect(adapter, ctx())  # paused at the interrupt

    class SaverDown(RuntimeError):
        pass

    async def broken(config, *args, **kwargs):
        raise SaverDown("db unavailable")

    monkeypatch.setattr(graph, "aget_state", broken)
    with pytest.raises(SaverDown):
        await collect(adapter, ctx("postgres", resumed=True))
    assert "SaverDown" in caplog.text


class _RemoteLike:
    """RemoteGraph shape: ``aget_state`` and ``astream``, no ``checkpointer`` attribute."""

    def __init__(self, state=None, error: Exception | None = None) -> None:
        self.state = state
        self.error = error
        self.payloads: list = []

    async def aget_state(self, config, *args, **kwargs):
        if self.error is not None:
            raise self.error
        return self.state

    async def astream(self, payload, config=None, stream_mode=None):
        self.payloads.append(payload)
        if isinstance(payload, Command):
            yield "messages", (AIMessageChunk(content="resumed"), {})
        else:
            yield "updates", {"__interrupt__": [types.SimpleNamespace(value="which db?")]}


async def test_remote_graph_without_checkpointer_attr_resumes():
    """RemoteGraph has aget_state but no local checkpointer: its pending interrupt resumes."""
    interrupt = types.SimpleNamespace(value="which db?")
    graph = _RemoteLike(state=types.SimpleNamespace(interrupts=(interrupt,), tasks=()))
    adapter = GraphAdapter(graph)
    evs = await collect(adapter, ctx())
    assert isinstance(evs[-1], NeedInput) and evs[-1].question == "which db?"
    await collect(adapter, ctx("postgres", resumed=True))
    assert isinstance(graph.payloads[-1], Command)


async def test_remote_graph_state_error_propagates():
    class RemoteDown(RuntimeError):
        pass

    adapter = GraphAdapter(_RemoteLike(error=RemoteDown("server down")))
    with pytest.raises(RemoteDown):
        await collect(adapter, ctx("postgres", resumed=True))


async def test_subgraph_interrupt_maps_and_resumes():
    sub = ask_graph(None)  # inherits the parent's checkpointer
    g = StateGraph(State)
    g.add_node("sub", sub)
    g.add_edge(START, "sub")
    adapter = GraphAdapter(g.compile(checkpointer=InMemorySaver()))
    assert await collect(adapter, ctx("go")) == [NeedInput(question="which db?")]
    evs = await collect(adapter, ctx("pg", resumed=True))
    assert "using pg" in "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk))


async def test_usage_counts_nodes_excluded_by_stream_nodes():
    graph = llm_graph(UsageModel())
    evs = await collect(GraphAdapter(graph, stream_nodes={"nowhere"}), ctx())
    assert not any(isinstance(e, ArtifactChunk) for e in evs)
    assert Usage(tokens_in=5, tokens_out=2) in evs


async def test_custom_input_mapper_and_thread_id():
    seen: dict[str, Any] = {}

    def node(state: dict, config):
        seen["thread"] = config["configurable"]["thread_id"]
        seen["q"] = state["q"]
        return {"out": "done"}

    class S(TypedDict):
        q: str
        out: str

    g = StateGraph(S)
    g.add_node("n", node)
    g.add_edge(START, "n")
    g.add_edge("n", END)
    adapter = GraphAdapter(g.compile(), input_mapper=lambda c: {"q": c.text.upper()})
    evs = await collect(adapter, ctx("abc", context_id="ctx-9"))
    assert seen == {"thread": "anonymous\x1fctx-9", "q": "ABC"}
    assert evs == [Done()]  # no AI message under "messages"


def test_durable_flag_false_for_inmemory():
    assert GraphAdapter(echo_graph(InMemorySaver())).durable_sessions is False
    assert GraphAdapter(echo_graph(None)).durable_sessions is False


def test_durable_flag_false_for_non_saver_values():
    class Fake:
        checkpointer = True

    assert GraphAdapter(Fake()).durable_sessions is False  # type: ignore[arg-type]
    Fake.checkpointer = False  # type: ignore[assignment]
    assert GraphAdapter(Fake()).durable_sessions is False  # type: ignore[arg-type]


def test_durable_flag_true_for_sqlite_saver(tmp_path):
    sqlite = pytest.importorskip("langgraph.checkpoint.sqlite")
    import sqlite3

    conn = sqlite3.connect(tmp_path / "cp.db", check_same_thread=False)
    try:
        graph = echo_graph(sqlite.SqliteSaver(conn))
        assert GraphAdapter(graph).durable_sessions is True
    finally:
        conn.close()


# -- streaming LLM nodes ------------------------------------------------------------------


class UsageModel(BaseChatModel):
    @property
    def _llm_type(self) -> str:
        return "usage-fake"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kw):
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ab"))])

    async def _astream(self, messages, stop=None, run_manager=None, **kw):
        for text, i, o in (("a", 5, 0), ("b", 0, 2)):
            yield ChatGenerationChunk(
                message=AIMessageChunk(
                    content=text,
                    usage_metadata={"input_tokens": i, "output_tokens": o, "total_tokens": i + o},
                )
            )


def llm_graph(model, *, extra_text: str | None = None):
    async def llm(state: State):
        return {"messages": [await model.ainvoke(state["messages"])]}

    g = StateGraph(State)
    g.add_node("llm", llm)
    g.add_edge(START, "llm")
    if extra_text is None:
        g.add_edge("llm", END)
    else:
        extra = GenericFakeChatModel(messages=iter([AIMessage(content=extra_text)]))

        async def other(state: State):
            return {"messages": [await extra.ainvoke(state["messages"])]}

        g.add_node("other", other)
        g.add_edge("llm", "other")
        g.add_edge("other", END)
    return g.compile()


async def test_llm_node_streams_chunks_and_usage():
    evs = await collect(GraphAdapter(llm_graph(UsageModel())), ctx())
    chunks = [e for e in evs if isinstance(e, ArtifactChunk)]
    assert [text_of(c) for c in chunks] == ["a", "b"]
    assert [c.last for c in chunks] == [False, True]
    assert [c.append for c in chunks] == [False, True]
    assert evs[-2:] == [Usage(tokens_in=5, tokens_out=2), Done()]
    assert not any(isinstance(e, Done) and e.text for e in evs)


async def test_stream_nodes_filters_other_nodes():
    model = GenericFakeChatModel(messages=iter([AIMessage(content="from llm node")]))
    graph = llm_graph(model, extra_text="from other node")
    evs = await collect(GraphAdapter(graph, stream_nodes={"llm"}), ctx())
    streamed = "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk))
    assert streamed == "from llm node"
    assert evs[-1] == Done()


async def test_unfiltered_streams_all_nodes():
    model = GenericFakeChatModel(messages=iter([AIMessage(content="one")]))
    graph = llm_graph(model, extra_text="two")
    evs = await collect(GraphAdapter(graph), ctx())
    assert "".join(text_of(e) for e in evs if isinstance(e, ArtifactChunk)) == "onetwo"


# -- end to end through AgentHost ---------------------------------------------------------


def make_spec(graph) -> AgentSpec:
    return AgentSpec(
        id="g",
        name="G",
        description="A graph agent",
        skills=[SkillSpec(id="g", name="G", description="A graph agent")],
        adapter=GraphAdapter(graph),
    )


def user_msg(text: str, *, context_id=None, task_id=None) -> Message:
    return Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text=text)],
        context_id=context_id or "",
        task_id=task_id or "",
    )


async def send(host: AgentHost, message: Message):
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["g"]
        )
        return [ev async for ev in client.send_message(SendMessageRequest(message=message))]
    finally:
        await hc.aclose()


def final_task(events):
    return events[-1].task


async def test_host_interrupt_resume_end_to_end(tmp_path):
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(make_spec(ask_graph(InMemorySaver())))
    await host.startup()
    try:
        t1 = final_task(await send(host, user_msg("go")))
        assert t1.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
        assert "which db?" in "".join(p.text for p in t1.status.message.parts)
        t2 = final_task(
            await send(host, user_msg("postgres", context_id=t1.context_id, task_id=t1.id))
        )
        assert (t2.id, t2.context_id) == (t1.id, t1.context_id)
        assert t2.status.state == TaskState.TASK_STATE_COMPLETED
        assert "using postgres" in "".join(p.text for a in t2.artifacts for p in a.parts) + "".join(
            p.text for p in t2.status.message.parts
        )
    finally:
        await host.shutdown()


async def test_durable_checkpointer_survives_restart(tmp_path):
    sqlite_aio = pytest.importorskip("langgraph.checkpoint.sqlite.aio")
    cp_path = str(tmp_path / "cp.db")
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'h.db'}"

    async with sqlite_aio.AsyncSqliteSaver.from_conn_string(cp_path) as saver:
        host = AgentHost("http://t", db_url=db_url)
        host.add(make_spec(ask_graph(saver)))
        await host.startup()
        try:
            t1 = final_task(await send(host, user_msg("go")))
            assert t1.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
        finally:
            await host.shutdown()

    # "Restart": brand-new host, graph and saver over the same DB files.
    async with sqlite_aio.AsyncSqliteSaver.from_conn_string(cp_path) as saver2:
        host2 = AgentHost("http://t", db_url=db_url)
        host2.add(make_spec(ask_graph(saver2)))
        await host2.startup()
        try:
            assert host2.last_recovery.failed == []
            assert t1.id in host2.last_recovery.kept
            t2 = final_task(
                await send(host2, user_msg("sqlite", context_id=t1.context_id, task_id=t1.id))
            )
            assert t2.status.state == TaskState.TASK_STATE_COMPLETED
        finally:
            await host2.shutdown()


async def test_contract_kit():
    def remembering(state: State):
        heard = ", ".join(m.content for m in state["messages"] if m.type == "human")
        return {"messages": [AIMessage(content=f"heard: {heard}")]}

    def boom(state: State):
        raise RuntimeError("boom")

    started, stopped = asyncio.Event(), asyncio.Event()

    async def block(state: State):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    def one_node(fn, checkpointer=None):
        g = StateGraph(State)
        g.add_node("n", fn)
        g.add_edge(START, "n")
        g.add_edge("n", END)
        return GraphAdapter(g.compile(checkpointer=checkpointer))

    adapter = one_node(remembering, InMemorySaver())
    assert_text_stream(await drive(adapter, "hi"), "heard: hi")
    await assert_multi_turn(adapter, "apples", "pears", "apples")
    await assert_failure_maps(one_node(boom), match="boom")
    await assert_cancellable(one_node(block), started=started, stopped=stopped)


async def test_isolated_callers():
    # The checkpointer thread is per caller: another principal sending the same contextId
    # starts its own thread.
    def remembering(state: State):
        heard = ", ".join(m.content for m in state["messages"] if m.type == "human")
        return {"messages": [AIMessage(content=f"heard: {heard}")]}

    g = StateGraph(State)
    g.add_node("n", remembering)
    g.add_edge(START, "n")
    g.add_edge("n", END)
    adapter = GraphAdapter(g.compile(checkpointer=InMemorySaver()))
    await assert_isolated_callers(adapter, "apples", "pears", "apples")
