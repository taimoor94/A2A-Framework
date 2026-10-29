from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from collections.abc import AsyncIterator
from typing import Any

import pytest

pytest.importorskip("claude_agent_sdk")

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
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    StreamEvent,
    SystemMessage,
    TextBlock,
    ToolUseBlock,
    Transport,
)
from mcp.client import Client

import a2agw.adapters.claude_agent as ca
from a2agw.adapters.claude_agent import ClaudeAgentAdapter, as_claude_tools
from a2agw.consult.tools import UNTRUSTED_NOTE
from a2agw.context.call_context import current_inbound_task, use_inbound
from a2agw.core.events import ArtifactChunk, Done, Failed, Status, Usage

# -- SDK message builders -----------------------------------------------------------------


def init(sid: str) -> SystemMessage:
    return SystemMessage(
        subtype="init", data={"type": "system", "subtype": "init", "session_id": sid}
    )


def delta(text: str, sid: str = "s", *, parent: str | None = None) -> StreamEvent:
    event = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": text},
    }
    return StreamEvent(uuid="u", session_id=sid, event=event, parent_tool_use_id=parent)


def assistant(*blocks: Any, parent: str | None = None) -> AssistantMessage:
    content = [TextBlock(text=b) if isinstance(b, str) else b for b in blocks]
    return AssistantMessage(content=content, model="claude-fake", parent_tool_use_id=parent)


def result(
    sid: str = "s",
    *,
    text: str | None = None,
    subtype: str = "success",
    is_error: bool = False,
    usage: dict[str, Any] | None = None,
    cost: float | None = None,
) -> ResultMessage:
    return ResultMessage(
        subtype=subtype,
        duration_ms=1,
        duration_api_ms=1,
        is_error=is_error,
        num_turns=1,
        session_id=sid,
        total_cost_usd=cost,
        usage=usage,
        result=text,
    )


# -- a scripted fake ``query`` --------------------------------------------------------------

BLOCK = "block"  # yields the init message, then waits until closed or cancelled
RAISE = "raise"


class FakeClaude:
    """Stands in for ``claude_agent_sdk.query`` (the Claude Code CLI is never started).

    Each call plays the next script: a list of messages, ``BLOCK`` or ``RAISE``. With no
    script left it echoes "heard: <every prompt of this session>", keeping one history per
    session id and continuing the session named by ``options.resume`` (as the CLI does)."""

    def __init__(self, *scripts: Any) -> None:
        self.scripts = list(scripts)
        self.calls: list[tuple[str, ClaudeAgentOptions]] = []
        self.sessions: dict[str, list[str]] = {}
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    async def __call__(
        self, *, prompt: str, options: ClaudeAgentOptions | None = None
    ) -> AsyncIterator[Any]:
        assert options is not None
        self.calls.append((prompt, options))
        script = self.scripts.pop(0) if self.scripts else None
        if script == BLOCK:
            yield init("s-block")
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.stopped.set()
        if script == RAISE:
            raise RuntimeError("CLI exploded")
        if script is not None:
            for message in script:
                yield message
            return
        sid = options.resume if options.resume in self.sessions else f"s-{len(self.sessions)}"
        history = self.sessions.setdefault(sid, [])
        history.append(prompt)
        yield init(sid)
        chunks = ["heard: ", ", ".join(history)]
        if options.include_partial_messages:
            for chunk in chunks:
                yield delta(chunk, sid)
        yield assistant("".join(chunks))
        yield result(sid, text="".join(chunks))


# -- inbound ------------------------------------------------------------------------------


async def test_streams_text():
    fake = FakeClaude(
        [init("s"), delta("Hel"), delta("lo"), delta(" world"), assistant("Hello world"), result()]
    )
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert_text_stream(evs, "Hello world")
    # Streamed delta by delta; the complete AssistantMessage does not repeat the text.
    assert sum(1 for e in evs if isinstance(e, ArtifactChunk)) == 3
    assert evs[-1] == Done()
    [(prompt, options)] = fake.calls
    assert prompt == "hi" and options.include_partial_messages is True


async def test_streams_text_blocks_without_partial_messages():
    # One chunk per text block when the CLI sends no partial messages.
    fake = FakeClaude([init("s"), assistant("Hello", " world"), assistant("!"), result()])
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert_text_stream(evs, "Hello world!")
    assert sum(1 for e in evs if isinstance(e, ArtifactChunk)) == 3


async def test_partial_and_complete_messages_mixed():
    # Deltas stand for the AssistantMessage that follows them, and only for that one.
    fake = FakeClaude([init("s"), delta("one "), assistant("one "), assistant("two"), result()])
    assert_text_stream(await drive(ClaudeAgentAdapter(query=fake), "hi"), "one two")


async def test_tool_use_is_status_and_subagent_text_is_not_output():
    use = ToolUseBlock(id="tu-1", name="mcp__a2a_partners__ask_pinger", input={"message": "x"})
    fake = FakeClaude(
        [
            init("s"),
            assistant("Asking. ", use),
            delta("inner", parent="tu-1"),
            assistant("subagent text", parent="tu-1"),
            assistant("Done."),
            result(),
        ]
    )
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert Status("calling mcp__a2a_partners__ask_pinger") in evs
    assert output_text(evs) == "Asking. Done."


async def test_result_text_when_nothing_streamed():
    fake = FakeClaude([init("s"), result(text="all at once")])
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert evs == [Done(text="all at once")]


async def test_resume_uses_session_id_per_context():
    fake = FakeClaude()
    options = ClaudeAgentOptions(model="claude-fake", max_turns=3)
    adapter = ClaudeAgentAdapter(options, query=fake)
    await drive(adapter, "a1", context_id="c-a")
    await drive(adapter, "b1", context_id="c-b")
    evs = await drive(adapter, "a2", context_id="c-a")
    assert output_text(evs) == "heard: a1, a2"
    assert [o.resume for _, o in fake.calls] == [None, None, "s-0"]
    # Every other option is passed through; the caller's options object is not changed.
    assert all(o.model == "claude-fake" and o.max_turns == 3 for _, o in fake.calls)
    assert all(o is not options for _, o in fake.calls)
    assert options.resume is None and options.include_partial_messages is False


async def test_session_id_from_init_message():
    # A turn that fails after the init message still names the session to resume.
    fake = FakeClaude([init("s-early")], None)
    adapter = ClaudeAgentAdapter(query=fake)
    evs = await drive(adapter, "first")
    assert evs[-1] == Failed("agent error")  # no result message
    await drive(adapter, "second")
    assert fake.calls[1][1].resume == "s-early"


async def test_multi_turn_session_memory():
    await assert_multi_turn(ClaudeAgentAdapter(query=FakeClaude()), "apples", "pears", "apples")


async def test_result_usage_and_cost():
    usage = {
        "input_tokens": 10,
        "cache_read_input_tokens": 3,
        "cache_creation_input_tokens": 2,
        "output_tokens": 5,
    }
    fake = FakeClaude([init("s"), assistant("ok"), result(usage=usage, cost=0.0123)])
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert evs[-2:] == [Usage(tokens_in=15, tokens_out=5, cost=0.0123), Done()]
    # Nothing to report: no Usage event.
    fake = FakeClaude([init("s"), assistant("ok"), result(usage={}, cost=0.0)])
    evs = await drive(ClaudeAgentAdapter(query=fake), "hi")
    assert not any(isinstance(e, Usage) for e in evs)


async def test_error_result_fails():
    for res in (
        result(subtype="error_during_execution", is_error=True, cost=0.5),
        result(subtype="error_max_turns", is_error=False),
        result(subtype="success", is_error=True, text="API Error: 529 secret detail"),
    ):
        evs = await drive(ClaudeAgentAdapter(query=FakeClaude([init("s"), res])), "hi")
        assert evs[-1] == Failed("agent error"), evs
        assert not any(isinstance(e, Done) for e in evs)
    # The cost of a failed run is still reported.
    res = result(subtype="error_during_execution", is_error=True, cost=0.5)
    evs = await drive(ClaudeAgentAdapter(query=FakeClaude([init("s"), res])), "hi")
    assert evs == [Usage(cost=0.5), Failed("agent error")]
    await assert_failure_maps(
        ClaudeAgentAdapter(query=FakeClaude([result(subtype="error_max_turns")])),
        match="agent error",
    )


async def test_query_error_propagates():
    await assert_failure_maps(ClaudeAgentAdapter(query=FakeClaude(RAISE)), match="CLI exploded")


async def test_cancellable():
    fake = FakeClaude(BLOCK)
    await assert_cancellable(
        ClaudeAgentAdapter(query=fake), started=fake.started, stopped=fake.stopped
    )


async def test_closing_the_stream_closes_the_query():
    stopped = asyncio.Event()

    async def endless(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[Any]:
        try:
            yield init("s")
            yield delta("one")
            yield delta("two")
            await asyncio.Event().wait()
        finally:
            stopped.set()

    gen = ClaudeAgentAdapter(query=endless).run(make_ctx("x"))
    first = await anext(gen)  # "one" (held back until "two" arrived)
    assert isinstance(first, ArtifactChunk)
    await gen.aclose()  # the executor stops reading (e.g. the task was canceled)
    # ``query``'s generator is closed right away (in the real SDK that stops the CLI
    # subprocess), not whenever the garbage collector finalises it.
    assert stopped.is_set()


async def test_turns_on_one_context_are_serialised():
    release = asyncio.Event()
    fake = FakeClaude()
    entered: list[str] = []

    async def gated(*, prompt: str, options: ClaudeAgentOptions) -> AsyncIterator[Any]:
        entered.append(prompt)
        if prompt == "one":
            fake.started.set()
            await release.wait()
        async for m in fake(prompt=prompt, options=options):
            yield m

    adapter = ClaudeAgentAdapter(query=gated)
    one = asyncio.create_task(drive(adapter, "one", context_id="c-ser"))
    await asyncio.wait_for(fake.started.wait(), 2)
    two = asyncio.create_task(drive(adapter, "two", context_id="c-ser"))
    other = await drive(adapter, "elsewhere", context_id="c-other")  # not blocked
    assert output_text(other) == "heard: elsewhere"
    for _ in range(20):
        await asyncio.sleep(0)
    assert not two.done() and entered == ["one", "elsewhere"]  # "two" waits for "one"
    release.set()
    await one
    # "two" started after "one" recorded its session, so it resumes it.
    assert output_text(await two) == "heard: one, two"


async def test_idle_contexts_evicted_with_their_session(monkeypatch):
    monkeypatch.setattr(ca, "MAX_SESSIONS", 2)
    fake = FakeClaude(BLOCK)
    adapter = ClaudeAgentAdapter(query=fake)
    busy = asyncio.create_task(drive(adapter, "busy", context_id="c-busy"))
    await asyncio.wait_for(fake.started.wait(), 2)
    for cid in ("c-1", "c-2", "c-3"):
        await drive(adapter, "x", context_id=cid)
    # The in-flight context is kept; the oldest idle ones went, lock and session id together.
    assert list(adapter._contexts) == ["anonymous\x1fc-busy", "anonymous\x1fc-3"]
    busy.cancel()
    await asyncio.wait({busy})
    evs = await drive(adapter, "again", context_id="c-1")
    assert output_text(evs) == "heard: again"  # a fresh session
    assert fake.calls[-1][1].resume is None
    assert ca.MAX_SESSIONS == 2 and ca.DEFAULT_MAX_SESSIONS == 10_000


async def test_session_store_keeps_the_map():
    store: dict[str, str] = {}
    fake = FakeClaude()
    await drive(ClaudeAgentAdapter(query=fake, session_store=store), "a1", context_id="c-a")
    assert store == {"anonymous\x1fc-a": "s-0"}  # keyed by caller and context
    # A new adapter (e.g. after a restart) with the same store resumes the session.
    adapter = ClaudeAgentAdapter(query=fake, durable_sessions=True, session_store=store)
    evs = await drive(adapter, "a2", context_id="c-a")
    assert output_text(evs) == "heard: a1, a2"
    assert fake.calls[-1][1].resume == "s-0"


def test_durable_sessions_need_a_session_store():
    fake = FakeClaude()
    assert ClaudeAgentAdapter(query=fake).durable_sessions is False
    with pytest.raises(ValueError, match="session_store"):
        ClaudeAgentAdapter(query=fake, durable_sessions=True)
    adapter = ClaudeAgentAdapter(query=fake, durable_sessions=True, session_store={})
    assert adapter.durable_sessions is True


@pytest.mark.parametrize(
    "field, value",
    [
        ("continue_conversation", True),
        ("session_id", "fixed-session"),
        ("fork_session", True),
        ("resume", "some-session"),
        ("resume_session_at", "msg-uuid"),
    ],
)
def test_options_that_pick_the_session_are_refused(field, value):
    # Each would make turns of different A2A contexts continue, fork or share one session
    # (the adapter picks the session per context with ``resume``): a cross-context leak.
    options = ClaudeAgentOptions(**{field: value})
    with pytest.raises(ValueError, match=field):
        ClaudeAgentAdapter(options, query=FakeClaude())


async def test_session_options_set_after_construction_are_refused():
    options = ClaudeAgentOptions()
    fake = FakeClaude()
    adapter = ClaudeAgentAdapter(options, query=fake)
    options.continue_conversation = True  # changed on the caller's object later
    with pytest.raises(ValueError, match="continue_conversation"):
        await drive(adapter, "hi")
    assert fake.calls == []  # refused before the CLI would have started


def test_session_options_left_at_their_defaults_are_accepted():
    options = ClaudeAgentOptions(continue_conversation=False, fork_session=False)
    assert ClaudeAgentAdapter(options, query=FakeClaude()).options is options


def test_default_query_is_the_sdks():
    import claude_agent_sdk

    assert ClaudeAgentAdapter().query is claude_agent_sdk.query


# -- outbound -----------------------------------------------------------------------------


async def call_tool(server: Any, name: str, args: dict[str, Any]) -> Any:
    """Call a projected tool through the SDK's in-process MCP server (the SDK validates the
    arguments against the schema, then runs the handler) and return its text."""
    async with Client(server["instance"]) as mcp:
        res = await mcp.call_tool(name, args)
    [content] = res.content
    return content.text, res.is_error


async def test_tools_server_call_reaches_partner_client():
    client = FakePartnerClient()
    server = as_claude_tools(client.tools(), client)
    text, is_error = await call_tool(server, "ask_pinger", {"message": "hi"})
    assert is_error is False
    envelope = json.loads(text)
    assert (envelope["state"], envelope["text"], envelope["task_id"]) == (
        "completed",
        "pong:hi",
        "pt-1",
    )
    assert [c["message"] for c in client.consults] == ["hi"]

    async def via_server(tool: Any, args: dict) -> Any:
        return (await call_tool(server, tool.name, args))[0]

    client2 = FakePartnerClient()
    server = as_claude_tools(client2.tools(), client2)
    await assert_projection(client2.tools(), via_server, client=client2)


async def test_tool_errors_are_answered():
    client = FakePartnerClient()
    server = as_claude_tools(client.tools(), client)
    # Schema violations are answered by the SDK before the handler runs.
    text, is_error = await call_tool(server, "ask_pinger", {"message": "hi", "bogus": 1})
    assert is_error is True and "validation" in text.lower()
    # Gateway-only limits (``x-`` keywords) are still enforced by ``invoke``.
    big = {"message": "hi", "data": {"blob": "x" * 40_000}}  # over ``x-max-json-bytes``
    text, is_error = await call_tool(server, "ask_pinger", big)
    assert json.loads(text)["state"] == "rejected"
    assert client.consults == []


async def test_projected_tools_listing():
    client = FakePartnerClient()
    ptools = client.tools()
    server = as_claude_tools(ptools, client)
    assert server["type"] == "sdk" and server["name"] == "a2a_partners"
    assert as_claude_tools(ptools, client, server_name="peers")["name"] == "peers"
    async with Client(server["instance"]) as mcp:
        listed = (await mcp.list_tools()).tools
    assert [t.name for t in listed] == [p.name for p in ptools]
    for t, p in zip(listed, ptools, strict=True):
        assert t.description.endswith(UNTRUSTED_NOTE)
        assert t.description.count(UNTRUSTED_NOTE) == 1
        assert "x-max-json-bytes" not in json.dumps(t.input_schema)
        assert t.input_schema["required"] == p.parameters["required"]
    assert "x-max-json-bytes" in json.dumps(ptools[0].parameters)  # the original is untouched


async def test_tool_calls_run_under_the_inbound_task():
    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    server = as_claude_tools(client.tools(), client)
    # The SDK serves the tools from tasks it starts inside the turn, so they inherit the
    # inbound contextvars the same way.
    with use_inbound("inbound-1", None):
        await call_tool(server, "ask_pinger", {"message": "hi"})
    assert seen == ["inbound-1"]


class ScriptedCLI(Transport):
    """A stand-in for the CLI on the other end of the SDK's control protocol: the real
    ``claude_agent_sdk.query`` runs against it (no subprocess). It answers ``initialize``,
    and on the user's message calls ``tool`` on SDK MCP server ``server`` through
    ``mcp_message`` control requests (MCP handshake, then ``tools/call``), as the CLI does,
    then streams the tool's text back as the answer."""

    def __init__(self, server: str, tool: str, args: dict[str, Any]) -> None:
        self.server, self.tool, self.args = server, tool, args
        self.out: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self.mcp: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.driver: asyncio.Task[None] | None = None
        self.ready = False

    async def connect(self) -> None:
        self.ready = True

    def is_ready(self) -> bool:
        return self.ready

    async def write(self, data: str) -> None:
        msg = json.loads(data)
        if msg["type"] == "control_request" and msg["request"]["subtype"] == "initialize":
            ok = {"subtype": "success", "request_id": msg["request_id"], "response": {}}
            await self.out.put({"type": "control_response", "response": ok})
        elif msg["type"] == "user":
            self.driver = asyncio.create_task(self._turn())
        elif msg["type"] == "control_response":
            await self.mcp.put(msg["response"])

    async def _rpc(self, n: int, message: dict[str, Any]) -> dict[str, Any]:
        request = {"subtype": "mcp_message", "server_name": self.server, "message": message}
        await self.out.put(
            {"type": "control_request", "request_id": f"cli-{n}", "request": request}
        )
        response = await self.mcp.get()
        assert response["subtype"] == "success" and response["request_id"] == f"cli-{n}"
        return response["response"]["mcp_response"]

    async def _turn(self) -> None:
        from mcp.types import LATEST_PROTOCOL_VERSION

        await self.out.put({"type": "system", "subtype": "init", "session_id": "s-cli"})
        init_params = {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "scripted-cli", "version": "0"},
        }
        await self._rpc(
            1, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": init_params}
        )
        await self._rpc(2, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        call = {"name": self.tool, "arguments": self.args}
        res = await self._rpc(
            3, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": call}
        )
        text = res["result"]["content"][0]["text"]
        message = {"content": [{"type": "text", "text": text}], "model": "claude-fake"}
        await self.out.put({"type": "assistant", "message": message, "parent_tool_use_id": None})
        await self.out.put(
            {
                "type": "result",
                "subtype": "success",
                "duration_ms": 1,
                "duration_api_ms": 1,
                "is_error": False,
                "num_turns": 1,
                "session_id": "s-cli",
                "result": text,
            }
        )

    async def read_messages(self) -> AsyncIterator[dict[str, Any]]:
        while (msg := await self.out.get()) is not None:
            yield msg

    async def end_input(self) -> None:
        await self.out.put(None)  # the CLI exits once its stdin closes after the result

    async def close(self) -> None:
        self.ready = False
        if self.driver is not None:
            self.driver.cancel()


async def test_real_query_serves_partner_tools_under_the_inbound_task():
    # The real SDK ``query`` (control protocol, SDK MCP bridge, in-process MCP server) between
    # a scripted CLI and the projected tool: the tool runs in tasks the SDK starts, and must
    # still see the inbound task's contextvars. Pins that propagation against SDK upgrades.
    import functools

    import claude_agent_sdk

    seen: list[str | None] = []

    class Recording(FakePartnerClient):
        async def consult(self, partner_id: str, message: str, **kwargs: Any) -> Any:
            seen.append(current_inbound_task.get())
            return await super().consult(partner_id, message, **kwargs)

    client = Recording()
    options = ClaudeAgentOptions(
        mcp_servers={"a2a_partners": as_claude_tools(client.tools(), client)}
    )
    cli = ScriptedCLI("a2a_partners", "ask_pinger", {"message": "hi"})
    query = functools.partial(claude_agent_sdk.query, transport=cli)
    with use_inbound("inbound-1", None):
        evs = await asyncio.wait_for(drive(ClaudeAgentAdapter(options, query=query), "go"), 10)
    assert seen == ["inbound-1"]
    envelope = json.loads(output_text(evs))
    assert (envelope["state"], envelope["text"]) == ("completed", "pong:hi")
    assert isinstance(evs[-1], Done)


async def test_contract_kit():
    adapter = ClaudeAgentAdapter(query=FakeClaude())
    assert_text_stream(await drive(adapter, "hi"), "heard: hi")
    await assert_multi_turn(adapter, "apples", "pears", "apples")
    failing = ClaudeAgentAdapter(query=FakeClaude([result(subtype="error_during_execution")]))
    await assert_failure_maps(failing, match="agent error")
    fake = FakeClaude(BLOCK)
    await assert_cancellable(
        ClaudeAgentAdapter(query=fake), started=fake.started, stopped=fake.stopped
    )
    client = FakePartnerClient()
    server = as_claude_tools(client.tools(), client)
    tools = client.tools()

    async def call(tool: Any, args: dict) -> Any:
        return (await call_tool(server, tool.name, args))[0]

    await assert_projection(tools, call, client=client)


async def test_served_end_to_end(tmp_path):
    import uuid

    import httpx
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
    from streaming_asgi import StreamingASGITransport

    from a2agw.serve.agent import AgentSpec, SkillSpec
    from a2agw.serve.host import AgentHost

    fake = FakeClaude(
        [init("s"), delta("served "), delta("fine"), assistant("served fine"), result(cost=0.01)]
    )
    spec = AgentSpec(
        id="claude",
        name="Claude",
        description="A Claude Agent SDK agent",
        skills=[SkillSpec(id="c", name="C", description="Echoes")],
        adapter=ClaudeAgentAdapter(query=fake),
    )
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    host.add(spec)
    await host.startup()
    hc = httpx.AsyncClient(transport=StreamingASGITransport({"t": host.app()}), base_url="http://t")
    try:
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["claude"]
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
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)  # the import raises ImportError
    spec = importlib.util.spec_from_file_location("_ca_probe", ca.__file__)
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match=r"a2a-gateway\[claude\]"):
        spec.loader.exec_module(module)


def test_core_does_not_import_claude_agent_sdk():
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.adapters.callable, a2agw.cli, a2agw.config,"
        " a2agw.gateway.rest;"
        "print([m for m in sys.modules if m.split('.')[0] == 'claude_agent_sdk'])"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"


async def test_example_runs():
    from examples.adapters import claude_agent_example

    assert await claude_agent_example.main() == "echo: hello from A2A"


async def test_isolated_callers():
    # Another caller sending the same contextId does not resume this one's Claude session.
    await assert_isolated_callers(
        ClaudeAgentAdapter(query=FakeClaude()), "apples", "pears", "apples"
    )


async def test_owned_tasks_only():
    # Partner tasks belong to whoever started them: a foreign task id answers "unknown task".
    from adapters.contract import FakePartnerClient, assert_owned_tasks_only

    client = FakePartnerClient()
    server = as_claude_tools(client.tools(), client)

    async def call(tool, args):
        return (await call_tool(server, tool.name, args))[0]

    await assert_owned_tasks_only(client.tools(), call, client)
