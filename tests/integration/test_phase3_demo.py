"""Phase 3 "done when": a non-Python agent and an MCP-only agent join the demo network.

The MCP client (an MCP-only agent, standing in for Claude Code or Cursor) asks ``pm`` through
the gateway's MCP server. ``pm`` delegates to ``architect`` and to the Node ``coder`` (a
webhook agent, run here as a ``node`` subprocess), and the coder consults ``security``
through the outbound REST API with its turn's consult token. One trace, one audit chain.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import socket
import time

import httpx
import pytest
from a2a.types import TaskState

from a2agw.gateway.protocol import sign
from a2agw.gateway.tokens import ConsultTokens
from examples.software_team import run_demo, security

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")
COMPLETED = TaskState.Name(TaskState.TASK_STATE_COMPLETED)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_node_and_mcp_agents_join_the_network(spans, fast, monkeypatch, caplog, capsys):
    monkeypatch.setattr(security, "STEP_DELAY_S", 0.2)
    caplog.set_level(logging.DEBUG)
    tokens: list[str] = []
    issue = ConsultTokens.issue

    def recording_issue(self, *args, **kwargs):
        grant = issue(self, *args, **kwargs)
        tokens.append(grant.token)
        return grant

    monkeypatch.setattr(ConsultTokens, "issue", recording_issue)

    result = await run_demo.run_network(port=_free_port(), phase3=True)

    # The MCP-only agent listed the tools, consulted pm, and waited on the handle.
    assert result.mcp is not None
    assert {"ask_pm", "a2a_wait"} <= set(result.mcp.tools)
    assert result.mcp.first["state"] == "working"
    final = result.mcp.final
    assert final["state"] == "completed", final
    assert "## Architecture" in final["text"]
    assert "## Code" in final["text"] and "node coder" in final["text"]
    assert "## Security review" in final["text"]

    # The Node agent's partner call is linked to its inbound task.
    [coder_task] = result.coder_tasks
    linked = [h for h in result.coder_handles if h["partner_id"] == "security"]
    assert linked, result.coder_handles
    assert all(h["inbound_task_id"] == coder_task for h in linked)
    assert [h["state"] for h in linked] == [COMPLETED]

    # One trace id spans every hop: MCP -> pm -> architect / coder -> security.
    a2a = [s for s in spans.get_finished_spans() if s.name.startswith("a2agw.")]
    inbound = {s.attributes.get("a2agw.agent_id") for s in a2a if s.name == "a2agw.inbound"}
    assert inbound >= {"pm", "architect", "coder", "security"}
    assert len({s.context.trace_id for s in a2a}) == 1
    # The coder's REST consult is a child of the coder's own inbound span (webhook path).
    [coder_in] = [
        s
        for s in a2a
        if s.name == "a2agw.inbound" and s.attributes.get("a2agw.agent_id") == "coder"
    ]
    [coder_call] = [
        s
        for s in a2a
        if s.name == "a2agw.partner_call"
        and s.parent is not None
        and s.parent.span_id == coder_in.context.span_id
    ]
    assert coder_call.attributes["a2agw.partner_id"] == "security"

    # One audit chain, intact, with the coder's linked call in it.
    assert result.chain_ok
    actions = {r["action"] for r in result.audit_rows}
    assert {"partner.call", "inbound.admit"} <= actions
    assert any(
        r["action"] == "partner.call"
        and r.get("agent_id") == "coder"
        and (r.get("detail") or {}).get("grant")
        for r in result.audit_rows
    ), [r for r in result.audit_rows if r["action"] == "partner.call"]

    # No secret, consult token or API key value in any log or audit row.
    assert tokens
    out = capsys.readouterr()
    span_text = [
        json.dumps(
            {
                "attributes": dict(s.attributes or {}),
                "events": [(e.name, dict(e.attributes or {})) for e in s.events],
            },
            default=str,
        )
        for s in a2a
    ]
    captured = "\n".join(
        [
            caplog.text,
            out.out,
            out.err,
            *result.coder_output,
            *span_text,
            json.dumps(result.audit_rows, default=str),
        ]
    )
    for value in [*tokens, *result.secrets]:
        assert value and value not in captured


# -- the Node agent on its own ------------------------------------------------------------

SECRET = "node-test-secret"


@pytest.fixture
async def coder():
    node = run_demo.NodeCoder(SECRET)
    url = await node.start()
    try:
        yield node, url
    finally:
        await node.stop()


def _invoke(**over) -> bytes:
    body = {
        "protocol": "a2agw.invoke/1",
        "agent_id": "coder",
        "task_id": "t1",
        "context_id": "c1",
        "resumed": False,
        "text": "write fizzbuzz",
        "parts": [{"text": "write fizzbuzz"}],
        "metadata": {},
        "caller": None,
        "consult": None,
        "deadline": None,
        **over,
    }
    return json.dumps(body).encode()


def _headers(body: bytes, *, ts: int | None = None, secret: str = SECRET) -> dict[str, str]:
    stamp = str(int(time.time()) if ts is None else ts)
    return {
        "content-type": "application/json",
        "x-a2agw-timestamp": stamp,
        "x-a2agw-signature": sign(secret, stamp, body),
    }


async def test_node_coder_verifies_signature_and_timestamp(coder):
    _, url = coder
    body = _invoke()
    async with httpx.AsyncClient(timeout=30) as hc:
        unsigned = await hc.post(url, content=body, headers={"content-type": "application/json"})
        wrong = await hc.post(url, content=body, headers=_headers(body, secret="other"))
        tampered = await hc.post(url, content=body + b" ", headers=_headers(body))
        stale = await hc.post(url, content=body, headers=_headers(body, ts=int(time.time()) - 301))
        future = await hc.post(url, content=body, headers=_headers(body, ts=int(time.time()) + 301))
        ok = await hc.post(url, content=body, headers=_headers(body))
    for r in (unsigned, wrong, tampered, stale, future):
        assert r.status_code == 401, r.text
    assert ok.status_code == 200
    assert ok.headers["content-type"].startswith("application/x-ndjson")
    events = [json.loads(line) for line in ok.text.splitlines() if line]
    assert [e["type"] for e in events] == ["status", "text", "text", "done"]
    assert "node coder: write fizzbuzz" in events[1]["text"]


async def test_node_coder_treats_disconnect_as_cancel(coder):
    node, url = coder
    reached = asyncio.Event()
    aborted = asyncio.Event()

    async def hang(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        reached.set()  # the coder is consulting: never answer
        await reader.read()  # EOF: the coder aborted its consult request
        aborted.set()
        writer.close()

    gateway = await asyncio.start_server(hang, "127.0.0.1", 0)
    port = gateway.sockets[0].getsockname()[1]
    grant = {"url": f"http://127.0.0.1:{port}/a2agw/v1", "token": "t" * 43, "expires_at": None}
    body = _invoke(consult=grant)
    try:
        async with (
            httpx.AsyncClient(timeout=30) as hc,
            hc.stream("POST", url, content=body, headers=_headers(body)) as r,
        ):
            assert r.status_code == 200
            await asyncio.wait_for(reached.wait(), 30)
        # Leaving the stream closes the connection: the coder's cancel signal.
        await asyncio.wait_for(aborted.wait(), 30)
    finally:
        gateway.close()
        await gateway.wait_closed()
    async with asyncio.timeout(30):
        while not any("cancelled (client disconnected)" in line for line in node.output):
            await asyncio.sleep(0.05)
    assert not any("t" * 43 in line for line in node.output)


async def _raw(port: int, head: bytes, body_chunks: list[bytes]) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(head)
        for chunk in body_chunks:
            writer.write(chunk)
        await writer.drain()
        async with asyncio.timeout(30):
            return await reader.read()  # until the coder closes the connection
    finally:
        writer.close()


async def test_node_coder_answers_413_for_an_oversized_body(coder):
    _, url = coder
    port = httpx.URL(url).port
    declared = await _raw(
        port,
        b"POST /a2agw/invoke HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2097152\r\n\r\n",
        [],  # refused on the header alone: the client waits for the answer before the body
    )
    piece = b"x" * 65536
    chunked = await _raw(
        port,
        b"POST /a2agw/invoke HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n",
        [b"%x\r\n%s\r\n" % (len(piece), piece)] * 18 + [b"0\r\n\r\n"],  # 1.125 MiB, no length
    )
    # A client that sends the declared body anyway still reads the answer (the coder drains
    # the body instead of closing on unread data, which would reset the connection).
    eager = await _raw(
        port,
        b"POST /a2agw/invoke HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2097152\r\n\r\n",
        [piece] * 32,  # the whole 2 MiB, written without waiting for the answer
    )
    for answer in (declared, chunked, eager):
        status, _, rest = answer.partition(b"\r\n")
        assert status == b"HTTP/1.1 413 Payload Too Large", answer[:200]
        assert b"connection: close" in rest.lower()
        assert b'{"error":"payload too large"}' in rest
