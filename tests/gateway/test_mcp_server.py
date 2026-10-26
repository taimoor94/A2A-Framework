"""The outbound MCP server (``/a2agw/mcp/{agent_id}``): the partner tools over MCP, with the
same auth and the same rules as the REST API."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest
from a2a.types import TaskState
from cascade_support import Fn, spec
from google.protobuf.json_format import MessageToDict
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp_types import ToolListChangedNotification
from streaming_asgi import streaming_transport

from a2agw.consult.credentials import StaticCredentials
from a2agw.consult.tools import UNTRUSTED_NOTE
from a2agw.core.events import Done
from a2agw.gateway.auth import MCP_EXTRA_HINT
from a2agw.gateway.mcp_server import _describe, _strip_x
from a2agw.security.auth import ApiKeyEntry, AuthConfig, hash_api_key
from a2agw.security.policy import Policy, PolicyEngine

MCP = "http://t/a2agw/mcp"
HANDLE_WAIT_S = 1.0
WORKING = TaskState.Name(TaskState.TASK_STATE_WORKING)
Transport2 = streaming_transport(httpx2)
COMPANIONS = {"a2a_check_task", "a2a_cancel_task", "a2a_wait"}
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"},
    },
}
ACCEPT = {"Accept": "application/json, text/event-stream"}


@pytest.fixture(autouse=True)
def no_errors_logged(caplog):
    """MCP traffic, including clients closing their sessions, logs no error or traceback."""
    caplog.set_level(logging.WARNING)
    yield
    bad = [
        r
        for when in ("setup", "call")
        for r in caplog.get_records(when)
        if r.levelno >= logging.ERROR or r.exc_info
    ]
    assert bad == [], [r.getMessage() for r in bad]


def bearer(grant) -> dict[str, str]:
    return {"Authorization": f"Bearer {grant.token}"}


def policy(**doc) -> PolicyEngine:
    return PolicyEngine(Policy.model_validate({"version": 1, **doc}))


class Blocker:
    durable_sessions = False

    async def run(self, ctx):
        await asyncio.Event().wait()
        yield Done(text="never")


async def echo(ctx):
    yield Done(text=f"echo: {ctx.text}")


@asynccontextmanager
async def session(e, agent: str, headers: dict[str, str], **kw: Any):
    """An initialized MCP client session with ``agent``'s server on ``e``'s host."""
    hc = httpx2.AsyncClient(transport=Transport2({"t": e.host.app()}), headers=headers)
    async with (
        hc,
        streamable_http_client(f"{MCP}/{agent}", http_client=hc) as (read, write),
        ClientSession(read, write, **kw) as s,
    ):
        await s.initialize()
        yield s


def structured(result) -> dict[str, Any]:
    """The envelope of a tool result; its text content is the same JSON."""
    [content] = result.content
    assert json.loads(content.text) == result.structured_content
    return result.structured_content


def x_keys(schema: Any) -> list[str]:
    if isinstance(schema, dict):
        return [k for k in schema if k.startswith("x-")] + [
            x for v in schema.values() for x in x_keys(v)
        ]
    if isinstance(schema, list):
        return [x for v in schema for x in x_keys(v)]
    return []


async def b_states(e) -> list[str]:
    rows, _ = await e.host.index.list(agent_id="b")
    return [r["state"] for r in rows]


async def linked(env, *specs, **kw):
    e = await env(spec("a", Fn(echo)), *specs, mcp_agents=["a"], **kw)
    return e, bearer(e.host.consult_tokens.issue("a", "T1", None, None))


async def test_lists_partner_and_companion_tools(env):
    e, h = await linked(env, spec("b", Fn(echo)))
    await e.register("b")
    async with session(e, "a", h) as s:
        tools = (await s.list_tools()).tools
    assert {t.name for t in tools} == {"ask_b", *COMPANIONS}
    [ask] = [t for t in tools if t.name == "ask_b"]
    assert ask.input_schema["required"] == ["message"]
    assert "data" in ask.input_schema["properties"]
    for t in tools:
        assert x_keys(t.input_schema) == [], t.name
    # The host's own tools keep their limits (they are checked on every call).
    [b_tool] = [t for t in e.host.partner_tools("a") if t.name == "ask_b"]
    assert x_keys(b_tool.parameters) == ["x-max-json-bytes"]


async def test_call_returns_envelope_structured(env):
    e, h = await linked(env, spec("b", Fn(echo)))
    await e.register("b")
    async with session(e, "a", h) as s:
        await s.list_tools()
        ok = await s.call_tool("ask_b", {"message": "hi"})
        bad = await s.call_tool("ask_b", {"text": "hi"})
        huge = await s.call_tool("ask_b", {"message": "hi", "data": {"x": "y" * 40000}})
    body = structured(ok)
    assert ok.is_error is False
    assert (body["partner"], body["state"], body["text"]) == ("b", "completed", "echo: hi")
    assert bad.is_error is True and structured(bad)["state"] == "rejected"
    # The x- limit removed from the advertised schema is still enforced.
    assert huge.is_error is True
    assert structured(huge) == {"state": "rejected", "reason": "invalid arguments: data"}


async def test_untrusted_note_in_descriptions(env):
    e, h = await linked(env, spec("b", Fn(echo)))
    await e.register("b")
    async with session(e, "a", h) as s:
        tools = (await s.list_tools()).tools
    for t in tools:
        assert t.description.endswith(UNTRUSTED_NOTE), t.name
        assert t.description.count(UNTRUSTED_NOTE) == 1, t.name


def test_untrusted_note_appended_when_missing():
    assert _describe("Ask b.") == "Ask b.\n\n" + UNTRUSTED_NOTE
    assert _describe("Ask b. " + UNTRUSTED_NOTE) == "Ask b. " + UNTRUSTED_NOTE


def test_strip_x_strips_keywords_only():
    schema = {
        "type": "object",
        "x-top": 1,
        "properties": {
            "x-trace": {"type": "string", "x-max-len": 5},  # a property named x-...
            "data": {"type": "object", "x-max-json-bytes": 10, "default": {"x-keep": 1}},
            "list": {"type": "array", "items": {"type": "string", "x-limit": 1}},
            "choice": {"anyOf": [{"type": "string", "x-a": 1}], "enum": [{"x-v": 1}]},
        },
        "required": ["x-trace"],
    }
    assert _strip_x(schema) == {
        "type": "object",
        "properties": {
            "x-trace": {"type": "string"},
            "data": {"type": "object", "default": {"x-keep": 1}},
            "list": {"type": "array", "items": {"type": "string"}},
            "choice": {"anyOf": [{"type": "string"}], "enum": [{"x-v": 1}]},
        },
        "required": ["x-trace"],
    }


def quarantine(host, pid: str) -> None:
    """Quarantine a registered (unsigned) partner: require signed cards on its tier."""
    host.partners.require_signed = frozenset({"internal"})
    host.partners.enforce_signed([pid])
    assert host.partners.get(pid).status == "quarantined"


async def test_quarantined_partner_disappears_and_stale_call_unavailable(env):
    e, h = await linked(env, spec("b", Fn(echo)))
    await e.register("b")
    async with session(e, "a", h) as s:
        assert "ask_b" in {t.name for t in (await s.list_tools()).tools}
        quarantine(e.host, "b")
        assert {t.name for t in (await s.list_tools()).tools} == COMPANIONS
        stale = await s.call_tool("ask_b", {"message": "hi"})
    assert stale.is_error is True
    assert structured(stale) == {"state": "unavailable", "reason": "unknown tool"}
    assert await b_states(e) == []  # nothing reached the partner


async def test_partner_change_notifies_open_sessions(env):
    e, h = await linked(env, spec("b", Fn(echo)), spec("c", Fn(echo)))
    await e.register("b")
    changed = asyncio.Event()

    async def on_message(message) -> None:
        if isinstance(message, ToolListChangedNotification):
            changed.set()

    async with session(e, "a", h, message_handler=on_message) as s:
        init = s.initialize_result
        assert init is not None and init.capabilities.tools.list_changed is True
        await s.list_tools()
        # The standalone stream opens in the background: change partners until it delivers.
        for i in range(50):
            pid = f"c{i}"
            await e.host.partners.add_from_card(pid, MessageToDict(e.host.cards["c"]), "internal")
            try:
                await asyncio.wait_for(changed.wait(), 0.1)
                break
            except TimeoutError:
                continue
        assert changed.is_set()
        assert "ask_c0" in {t.name for t in (await s.list_tools()).tools}


async def test_forbidden_partner_hidden(env):
    rules = policy(routing=[{"agent": "a", "partners": ["b"], "mode": "forbid"}])
    e, h = await linked(env, spec("b", Fn(echo)), spec("c", Fn(echo)), policy=rules)
    await e.register("b", "c")
    async with session(e, "a", h) as s:
        assert {t.name for t in (await s.list_tools()).tools} == {"ask_c", *COMPANIONS}
        hidden = await s.call_tool("ask_b", {"message": "hi"})
        check = await s.call_tool("a2a_check_task", {"partner_id": "b", "task_id": "x"})
    assert structured(hidden) == {"state": "unavailable", "reason": "unknown tool"}
    assert structured(check) == {
        "partner": "b",
        "state": "unavailable",
        "reason": "unknown partner",
    }
    assert await b_states(e) == []


async def test_task_ops_bound_to_the_owner(env):
    e, owner = await linked(env, spec("b", Blocker()))
    await e.register("b")
    other = bearer(e.host.consult_tokens.issue("a", "T2", None, None))
    async with session(e, "a", owner) as s:
        r = await s.call_tool("ask_b", {"message": "go", "wait_seconds": HANDLE_WAIT_S})
        tid = structured(r)["task_id"]
    handle = {"partner_id": "b", "task_id": tid}
    unknown_task = {"partner": "b", "state": "unavailable", "reason": "unknown task"}
    async with session(e, "a", other) as s:
        for name, args in (
            ("a2a_check_task", handle),
            ("a2a_cancel_task", handle),
            ("a2a_wait", {"tasks": [handle], "seconds": 0}),
            ("ask_b", {"message": "more", "task_id": tid}),
        ):
            assert structured(await s.call_tool(name, args)) == unknown_task, name
    assert await b_states(e) == [WORKING]
    async with session(e, "a", owner) as s:
        r = await s.call_tool("a2a_cancel_task", handle)
    assert structured(r)["state"] == "canceled"


async def test_consult_token_session_links_inbound_task(env):
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        grant = await e.host.consult_issuer(ctx)
        async with session(e, "a", bearer(grant)) as s:
            await s.list_tools()
            seen["result"] = structured(await s.call_tool("ask_b", {"message": "hi"}))
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)), mcp_agents=["a"])
    await e.register("b")
    [ev] = await e.send("a", "go")
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert seen["result"]["text"] == "echo: hi"
    [handle] = await e.host.handles.by_inbound(ev.task.id)
    assert (handle["partner_id"], handle["task_id"]) == ("b", seen["result"]["task_id"])
    assert handle["owner"] is None


SVC, SVC2, PLAIN, PEER = "svc-key", "svc2-key", "plain-key", "peer-key"


def auth_config() -> AuthConfig:
    return AuthConfig(
        api_keys={
            hash_api_key(SVC): ApiKeyEntry(principal_id="svc", scopes=["a2agw:sidecar"]),
            hash_api_key(SVC2): ApiKeyEntry(principal_id="svc2", scopes=["a2agw:sidecar"]),
            hash_api_key(PLAIN): ApiKeyEntry(principal_id="plain", scopes=["other"]),
            hash_api_key(PEER): ApiKeyEntry(principal_id="peer"),  # the host calling itself
        }
    )


async def standalone(env, b_adapter, **kw):
    e = await env(
        spec("a", Fn(echo)),
        spec("b", b_adapter),
        auth=auth_config(),
        sidecar_clients={"key:svc": ["a"], "key:svc2": ["a", "b"], "key:plain": ["a"]},
        credentials=StaticCredentials({"gw": {"X-API-Key": PEER}}),
        mcp_agents=["a", "x"],
        **kw,
    )
    card = MessageToDict(e.host.cards["b"])
    await e.host.partners.add_from_card("b", card, "internal", credential_ref="gw")
    return e


async def test_http_requires_auth(env):
    e = await standalone(env, Fn(echo))
    grant_b = e.host.consult_tokens.issue("b", "T9", None, None)

    async def status(headers: dict[str, str], agent: str = "a") -> int:
        r = await e.hc.post(f"{MCP}/{agent}", json=INIT, headers={**ACCEPT, **headers})
        return r.status_code

    assert await status({}) == 401
    assert await status({"X-API-Key": "wrong"}) == 401
    assert await status({"X-API-Key": PLAIN}) == 401  # mapped, but no a2agw:sidecar scope
    assert await status({"X-API-Key": SVC}, "x") == 403  # not mapped to this principal
    assert await status(bearer(grant_b)) == 403  # a token for another agent
    assert await status({"X-API-Key": SVC}) == 200  # the path names the agent
    await e.host.audit.drain()
    await e.host.audit.flush_coalesced()
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "sidecar.denied"}, 50, None, ascending=True)
    assert {r["outcome"] for r in rows} == {"unauthenticated", "forbidden"}
    assert all(SVC not in json.dumps(r) and grant_b.token not in json.dumps(r) for r in rows)


async def test_session_is_bound_to_its_caller(env):
    e = await standalone(env, Fn(echo))
    r = await e.hc.post(f"{MCP}/a", json=INIT, headers={**ACCEPT, "X-API-Key": SVC})
    sid = r.headers["mcp-session-id"]
    listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    headers = {**ACCEPT, "Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
    other = await e.hc.post(f"{MCP}/a", json=listing, headers={**headers, "X-API-Key": SVC2})
    assert other.status_code == 404  # as if the session did not exist
    mine = await e.hc.post(f"{MCP}/a", json=listing, headers={**headers, "X-API-Key": SVC})
    assert mine.status_code == 200 and "ask_b" in mine.text


async def test_standalone_calls_owned_and_capped(env):
    e = await standalone(env, Blocker(), max_open_sidecar_tasks_per_caller=1)
    ask = {"message": "go", "wait_seconds": HANDLE_WAIT_S}
    async with session(e, "a", {"X-API-Key": SVC}) as s:
        first = structured(await s.call_tool("ask_b", ask))
        second = structured(await s.call_tool("ask_b", ask))
    assert first["state"] == "working"
    assert second == {"partner": "b", "state": "unavailable", "reason": "too many open tasks"}
    handle = await e.host.handles.get("b", first["task_id"])
    assert (handle["inbound_task_id"], handle["owner"], handle["caller_id"]) == (
        None,
        "sidecar:a",
        "key:svc",
    )


async def test_unknown_agent_404_only_after_auth(env):
    """Callers are authenticated first, so the answers do not reveal which agent ids are
    served: only a caller mapped to an agent id learns it is not served over MCP."""
    e = await standalone(env, Fn(echo))
    token_a = bearer(e.host.consult_tokens.issue("a", "T1", None, None))

    async def status(agent: str, headers: dict[str, str]) -> int:
        r = await e.hc.post(f"{MCP}/{agent}", json=INIT, headers={**ACCEPT, **headers})
        return r.status_code

    for agent in ("zzz", "b", "a/extra", "a"):
        assert await status(agent, {}) == 401, agent
        assert await status(agent, {"X-API-Key": "wrong"}) == 401, agent
    for agent in ("zzz", "b", "a/extra"):
        assert await status(agent, {"X-API-Key": SVC}) == 403, agent  # not mapped
        assert await status(agent, token_a) == 403, agent  # the token is for a
    assert await status("b", {"X-API-Key": SVC2}) == 404  # mapped, not served over MCP
    assert await status("a", {"X-API-Key": SVC2}) == 200


async def test_revoked_token_ends_its_sessions(env):
    """A consult-token session does not outlive its turn: revoking the token (the inbound
    task ended) ends the session, and its open notification stream completes."""
    e, h = await linked(env)
    r = await e.hc.post(f"{MCP}/a", json=INIT, headers={**ACCEPT, **h})
    sid = r.headers["mcp-session-id"]
    session_headers = {**h, "Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    await e.hc.post(f"{MCP}/a", json=note, headers={**ACCEPT, **session_headers})
    opened = asyncio.Event()

    async def standalone_stream() -> int:
        headers = {**session_headers, "Accept": "text/event-stream"}
        async with e.hc.stream("GET", f"{MCP}/a", headers=headers) as resp:
            opened.set()
            async for _ in resp.aiter_bytes():
                pass
            return resp.status_code

    stream = asyncio.create_task(standalone_stream())
    await asyncio.wait_for(opened.wait(), 5)
    e.host.consult_tokens.revoke_task("T1")
    assert await asyncio.wait_for(stream, 5) == 200  # ended, completely
    assert e.host._mcp._sessions == {}
    # A new token for the same agent cannot use the ended session.
    other = bearer(e.host.consult_tokens.issue("a", "T1", None, None))
    listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    r = await e.hc.post(f"{MCP}/a", json=listing, headers={**ACCEPT, **session_headers, **other})
    assert r.status_code == 404


async def test_mcp_prefix_uses_gateway_auth_when_mcp_is_off(env):
    e = await env(spec("a", Fn(echo)), auth=auth_config())
    r = await e.hc.post(f"{MCP}/a", json=INIT, headers={**ACCEPT, "X-API-Key": "wrong"})
    assert r.status_code == 401
    assert r.headers.get("cache-control") != "no-store"  # the gateway's refusal, not MCP's
    r = await e.hc.post(f"{MCP}/a", json=INIT, headers={**ACCEPT, "X-API-Key": SVC})
    assert r.status_code == 404  # nothing is served there


def test_missing_extra_is_named(tmp_path):
    """Without the mcp extra, enabling MCP fails with a hint naming it, not a raw
    ModuleNotFoundError: in build_host (config), AgentHost.app() and the module import."""
    cfg = tmp_path / "a2agw.yaml"
    cfg.write_text(
        "base_url: http://127.0.0.1:8000\n"
        f"db_url: sqlite+aiosqlite:///{tmp_path / 'db.sqlite'}\n"
        "sidecar: {mcp: {enabled: true, agents: [a]}}\n"
    )
    code = (
        "import sys\n"
        "sys.modules['mcp'] = None\n"
        "sys.modules['mcp_types'] = None\n"
        "from a2agw.config import ConfigError, build_host, load_config\n"
        "from a2agw.serve.host import AgentHost\n"
        "try:\n"
        f"    build_host(load_config({str(cfg)!r}))\n"
        "except ConfigError as e:\n"
        "    print('config:', e)\n"
        "try:\n"
        "    AgentHost('http://t', mcp_agents=['a']).app()\n"
        "except ImportError as e:\n"
        "    print('host:', type(e).__name__, e)\n"
        "try:\n"
        "    import a2agw.gateway.mcp_server\n"
        "except ImportError as e:\n"
        "    print('import:', type(e).__name__, e)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=True
    )
    assert out.stdout.splitlines() == [
        f"config: sidecar.mcp.enabled: {MCP_EXTRA_HINT}",
        f"host: ImportError {MCP_EXTRA_HINT}",
        f"import: ImportError {MCP_EXTRA_HINT}",
    ]


async def test_rebinding_protection_allows_only_the_base_url_host(env):
    e, h = await linked(env)
    r = await e.hc.post(f"{MCP}/a", json=INIT, headers={**ACCEPT, **h, "Host": "evil.example"})
    assert r.status_code == 421  # never served


@pytest.mark.parametrize("enabled", [False, True])
def test_core_does_not_import_mcp(tmp_path, enabled):
    cfg = tmp_path / "a2agw.yaml"
    cfg.write_text(
        "base_url: http://127.0.0.1:8000\n"
        f"db_url: sqlite+aiosqlite:///{tmp_path / 'db.sqlite'}\n"
        f"sidecar: {{mcp: {{enabled: {str(enabled).lower()}, agents: [a]}}}}\n"
    )
    code = (
        "import sys, a2agw, a2agw.serve.host, a2agw.config\n"
        "from a2agw.config import build_host, load_config\n"
        f"host = build_host(load_config({str(cfg)!r}))\n"
        "host.app()\n"
        "assert sorted(host.sidecar_agent_ids()) == ['a'], host.sidecar_agent_ids()\n"
        "print('mcp' in sys.modules, 'mcp_types' in sys.modules)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=True
    )
    assert out.stdout.split() == [str(enabled), str(enabled)]
