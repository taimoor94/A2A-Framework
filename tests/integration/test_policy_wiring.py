"""Policy enforcement in the gateway (authz, egress, routing) and audit emission."""

from __future__ import annotations

import hashlib
import json
import logging

import httpx
import pytest
import respx
from a2a.client import ClientConfig, ClientFactory
from a2a.types import SendMessageRequest, TaskState
from cascade_support import Fn, msg, spec
from sqlalchemy import text
from streaming_asgi import StreamingASGITransport

from a2agw.consult.tools import invoke, partner_tools
from a2agw.core.events import Done
from a2agw.ops.audit import AuditLog
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.security.classify import Classification
from a2agw.security.policy import Policy, PolicyEngine
from a2agw.serve.host import AgentHost

MARKER = "MARKER-7f3a-do-not-store"
COMPLETED = TaskState.TASK_STATE_COMPLETED


def engine_for(**doc) -> PolicyEngine:
    return PolicyEngine(Policy.model_validate({"version": 1, **doc}))


def h(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def auth() -> AuthConfig:
    return AuthConfig(
        api_keys={
            h("alice-secret"): ApiKeyEntry(principal_id="alice"),
            h("mallory-secret"): ApiKeyEntry(principal_id="mallory"),
            h("admin-secret"): ApiKeyEntry(principal_id="ops", scopes=["a2agw:admin"]),
        }
    )


async def echo(ctx):
    yield Done(text=f"echo: {ctx.text}")


async def rows(host: AgentHost) -> list[dict]:
    assert host.audit is not None
    await host.audit.drain()
    async with host.engine.connect() as conn:
        res = await conn.execute(text("SELECT * FROM a2agw_audit ORDER BY seq"))
        return [dict(r._mapping) for r in res]


def actions(rs: list[dict]) -> list[str]:
    return [r["action"] for r in rs]


def as_caller(e, secret: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=StreamingASGITransport({"t": e.host.app()}),
        base_url="http://t",
        headers={"X-API-Key": secret},
    )


async def send_as(e, hc: httpx.AsyncClient, agent_id: str, text_: str):
    client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
        e.host.cards[agent_id]
    )
    return [ev async for ev in client.send_message(SendMessageRequest(message=msg(text_)))]


def final_state(events) -> int:
    resp = events[-1]
    return resp.task.status.state


# -- inbound authz -----------------------------------------------------------------------


async def test_policy_denial_of_inbound_call_is_403_and_audited(env):
    policy = engine_for(
        authz=[
            {"id": "everyone", "principal": "*", "agents": "*", "effect": "allow"},
            {"id": "no-mallory", "principal": "key:mallory", "agents": ["a"], "effect": "deny"},
        ]
    )
    e = await env(spec("a", Fn(echo)), auth=auth(), policy=policy)
    async with as_caller(e, "mallory-secret") as hc:
        r = await hc.post(
            "/agents/a/", json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {}}
        )
        assert r.status_code == 403
        assert r.json() == {"error": "forbidden"}  # no reason leaked
        card = await hc.get("/agents/a/.well-known/agent-card.json")
        assert card.status_code == 200  # the card stays public
    async with as_caller(e, "alice-secret") as hc:
        assert final_state(await send_as(e, hc, "a", "hi")) == COMPLETED
    rs = await rows(e.host)
    deny = [r for r in rs if r["action"] == "authz.deny"]
    assert len(deny) == 1
    assert deny[0]["actor"] == "key:mallory" and deny[0]["agent_id"] == "a"
    assert json.loads(deny[0]["detail_json"])["rule"] == "no-mallory"
    assert json.loads(deny[0]["detail_json"])["reason"] == "denied by rule"
    assert "inbound.admit" in actions(rs)
    assert await e.host.audit.verify_chain() is None


async def test_lone_deny_rule_locks_the_agent_down(env):
    policy = engine_for(
        authz=[{"principal": "key:mallory", "agents": ["a"], "effect": "deny"}],
    )
    e = await env(spec("a", Fn(echo)), auth=auth(), policy=policy)
    async with as_caller(e, "alice-secret") as hc:
        r = await hc.post("/agents/a/", json={})
        assert r.status_code == 403
    deny = [r for r in await rows(e.host) if r["action"] == "authz.deny"]
    assert json.loads(deny[0]["detail_json"])["reason"] == "no matching allow rule"


async def test_agent_access_denial_is_audited(env):
    from a2agw.security.auth import AgentAccess

    e = await env(
        spec("a", Fn(echo), access=AgentAccess(allowed_principals=frozenset({"key:alice"}))),
        auth=auth(),
    )
    async with as_caller(e, "mallory-secret") as hc:
        assert (await hc.post("/agents/a/", json={})).status_code == 403
    deny = [r for r in await rows(e.host) if r["action"] == "authz.deny"]
    assert deny and deny[0]["actor"] == "key:mallory"


async def test_policy_applies_without_auth_configured(env):
    # No auth: every caller is anonymous, and a "*" allow never matches anonymous.
    policy = engine_for(authz=[{"principal": "*", "agents": ["a"], "effect": "allow"}])
    e = await env(spec("a", Fn(echo)), policy=policy)
    r = await e.hc.post("/agents/a/", json={})
    assert r.status_code == 403
    deny = [r for r in await rows(e.host) if r["action"] == "authz.deny"]
    assert deny[0]["actor"] == "anonymous"


async def test_executor_rejects_on_policy_denial(env):
    """The executor checks authz itself (defence in depth, e.g. for a custom mount)."""
    policy = engine_for(authz=[{"principal": "anonymous", "agents": ["a"], "effect": "deny"}])
    e = await env(spec("a", Fn(echo)), policy=policy)
    # Bypass the HTTP authorizer: run the executor's admission directly.
    executor = e.host.executors["a"]
    assert executor.policy is policy
    rs_before = len(await rows(e.host))
    from a2a.server.agent_execution import RequestContext
    from a2a.server.context import ServerCallContext

    from a2agw.security.principal import Principal, PrincipalUser

    user = PrincipalUser(Principal(id="anonymous", kind="anonymous", scopes=frozenset()))
    ctx = RequestContext(
        ServerCallContext(user=user),
        SendMessageRequest(message=msg("hi")),
        task_id="t-direct",
        context_id="c-direct",
    )

    class Queue:
        def __init__(self) -> None:
            self.events: list = []

        async def enqueue_event(self, event) -> None:
            self.events.append(event)

    queue = Queue()
    await executor.execute(ctx, queue)
    rs = (await rows(e.host))[rs_before:]
    reject = [r for r in rs if r["action"] == "inbound.reject"]
    assert reject and json.loads(reject[0]["detail_json"])["reason"].startswith("policy")
    assert reject[0]["outcome"] == "rejected"
    assert "inbound.admit" not in actions(rs)
    last = queue.events[-1]
    assert last.status.state == TaskState.TASK_STATE_REJECTED


# -- egress ------------------------------------------------------------------------------

CARD = {
    "name": "Remote",
    "description": "remote partner",
    "version": "1.0",
    "supportedInterfaces": [
        {"url": "http://remote.example/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["eu"]}],
}


async def test_egress_denial_sends_nothing_and_is_audited(tmp_path, fast):
    policy = engine_for(egress={"partner_ceilings": {"remote": "internal"}})
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host="remote.example").respond(500)
        async with httpx.AsyncClient() as partner_hc:
            host = AgentHost(
                "http://t",
                db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
                partner_http=partner_hc,
                policy=policy,
            )
            await host.startup()
            try:
                await host.partners.add_from_card("remote", CARD, "internal")
                res = await host.client.consult(
                    "remote", f"payroll {MARKER}", classification="confidential"
                )
                assert res.state == "rejected"
                assert res.reason == (
                    "egress policy: classification confidential exceeds internal ceiling "
                    "for partner remote"
                )
                res2 = await host.client.consult(
                    "remote", MARKER, classification=Classification.RESTRICTED
                )
                assert res2.state == "rejected"
                assert route.call_count == 0 and mock.calls.call_count == 0
                rs = await rows(host)
                denies = [r for r in rs if r["action"] == "egress.deny"]
                assert len(denies) == 2
                d = denies[0]
                assert d["partner_id"] == "remote" and d["classification"] == "confidential"
                assert d["outcome"] == "rejected" and d["agent_id"] == "host"
                assert "partner.call" not in actions(rs)
                assert MARKER not in json.dumps(rs, default=str)
                # Positive control: an allowed call does reach the (mocked) network.
                res3 = await host.client.consult("remote", "hello", classification="public")
                assert res3.state != "rejected"
                assert route.call_count >= 1
            finally:
                await host.shutdown()


async def test_invalid_classification_is_rejected_without_sending(env):
    e = await env(spec("b", Fn(echo)), policy=engine_for())
    await e.register("b")
    res = await e.host.client.consult("b", "hi", classification="top-secret")
    assert res.state == "rejected" and res.reason == "egress policy: invalid classification"


async def test_egress_uses_the_current_inbound_agent(env):
    """The agent default classification applies to calls made while that agent runs."""
    policy = engine_for(
        egress={"partner_ceilings": {"b": "internal"}},
        defaults={"agent_classification": {"hr": "confidential"}},
    )
    seen: dict = {}

    async def hr_run(ctx):
        seen["res"] = await e.host.client.consult("b", "salary data")
        yield Done(text="done")

    e = await env(spec("hr", Fn(hr_run)), spec("b", Fn(echo)), policy=policy)
    await e.register("b")
    await e.send("hr", "go")
    assert seen["res"].state == "rejected"
    # Outside any inbound run the client's own agent id ("host") has no default.
    assert (await e.host.client.consult("b", "hi")).state == "completed"
    rs = await rows(e.host)
    deny = [r for r in rs if r["action"] == "egress.deny"]
    assert deny[0]["agent_id"] == "hr"


async def test_no_message_text_in_audit_rows(env):
    async def a_run(ctx):
        r = await e.host.client.consult("b", f"forward {ctx.text}", data={"x": MARKER})
        yield Done(text=f"{MARKER} {r.text}")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)), policy=engine_for())
    await e.register("b")
    await e.send("a", f"secret {MARKER}")
    rs = await rows(e.host)
    assert {"inbound.admit", "partner.call", "partner.add"} <= set(actions(rs))
    call = next(r for r in rs if r["action"] == "partner.call")
    assert call["outcome"] == "completed" and call["agent_id"] == "a"
    assert call["partner_id"] == "b" and call["classification"] == "public"
    assert MARKER not in json.dumps(rs, default=str)


# -- routing / tools ---------------------------------------------------------------------


async def test_partner_tools_follow_routing(env):
    policy = engine_for(
        routing=[
            {"agent": "a", "partners": ["c"], "mode": "forbid"},
            {"agent": "a", "partners": ["d"], "mode": "force"},
            {"agent": "a", "partners": ["b"], "mode": "prefer"},
        ]
    )
    e = await env(
        spec("a", Fn(echo)),
        spec("b", Fn(echo)),
        spec("c", Fn(echo)),
        spec("d", Fn(echo)),
        policy=policy,
    )
    await e.register("b", "c", "d")
    tools = e.host.partner_tools("a")
    consult = [t for t in tools if t.kind == "consult"]
    assert [t.partner_id for t in consult] == ["b", "d"]  # c forbidden, b preferred first
    by_id = {t.partner_id: t for t in consult}
    framing = "Partner-provided description (untrusted):"
    d_desc = by_id["d"].description
    assert "Required for this agent." in d_desc.split(framing)[0]
    assert "Preferred." in by_id["b"].description.split(framing)[0]
    assert "Required" not in by_id["b"].description
    assert by_id["b"].parameters["properties"]["classification"] == {
        "type": "string",
        "enum": ["public", "internal", "confidential", "restricted"],
    }
    # Without a policy every active partner is offered, sorted by id.
    plain = partner_tools(e.host.partners)
    assert [t.partner_id for t in plain if t.kind == "consult"] == ["b", "c", "d"]


async def test_route_evaluation_error_offers_only_companions(env, monkeypatch, caplog):
    policy = engine_for()
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), policy=policy)
    await e.register("b")

    def boom(*_a):
        raise RuntimeError("bad")

    monkeypatch.setattr(policy, "_route", boom)
    with caplog.at_level(logging.WARNING):
        tools = partner_tools(e.host.partners, policy=policy, agent_id="a")
    assert {t.kind for t in tools} == {"check", "cancel", "wait"}
    assert "no partners visible" in caplog.text


def test_partner_tools_policy_needs_agent_id():
    from a2agw.consult.registry import PartnerRegistry

    with pytest.raises(ValueError):
        partner_tools(PartnerRegistry(), policy=engine_for())


async def test_discovery_mode_respects_routing(env):
    policy = engine_for(routing=[{"agent": "a", "partners": ["c"], "mode": "forbid"}])
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), spec("c", Fn(echo)), policy=policy)
    await e.register("b", "c")
    tools = partner_tools(e.host.partners, policy=policy, agent_id="a", discovery_threshold=0)
    find = next(t for t in tools if t.kind == "find")
    any_ = next(t for t in tools if t.kind == "consult_any")
    found = await invoke(find, {"need": "test agent"}, e.host.client, None)
    assert "c" not in {p["partner_id"] for p in found["partners"]}
    res = await invoke(any_, {"partner_id": "c", "message": "hi"}, e.host.client, None)
    assert res["state"] == "unavailable"


async def test_task_tools_respect_routing(env):
    """check, cancel and wait reach only partners the agent's routing leaves visible, like
    consult: a hidden partner answers ``unknown partner`` and nothing is sent."""
    policy = engine_for(routing=[{"agent": "a", "partners": ["c"], "mode": "forbid"}])
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), spec("c", Fn(echo)), policy=policy)
    await e.register("b", "c")
    sent: list[str] = []

    async def spy(pid, tid, **kw):
        sent.append(pid)
        raise AssertionError("must not be called")

    e.host.client.check = spy  # type: ignore[method-assign]
    e.host.client.cancel = spy  # type: ignore[method-assign]
    tools = {t.kind: t for t in partner_tools(e.host.partners, policy=policy, agent_id="a")}
    handle = {"partner_id": "c", "task_id": "t1"}
    hidden = {"partner": "c", "state": "unavailable", "reason": "unknown partner"}
    assert await invoke(tools["check"], handle, e.host.client, None) == hidden
    assert await invoke(tools["cancel"], handle, e.host.client, None) == hidden
    waited = await invoke(tools["wait"], {"tasks": [handle], "seconds": 0}, e.host.client, None)
    assert waited == hidden
    assert sent == []


async def test_invoke_passes_classification(env):
    policy = engine_for(egress={"partner_ceilings": {"b": "internal"}})
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), policy=policy)
    await e.register("b")
    tool = next(t for t in e.host.partner_tools("a") if t.partner_id == "b")
    res = await invoke(tool, {"message": "hi", "classification": "restricted"}, e.host.client, None)
    assert res["state"] == "rejected" and res["reason"].startswith("egress policy:")
    bad = await invoke(tool, {"message": "hi", "classification": "nope"}, e.host.client, None)
    assert bad["state"] == "rejected" and "classification" in bad["reason"]
    ok = await invoke(tool, {"message": "hi", "classification": "internal"}, e.host.client, None)
    assert ok["state"] == "completed"


async def test_startup_warns_about_unknown_routing_partners(env, caplog):
    policy = engine_for(routing=[{"agent": "a", "partners": ["ghost", "b"], "mode": "prefer"}])
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        await env(spec("a", Fn(echo)), policy=policy)
    msgs = [r.getMessage() for r in caplog.records if "unknown partner" in r.getMessage()]
    assert len(msgs) == 1 and "ghost" in msgs[0]


# -- registry events ---------------------------------------------------------------------


async def test_registry_changes_are_audited_and_chain_existing_callback(tmp_path, fast):
    seen: list[str] = []
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'r.db'}")
    host.partners.on_change = lambda rec, ev: seen.append(ev)  # installed before startup
    host.add(spec("p", Fn(echo)))
    await host.startup()
    try:
        await host.partners.add_from_card("q", json.loads(json.dumps(CARD)), "internal")
        host.partners.disable("q")
        host.partners.enable("q")
        rs = await rows(host)
        assert actions(rs) == ["partner.add", "partner.disable", "partner.enable"]
        assert all(r["actor"] == "system" and r["partner_id"] == "q" for r in rs)
        assert seen == ["added", "disabled", "enabled"]
    finally:
        await host.shutdown()
    # A second startup does not stack a second audit callback.
    await host.startup()
    try:
        before = len(await rows(host))
        host.partners.disable("q")
        assert len(await rows(host)) == before + 1
        assert seen.count("disabled") == 2
    finally:
        await host.shutdown()


# -- audit switch and failures -----------------------------------------------------------


async def test_audit_false_disables_everything(env):
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), audit=False)
    await e.register("b")
    await e.send("a", "hi")
    assert e.host.audit is None
    async with e.host.engine.connect() as conn:
        exists = await conn.run_sync(
            lambda sync: __import__("sqlalchemy").inspect(sync).has_table("a2agw_audit")
        )
    assert not exists


async def test_audit_failure_does_not_break_requests(env, monkeypatch):
    e = await env(spec("a", Fn(echo)), admin_without_auth=True)

    async def boom(self, ev):
        raise RuntimeError("db gone")

    monkeypatch.setattr(AuditLog, "append", boom)
    events = await e.send("a", "hi")
    assert final_state(events) == COMPLETED
    health = (await e.hc.get("/a2agw/admin/healthz")).json()
    assert health["status"] == "ok" and health["audit_errors"] >= 1


# -- admin -------------------------------------------------------------------------------


async def test_admin_audit_requires_admin_scope(env):
    e = await env(spec("a", Fn(echo)), auth=auth())
    async with as_caller(e, "alice-secret") as hc:
        for path in ("/a2agw/admin/audit", "/a2agw/admin/audit/verify"):
            r = await hc.get(path)
            assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    async with as_caller(e, "admin-secret") as hc:
        r = await hc.get("/a2agw/admin/audit")
        assert r.status_code == 200
        r = await hc.get("/a2agw/admin/audit/verify")
        assert r.json() == {"ok": True}


async def test_admin_audit_query_params_and_reads_are_audited(env):
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), auth=auth())
    async with as_caller(e, "alice-secret") as hc:
        await send_as(e, hc, "a", "one")
        await send_as(e, hc, "a", "two")
        await send_as(e, hc, "b", "three")
    async with as_caller(e, "admin-secret") as hc:
        r = await hc.get("/a2agw/admin/audit", params={"action": "inbound.admit", "limit": 2})
        body = r.json()
        assert [x["action"] for x in body["events"]] == ["inbound.admit"] * 2
        assert body["events"][0]["seq"] > body["events"][1]["seq"]
        assert isinstance(body["events"][0]["detail"], dict)
        r2 = await hc.get(
            "/a2agw/admin/audit",
            params={"action": "inbound.admit", "limit": 2, "cursor": body["next_cursor"]},
        )
        assert len(r2.json()["events"]) == 1 and r2.json()["next_cursor"] is None
        agent_b = (await hc.get("/a2agw/admin/audit", params={"agent": "b"})).json()["events"]
        assert agent_b and {x["agent_id"] for x in agent_b} == {"b"}
        since = await hc.get("/a2agw/admin/audit", params={"since": "2999-01-01T00:00:00Z"})
        assert since.json()["events"] == []
        for field, value in (
            ("limit", "0"),
            ("limit", "501"),
            ("limit", "x"),
            ("action", "nope"),
            ("since", "later"),
            ("cursor", "abc"),
        ):
            bad = await hc.get("/a2agw/admin/audit", params={field: value})
            assert bad.status_code == 400 and bad.json()["field"] == field, (field, value)
        await hc.get("/a2agw/admin/agents")
    rs = await rows(e.host)
    reads = [json.loads(r["detail_json"])["reason"] for r in rs if r["action"] == "admin.read"]
    assert "audit" in reads and "agents" in reads
    assert all(r["actor"] == "key:ops" for r in rs if r["action"] == "admin.read")


async def test_admin_audit_verify_reports_first_bad_seq(env):
    e = await env(spec("a", Fn(echo)), admin_without_auth=True)
    for i in range(3):
        await e.send("a", f"m{i}")
    rs = await rows(e.host)
    bad = rs[1]["seq"]
    async with e.host.engine.begin() as conn:
        await conn.execute(
            text("UPDATE a2agw_audit SET agent_id = 'zz' WHERE seq = :s"), {"s": bad}
        )
    r = await e.hc.get("/a2agw/admin/audit/verify")
    assert r.json() == {"ok": False, "first_bad_seq": bad}


# -- fix round 1 -------------------------------------------------------------------------


async def test_llm_label_cannot_lower_unknown_classification(env):
    """Reviewer probe (lower.py) end to end: the tool argument "public" does not defeat
    unknown_classification above the partner's ceiling."""
    policy = engine_for(
        defaults={"unknown_classification": "confidential"},
        egress={"partner_ceilings": {"b": "public"}},
    )
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), policy=policy)
    await e.register("b")
    tool = next(t for t in e.host.partner_tools("a") if t.partner_id == "b")
    res = await invoke(tool, {"message": "secret", "classification": "public"}, e.host.client, None)
    assert res["state"] == "rejected"
    assert "confidential exceeds public" in res["reason"]
    direct = await e.host.client.consult("b", "secret", classification="public")
    assert direct.state == "rejected"


async def test_anonymous_denials_are_coalesced_authenticated_are_not(env):
    policy = engine_for(
        authz=[
            {"principal": "key:alice", "agents": ["a"], "effect": "allow"},
        ]
    )
    e = await env(spec("a", Fn(echo)), auth=auth(), policy=policy)
    for _ in range(5):  # anonymous callers never reach the agent: auth answers 401 first
        await e.hc.post("/agents/a/", json={})
    async with as_caller(e, "mallory-secret") as hc:
        for _ in range(3):
            assert (await hc.post("/agents/a/", json={})).status_code == 403
    deny = [r for r in await rows(e.host) if r["action"] == "authz.deny"]
    assert [r["actor"] for r in deny] == ["key:mallory"] * 3

    # Without auth every caller is anonymous: one row per agent per window.
    e2 = await env(
        spec("x", Fn(echo)),
        db="anon.db",
        policy=engine_for(authz=[{"principal": "key:alice", "agents": ["x"], "effect": "allow"}]),
    )
    for _ in range(5):
        assert (await e2.hc.post("/agents/x/", json={})).status_code == 403
    deny2 = [r for r in await rows(e2.host) if r["action"] == "authz.deny"]
    assert len(deny2) == 1 and deny2[0]["actor"] == "anonymous"
    await e2.host.audit.flush_coalesced()
    deny2 = [r for r in await rows(e2.host) if r["action"] == "authz.deny"]
    assert [json.loads(r["detail_json"])["count"] for r in deny2] == [0, 3]


async def test_consult_exception_still_audits_partner_call(env, monkeypatch):
    e = await env(spec("b", Fn(echo)), policy=engine_for())
    await e.register("b")

    async def boom(*a, **kw):
        raise RuntimeError("internal bug")

    monkeypatch.setattr(e.host.client, "_consult", boom)
    with pytest.raises(RuntimeError):
        await e.host.client.consult("b", "hi")
    calls = [r for r in await rows(e.host) if r["action"] == "partner.call"]
    assert len(calls) == 1 and calls[0]["outcome"] == "error"
