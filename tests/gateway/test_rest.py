"""The outbound REST API (``/a2agw/v1``): consult partners with a run-scoped consult token
(linked to the inbound task) or with the gateway's own auth (standalone)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from contextlib import contextmanager
from typing import Any

from a2a.types import CancelTaskRequest, TaskState
from cascade_support import Fn, spec
from google.protobuf.json_format import MessageToDict

from a2agw.consult.client import FANOUT_LIMIT
from a2agw.consult.credentials import StaticCredentials
from a2agw.context.call_context import EXTENSION_URI
from a2agw.core.events import Done
from a2agw.security.auth import ApiKeyEntry, AuthConfig, hash_api_key
from a2agw.security.policy import Policy, PolicyEngine
from a2agw.security.principal import Principal

V1 = "http://t/a2agw/v1"
CANCELED = TaskState.Name(TaskState.TASK_STATE_CANCELED)
HANDLE_WAIT_S = 1.0  # see tests/integration/test_cascade.py


def bearer(grant) -> dict[str, str]:
    return {"Authorization": f"Bearer {grant.token}"}


def policy(**doc) -> PolicyEngine:
    return PolicyEngine(Policy.model_validate({"version": 1, **doc}))


class Blocker:
    durable_sessions = False

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def run(self, ctx):
        self.started.set()
        await asyncio.Event().wait()
        yield Done(text="never")


async def echo(ctx):
    yield Done(text=f"echo: {ctx.text}")


async def until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.02)


async def audit_rows(host, action: str | None = None) -> list[dict[str, Any]]:
    await host.audit.drain()
    await host.audit.flush_coalesced()
    await host.audit.drain()
    rows, _ = await host.audit.query(
        {"action": action} if action else {}, 500, None, ascending=True
    )
    return rows


# -- linked calls ----------------------------------------------------------------------


async def test_linked_consult_links_inbound_task(env):
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        grant = await e.host.consult_issuer(ctx)
        r = await e.hc.post(
            f"{V1}/partners/b/messages", json={"message": "hi"}, headers=bearer(grant)
        )
        seen.update(status=r.status_code, body=r.json(), cache=r.headers.get("cache-control"))
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)))
    await e.register("b")
    [ev] = await e.send("a", "go")
    a_task = ev.task.id
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED
    assert (seen["status"], seen["cache"]) == (200, "no-store")
    body = seen["body"]
    assert (body["partner"], body["state"], body["text"]) == ("b", "completed", "echo: hi")
    [handle] = await e.host.handles.by_inbound(a_task)
    assert (handle["partner_id"], handle["task_id"]) == ("b", body["task_id"])
    assert handle["caller_id"] == "anonymous" and handle["owner"] is None


async def test_linked_consult_continues_the_turn_trace(env, spans):
    """A linked call is a child of the turn's inbound span, even though the request arrives
    with no trace context of its own (a sidecar agent in another process)."""
    from opentelemetry import context as otel_context

    async def a_run(ctx):
        grant = await e.host.consult_issuer(ctx)
        detached = otel_context.attach(otel_context.Context())  # as from another process
        try:
            await e.hc.post(
                f"{V1}/partners/b/messages", json={"message": "hi"}, headers=bearer(grant)
            )
        finally:
            otel_context.detach(detached)
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)))
    await e.register("b")
    await e.send("a", "go")
    done = [s for s in spans.get_finished_spans() if s.name.startswith("a2agw.")]
    [a_in] = [
        s for s in done if s.name == "a2agw.inbound" and s.attributes["a2agw.agent_id"] == "a"
    ]
    [call] = [s for s in done if s.name == "a2agw.partner_call"]
    [b_in] = [
        s for s in done if s.name == "a2agw.inbound" and s.attributes["a2agw.agent_id"] == "b"
    ]
    assert call.parent is not None and call.parent.span_id == a_in.context.span_id
    assert {a_in.context.trace_id, call.context.trace_id, b_in.context.trace_id} == {
        a_in.context.trace_id
    }


async def test_cancel_inbound_cascades_to_token_started_partner_task(env):
    b = Blocker()
    seen: dict[str, Any] = {}
    consulted = asyncio.Event()

    async def a_run(ctx):
        grant = await e.host.consult_issuer(ctx)
        r = await e.hc.post(
            f"{V1}/partners/b/messages",
            json={"message": "go", "wait_seconds": HANDLE_WAIT_S},
            headers=bearer(grant),
        )
        seen["result"] = r.json()
        consulted.set()
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    await e.register("b")
    [ev] = await e.send("a", "start", return_immediately=True)
    a_task = ev.task.id
    await asyncio.wait_for(consulted.wait(), 5)
    b_task = seen["result"]["task_id"]
    assert seen["result"]["state"] == "working" and b_task

    await e.client("a").cancel_task(CancelTaskRequest(id=a_task))

    async def b_canceled() -> bool:
        rows, _ = await e.host.index.list(agent_id="b")
        return [r["state"] for r in rows if r["task_id"] == b_task] == [CANCELED]

    await until(b_canceled)
    [handle] = await e.host.handles.by_inbound(a_task)
    assert handle["state"] == CANCELED


async def test_revoking_a_grant_ends_its_call_in_flight(env):
    """A linked call still waiting on a partner when its inbound task is cancelled ends at
    once, like an embedded agent's consult would (its partner task is cancelled too)."""
    b = Blocker()
    box: dict[str, Any] = {}
    granted = asyncio.Event()

    async def a_run(ctx):
        box["grant"] = await e.host.consult_issuer(ctx)
        granted.set()
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(spec("a", Fn(a_run)), spec("b", b))
    await e.register("b")
    [ev] = await e.send("a", "start", return_immediately=True)
    await asyncio.wait_for(granted.wait(), 5)
    call = asyncio.create_task(
        e.hc.post(
            f"{V1}/partners/b/messages",
            json={"message": "go", "wait_seconds": 30},
            headers=bearer(box["grant"]),
        )
    )
    await asyncio.wait_for(b.started.wait(), 5)
    await e.client("a").cancel_task(CancelTaskRequest(id=ev.task.id))
    r = await asyncio.wait_for(call, 10)  # long before the 30 s wait
    assert r.status_code == 200
    assert r.json()["state"] == "unavailable" and r.json()["reason"] == "inbound task ended"

    async def b_canceled() -> bool:
        rows, _ = await e.host.index.list(agent_id="b")
        return [r["state"] for r in rows] == [CANCELED]

    await until(b_canceled)


async def test_revoked_token_401(env):
    box: dict[str, Any] = {}

    async def a_run(ctx):
        box["grant"] = await e.host.consult_issuer(ctx)
        box["during"] = (await e.hc.get(f"{V1}/partners", headers=bearer(box["grant"]))).status_code
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)))
    tokens = e.host.consult_tokens
    grant = tokens.issue("a", "t-x", None, None)
    assert (await e.hc.get(f"{V1}/partners", headers=bearer(grant))).status_code == 200
    tokens.revoke_task("t-x")
    r = await e.hc.get(f"{V1}/partners", headers=bearer(grant))
    assert r.status_code == 401 and r.json() == {"error": "unauthenticated"}
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.headers["cache-control"] == "no-store"

    # A run's grant ends with the run.
    await e.send("a", "go")
    assert box["during"] == 200

    async def revoked() -> bool:
        r = await e.hc.get(f"{V1}/partners", headers=bearer(box["grant"]))
        return r.status_code == 401

    await until(revoked)
    rows = await audit_rows(e.host, "sidecar.denied")
    assert rows and all(r["outcome"] == "unauthenticated" for r in rows)


async def test_token_for_other_agent_cannot_widen_routing(env):
    rules = policy(routing=[{"agent": "a", "partners": ["c"], "mode": "forbid"}])
    e = await env(
        spec("a", Fn(echo)),
        spec("b", Fn(echo)),
        spec("c", Fn(echo)),
        spec("d", Fn(echo)),
        policy=rules,
    )
    await e.register("c", "d")
    grant = e.host.consult_tokens.issue("a", "t-1", None, None)
    headers = {**bearer(grant), "X-A2AGW-Agent": "b"}  # b may use c; the token binds a
    listed = (await e.hc.get(f"{V1}/partners", headers=headers)).json()
    assert {t["partner_id"] for t in listed if t["kind"] == "consult"} == {"d"}
    r = await e.hc.post(f"{V1}/partners/c/messages", json={"message": "hi"}, headers=headers)
    assert r.json() == {"partner": "c", "state": "unavailable", "reason": "unknown partner"}
    r = await e.hc.post(f"{V1}/partners/d/messages", json={"message": "hi"}, headers=headers)
    assert r.json()["state"] == "completed"


async def test_forbidden_partner_unavailable(env):
    rules = policy(routing=[{"agent": "a", "partners": ["b"], "mode": "forbid"}])
    e = await env(spec("a", Fn(echo)), spec("b", Fn(echo)), policy=rules)
    await e.register("b")
    grant = e.host.consult_tokens.issue("a", "t-1", None, None)
    unknown = {"partner": "b", "state": "unavailable", "reason": "unknown partner"}
    for method, path, body in (
        ("POST", "/partners/b/messages", {"message": "hi"}),
        ("GET", "/partners/b/tasks/x", None),
        ("POST", "/partners/b/tasks/x/cancel", None),
        ("POST", "/wait", {"tasks": [{"partner_id": "b", "task_id": "x"}], "seconds": 0}),
    ):
        r = await e.hc.request(method, f"{V1}{path}", json=body, headers=bearer(grant))
        assert (r.status_code, r.json()) == (200, unknown), path
    find = await e.hc.post(f"{V1}/find", json={"need": "test agent b"}, headers=bearer(grant))
    assert find.json() == {"partners": []}
    rows, _ = await e.host.index.list(agent_id="b")
    assert rows == []  # nothing reached the partner


async def test_fanout_cap_applies_to_linked_calls(env):
    seen: list[dict] = []

    async def a_run(ctx):
        grant = await e.host.consult_issuer(ctx)
        for _ in range(2):
            r = await e.hc.post(
                f"{V1}/partners/b/messages", json={"message": "hi"}, headers=bearer(grant)
            )
            seen.append(r.json())
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)), max_consults_per_task=1)
    await e.register("b")
    await e.send("a", "go")
    assert [s["state"] for s in seen] == ["completed", "unavailable"]
    assert seen[1]["reason"] == FANOUT_LIMIT
    [limit] = await audit_rows(e.host, "limit.exceeded")
    assert limit["agent_id"] == "a"


async def test_hop_budget_propagates(env):
    seen: dict[str, Any] = {}

    async def a_run(ctx):
        seen["a"] = ctx.call
        grant = await e.host.consult_issuer(ctx)
        await e.hc.post(f"{V1}/partners/b/messages", json={"message": "hi"}, headers=bearer(grant))
        yield Done(text="ok")

    async def b_run(ctx):
        seen["b"] = ctx.metadata[EXTENSION_URI]
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    await e.register("b")
    await e.send("a", "go")
    a_call, received = seen["a"], seen["b"]
    assert a_call.hop == 1  # the inbound call (hop 0) plus one
    assert received["hop"] == a_call.hop
    assert received["origin"] == a_call.origin
    assert received["path"] == list(a_call.path) == ["a"]
    assert (received["max_hops"], received["calls_used"], received["deadline"]) == (
        a_call.max_hops,
        a_call.calls_used,
        a_call.deadline,
    )


async def test_token_never_logged_or_audited(env, caplog):
    caplog.set_level(logging.DEBUG)
    box: dict[str, Any] = {}

    async def a_run(ctx):
        grant = box["grant"] = await e.host.consult_issuer(ctx)
        await e.hc.get(f"{V1}/partners", headers=bearer(grant))
        await e.hc.post(f"{V1}/partners/b/messages", json={"message": "hi"}, headers=bearer(grant))
        await e.hc.post(f"{V1}/partners/b/messages", content=b"{", headers=bearer(grant))
        yield Done(text="ok")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(echo)))
    await e.register("b")
    await e.send("a", "go")
    token = box["grant"].token

    async def revoked() -> bool:
        r = await e.hc.get(f"{V1}/partners", headers=bearer(box["grant"]))
        return r.status_code == 401

    await until(revoked)
    rows = await audit_rows(e.host)
    assert any(r["action"] == "sidecar.denied" for r in rows)
    assert any(r["action"] == "partner.call" for r in rows)
    assert token not in json.dumps(rows)
    assert token not in caplog.text
    for record in caplog.records:
        assert token not in repr(record.args)


async def test_body_cap_413(env):
    e = await env(spec("a", Fn(echo)))
    grant = e.host.consult_tokens.issue("a", "t-1", None, None)
    big = json.dumps({"message": "x" * (300 * 1024)}).encode()
    r = await e.hc.post(f"{V1}/partners/b/messages", content=big, headers=bearer(grant))
    assert r.status_code == 413 and r.json() == {"error": "payload too large"}
    assert r.headers["cache-control"] == "no-store"

    async def chunks():  # no content-length: the cap applies while reading
        for _ in range(300):
            yield b" " * 1024

    r = await e.hc.post(f"{V1}/wait", content=chunks(), headers=bearer(grant))
    assert r.status_code == 413


async def test_partner_list_and_task_routes(env):
    b = Blocker()
    e = await env(spec("a", Fn(echo)), spec("b", b))
    await e.register("b")
    grant = e.host.consult_tokens.issue("a", "t-1", None, None)
    h = bearer(grant)
    tools = (await e.hc.get(f"{V1}/partners", headers=h)).json()
    assert {t["kind"] for t in tools} == {"consult", "check", "cancel", "wait"}
    [ask] = [t for t in tools if t["kind"] == "consult"]
    assert set(ask) == {"name", "description", "parameters", "partner_id", "kind"}
    assert ask["partner_id"] == "b" and ask["parameters"]["required"] == ["message"]

    r = await e.hc.post(
        f"{V1}/partners/b/messages",
        json={"message": "go", "wait_seconds": HANDLE_WAIT_S},
        headers=h,
    )
    tid = r.json()["task_id"]
    assert r.json()["state"] == "working"
    check = await e.hc.get(f"{V1}/partners/b/tasks/{tid}", headers=h)
    assert (check.json()["state"], check.headers["cache-control"]) == ("working", "no-store")
    wait = await e.hc.post(
        f"{V1}/wait", json={"tasks": [{"partner_id": "b", "task_id": tid}], "seconds": 0}, headers=h
    )
    assert [x["state"] for x in wait.json()["results"]] == ["working"]
    found = await e.hc.post(f"{V1}/find", json={"need": "test agent b", "k": 3}, headers=h)
    assert [p["partner_id"] for p in found.json()["partners"]] == ["b"]
    cancel = await e.hc.post(f"{V1}/partners/b/tasks/{tid}/cancel", headers=h)
    assert cancel.json()["state"] == "canceled"

    bad = await e.hc.post(f"{V1}/partners/b/messages", json={"text": "x"}, headers=h)
    assert bad.json()["state"] == "rejected"  # the tool's own argument check
    for content in (b"{", b"[]", b"\xff"):
        r = await e.hc.post(f"{V1}/partners/b/messages", content=content, headers=h)
        assert r.status_code == 400 and r.json() == {"error": "bad request"}


# -- standalone calls ------------------------------------------------------------------

SVC, PLAIN, PEER = "svc-key", "plain-key", "peer-key"


def auth_config() -> AuthConfig:
    return AuthConfig(
        api_keys={
            hash_api_key(SVC): ApiKeyEntry(principal_id="svc", scopes=["a2agw:sidecar"]),
            hash_api_key(PLAIN): ApiKeyEntry(principal_id="plain", scopes=["other"]),
            hash_api_key(PEER): ApiKeyEntry(principal_id="peer"),
        }
    )


async def test_standalone_needs_scope_and_mapping(env):
    e = await env(
        spec("a", Fn(echo)),
        spec("b", Fn(echo)),
        auth=auth_config(),
        sidecar_clients={"key:svc": ["a", "tool-bot"], "key:plain": ["a"]},
        credentials=StaticCredentials({"gw": {"X-API-Key": PEER}}),
    )
    host = e.host
    await host.partners.add_from_card(
        "b", MessageToDict(e.host.cards["b"]), "internal", credential_ref="gw"
    )

    async def status(key: str | None, agent: str | None) -> int:
        headers = {}
        if key is not None:
            headers["X-API-Key"] = key
        if agent is not None:
            headers["X-A2AGW-Agent"] = agent
        return (await e.hc.get(f"{V1}/partners", headers=headers)).status_code

    assert await status(None, "a") == 401
    assert await status("wrong", "a") == 401
    assert await status(PLAIN, "a") == 401  # mapped, but no a2agw:sidecar scope
    assert await status(SVC, None) == 401
    assert await status(SVC, "c") == 403  # not mapped to this principal
    assert await status(SVC, "a") == 200
    assert await status(SVC, "tool-bot") == 200  # an identity, not a served agent

    r = await e.hc.post(
        f"{V1}/partners/b/messages",
        json={"message": "hi"},
        headers={"X-API-Key": SVC, "X-A2AGW-Agent": "a"},
    )
    body = r.json()
    assert (body["state"], body["text"]) == ("completed", "echo: hi")
    handle = await host.handles.get("b", body["task_id"])
    assert handle["inbound_task_id"] is None
    assert (handle["owner"], handle["caller_id"]) == ("sidecar:a", "key:svc")

    denied = await audit_rows(host, "sidecar.denied")
    assert {(r["outcome"], r["agent_id"]) for r in denied} >= {
        ("forbidden", "c"),
        ("unauthenticated", "a"),
    }
    for r in denied:
        assert set(r["detail"]) <= {"reason", "count"}
    assert all(SVC not in json.dumps(r) and PLAIN not in json.dumps(r) for r in denied)


async def test_standalone_call_context_is_a_fresh_root(env):
    seen: dict[str, Any] = {}

    async def b_run(ctx):
        seen["b"] = ctx.metadata[EXTENSION_URI]
        yield Done(text="ok")

    e = await env(
        spec("a", Fn(echo)),
        spec("b", Fn(b_run)),
        auth=auth_config(),
        sidecar_clients={"key:svc": ["a"]},
        credentials=StaticCredentials({"gw": {"X-API-Key": PEER}}),
    )
    await e.host.partners.add_from_card(
        "b", MessageToDict(e.host.cards["b"]), "internal", credential_ref="gw"
    )
    await e.hc.post(
        f"{V1}/partners/b/messages",
        json={"message": "hi"},
        headers={"X-API-Key": SVC, "X-A2AGW-Agent": "a"},
    )
    assert (seen["b"]["hop"], seen["b"]["path"], seen["b"]["root_agent"]) == (0, ["a"], "a")


# -- task ownership (fix round 1) ---------------------------------------------------------

UNKNOWN_TASK = {"partner": "b", "state": "unavailable", "reason": "unknown task"}
WORKING = TaskState.Name(TaskState.TASK_STATE_WORKING)


async def task_ops(e, headers: dict[str, str], tid: str) -> list[Any]:
    """check, cancel, wait and a reply on partner b's task ``tid``: the JSON answers."""
    out = []
    for method, path, body in (
        ("GET", f"/partners/b/tasks/{tid}", None),
        ("POST", f"/partners/b/tasks/{tid}/cancel", None),
        ("POST", "/wait", {"tasks": [{"partner_id": "b", "task_id": tid}], "seconds": 0}),
        ("POST", "/partners/b/messages", {"message": "more", "task_id": tid}),
    ):
        r = await e.hc.request(method, f"{V1}{path}", json=body, headers=headers)
        out.append(r.json())
    return out


async def b_states(e) -> list[str]:
    rows, _ = await e.host.index.list(agent_id="b")
    return [r["state"] for r in rows]


async def test_task_ops_need_the_linked_inbound_task(env):
    e = await env(spec("a", Fn(echo)), spec("b", Blocker()))
    await e.register("b")
    tokens = e.host.consult_tokens
    owner = bearer(tokens.issue("a", "T1", None, None))
    r = await e.hc.post(
        f"{V1}/partners/b/messages",
        json={"message": "go", "wait_seconds": HANDLE_WAIT_S},
        headers=owner,
    )
    tid = r.json()["task_id"]
    for other in (tokens.issue("a", "T2", None, None), tokens.issue("b", "T3", None, None)):
        assert await task_ops(e, bearer(other), tid) == [UNKNOWN_TASK] * 4
    # Not reaching the partner at all: its task still runs, and an unknown id looks the same.
    assert await b_states(e) == [WORKING]
    check = await e.hc.get(f"{V1}/partners/b/tasks/nope", headers=owner)
    assert check.json() == UNKNOWN_TASK
    # The owner's own calls work.
    check = await e.hc.get(f"{V1}/partners/b/tasks/{tid}", headers=owner)
    assert check.json()["state"] == "working"
    cancel = await e.hc.post(f"{V1}/partners/b/tasks/{tid}/cancel", headers=owner)
    assert cancel.json()["state"] == "canceled"


SVC2 = "svc2-key"


def auth_config2() -> AuthConfig:
    cfg = auth_config()
    cfg.api_keys[hash_api_key(SVC2)] = ApiKeyEntry(principal_id="svc2", scopes=["a2agw:sidecar"])
    return cfg


async def standalone_env(env, b_adapter, **kw):
    e = await env(
        spec("a", Fn(echo)),
        spec("b", b_adapter),
        auth=auth_config2(),
        sidecar_clients={"key:svc": ["a"], "key:svc2": ["a"]},
        credentials=StaticCredentials({"gw": {"X-API-Key": PEER}}),
        **kw,
    )
    card = MessageToDict(e.host.cards["b"])
    await e.host.partners.add_from_card("b", card, "internal", credential_ref="gw")
    return e


def as_svc(key: str) -> dict[str, str]:
    return {"X-API-Key": key, "X-A2AGW-Agent": "a"}


async def test_standalone_task_ops_need_owner_and_caller(env):
    e = await standalone_env(env, Blocker())
    ask = {"message": "go", "wait_seconds": HANDLE_WAIT_S}
    r = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC))
    mine = r.json()["task_id"]
    linked = bearer(e.host.consult_tokens.issue("a", "T1", None, None))
    r = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=linked)
    theirs = r.json()["task_id"]
    assert await task_ops(e, as_svc(SVC), theirs) == [UNKNOWN_TASK] * 4  # a linked handle
    assert await task_ops(e, as_svc(SVC2), mine) == [UNKNOWN_TASK] * 4  # another caller's
    assert await task_ops(e, linked, mine) == [UNKNOWN_TASK] * 4  # a standalone handle
    assert await b_states(e) == [WORKING, WORKING]
    check = await e.hc.get(f"{V1}/partners/b/tasks/{mine}", headers=as_svc(SVC))
    assert check.json()["state"] == "working"


async def test_standalone_open_task_cap(env):
    e = await standalone_env(env, Blocker(), max_open_sidecar_tasks_per_caller=1)
    ask = {"message": "go", "wait_seconds": HANDLE_WAIT_S}
    first = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC))
    assert first.json()["state"] == "working"
    second = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC))
    assert second.json() == {
        "partner": "b",
        "state": "unavailable",
        "reason": "too many open tasks",
    }
    assert await b_states(e) == [WORKING]  # nothing sent
    other = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC2))
    assert other.json()["state"] == "working"  # counted per caller
    [row] = await audit_rows(e.host, "limit.exceeded")
    assert (row["actor"], row["agent_id"], row["partner_id"]) == ("key:svc", "a", "b")
    assert row["detail"]["limit"] == "max_open_sidecar_tasks_per_caller"
    assert row["detail"]["count"] == 1
    # Once the task ends, the slot is free again.
    tid = first.json()["task_id"]
    await e.hc.post(f"{V1}/partners/b/tasks/{tid}/cancel", headers=as_svc(SVC))
    again = await e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC))
    assert again.json()["state"] == "working"


async def test_unknown_paths_under_the_prefix_stay_in_the_api(env):
    e = await env(spec("a", Fn(echo)), auth=auth_config())
    cases = (
        ("POST", "/a2agw/v1/partners", 405),
        ("DELETE", "/a2agw/v1/partners/b/tasks/x", 405),
        ("GET", "/a2agw/v1/nope", 404),
        ("GET", "/a2agw/v1/agents/a/.well-known/agent-card.json", 404),
        ("GET", "/a2agw/v1", 404),
    )
    for method, path, status in cases:
        r = await e.hc.request(method, f"http://t{path}", headers={"X-API-Key": "wrong"})
        assert r.status_code == status, path
        assert r.headers["cache-control"] == "no-store", path  # answered by the API itself
    assert (await e.hc.post(f"{V1}/partners")).headers["allow"] == "GET, HEAD"


async def test_linked_partner_call_rows_carry_the_grant_id(env):
    e = await standalone_env(env, Fn(echo))
    grant = e.host.consult_tokens.issue("a", "T1", None, None)
    await e.hc.post(f"{V1}/partners/b/messages", json={"message": "x"}, headers=bearer(grant))
    await e.hc.post(f"{V1}/partners/b/messages", json={"message": "x"}, headers=as_svc(SVC))
    rows = await audit_rows(e.host, "partner.call")
    linked, standalone = rows
    assert linked["detail"]["grant"] == hashlib.sha256(grant.token.encode()).hexdigest()[:12]
    assert "grant" not in standalone["detail"]
    assert grant.token not in json.dumps(rows)


async def test_revoked_mid_request_is_audited_with_the_binding(env, monkeypatch):
    e = await env(spec("a", Fn(echo)))
    alice = Principal("key:alice", "api_key", frozenset())
    grant = e.host.consult_tokens.issue("a", "T1", None, alice)

    @contextmanager
    def gone(binding, task):
        yield False  # revoked between authentication and the call

    monkeypatch.setattr(e.host.consult_tokens, "track", gone)
    r = await e.hc.get(f"{V1}/partners", headers=bearer(grant))
    assert r.status_code == 401
    [row] = await audit_rows(e.host, "sidecar.denied")
    assert (row["actor"], row["agent_id"], row["detail"]["reason"]) == (
        "key:alice",
        "a",
        "consult token revoked",
    )


# -- fix round 2 ---------------------------------------------------------------------------


async def test_standalone_open_task_cap_is_hard_under_concurrency(env):
    """Concurrent first consults cannot all pass the open-task check before any of them
    records its partner task: exactly ``cap`` proceed."""
    e = await standalone_env(env, Blocker(), max_open_sidecar_tasks_per_caller=2)
    ask = {"message": "go", "wait_seconds": HANDLE_WAIT_S}
    replies = await asyncio.gather(
        *(e.hc.post(f"{V1}/partners/b/messages", json=ask, headers=as_svc(SVC)) for _ in range(6))
    )
    states = sorted(r.json()["state"] for r in replies)
    assert states == ["unavailable"] * 4 + ["working"] * 2
    assert {r.json().get("reason") for r in replies if r.json()["state"] == "unavailable"} == {
        "too many open tasks"
    }
    assert await b_states(e) == [WORKING, WORKING]


async def test_wait_bounds_handle_lookups(env, monkeypatch):
    e = await env(spec("a", Fn(echo)), spec("b", Blocker()))
    await e.register("b")
    h = bearer(e.host.consult_tokens.issue("a", "T1", None, None))
    r = await e.hc.post(
        f"{V1}/partners/b/messages",
        json={"message": "go", "wait_seconds": HANDLE_WAIT_S},
        headers=h,
    )
    tid = r.json()["task_id"]
    lookups = 0
    get = e.host.handles.get

    async def counting(pid, task_id):
        nonlocal lookups
        lookups += 1
        return await get(pid, task_id)

    monkeypatch.setattr(e.host.handles, "get", counting)
    item = {"partner_id": "b", "task_id": tid}
    r = await e.hc.post(f"{V1}/wait", json={"tasks": [item] * 1000, "seconds": 0}, headers=h)
    assert r.json()["state"] == "rejected"
    assert lookups <= 20
    lookups = 0
    r = await e.hc.post(f"{V1}/wait", json={"tasks": [item] * 20, "seconds": 0}, headers=h)
    assert [x["state"] for x in r.json()["results"]] == ["working"]
    assert lookups == 1  # the same handle is looked up once


async def test_agent_header_must_be_a_valid_agent_id(env):
    """An ``X-A2AGW-Agent`` that is not a valid agent id (``AGENT_ID_PATTERN``) counts as no
    agent id: refused before any mapping check, and audited without the value."""
    e = await env(
        spec("a", Fn(echo)),
        auth=auth_config(),
        # Host kwargs are not validated like the config: a bad id must still never match.
        sidecar_clients={"key:svc": ["a", "Bad_Agent"]},
    )

    async def status(agent: str) -> int:
        headers = {"X-API-Key": SVC, "X-A2AGW-Agent": agent}
        return (await e.hc.get(f"{V1}/partners", headers=headers)).status_code

    assert await status("a") == 200
    for bad in ("Bad_Agent", "../../etc/passwd", "a" * 64, "-a"):
        assert await status(bad) == 401, bad
    denied = await audit_rows(e.host, "sidecar.denied")
    assert denied and all(r["agent_id"] is None for r in denied), denied
    assert {r["detail"]["reason"] for r in denied} == {"no agent id"}
