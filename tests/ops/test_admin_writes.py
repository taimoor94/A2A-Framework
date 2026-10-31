"""Admin API writes: task detail, cancel; partner and policy writes (``a2agw.ops.actions``)."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Part, SendMessageConfiguration, SendMessageRequest
from cascade_support import Fn, msg
from cascade_support import spec as cspec
from google.protobuf.json_format import MessageToDict

from a2agw.consult import netguard
from a2agw.consult.registry import card_hash
from a2agw.core.events import ArtifactChunk, Done, NeedInput, Status
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

A = "/a2agw/admin"
ADMIN = {"X-API-Key": "admin-secret"}
ADMIN_POST = {**ADMIN, "X-A2AGW-Admin": "1"}
USER = {"X-API-Key": "user-secret"}
OPS = "key:ops"
CANCELED = "TASK_STATE_CANCELED"

CARD = {
    "name": "Partner",
    "description": "does things",
    "version": "1.0",
    "supportedInterfaces": [
        {
            "url": "https://partner.example.com/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "capabilities": {},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
}


def auth() -> AuthConfig:
    def h(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    return AuthConfig(
        api_keys={
            h("admin-secret"): ApiKeyEntry(principal_id="ops", scopes=["a2agw:admin"]),
            h("user-secret"): ApiKeyEntry(principal_id="user", scopes=["other"]),
        }
    )


def spec(agent_id: str, adapter) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="d",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter,
    )


async def finished(ctx):
    yield Done(text="done")


async def busy(ctx):
    """60 status messages and 62 artifacts (two with files), then a question."""
    for i in range(60):
        yield Status(text=f"step {i}")
        yield ArtifactChunk(parts=[Part(text=f"a{i}")], artifact_id=f"art-{i}", name=f"n{i}")
    yield ArtifactChunk(
        parts=[
            Part(raw=b"TOP-SECRET-BYTES", filename="f.bin", media_type="application/octet-stream")
        ],
        artifact_id="file-raw",
        name="raw",
    )
    yield ArtifactChunk(
        parts=[
            Part(url="https://files.example/SECRET-URL", filename="u.txt", media_type="text/plain")
        ],
        artifact_id="file-url",
        name="url",
    )
    yield NeedInput(question="what next?")


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(host):
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


@pytest.fixture
async def make(tmp_path):
    made: list[tuple[AgentHost, httpx.AsyncClient]] = []

    async def _make(*specs: AgentSpec, **kw) -> tuple[AgentHost, httpx.AsyncClient]:
        kw.setdefault("auth", auth())
        host = AgentHost(
            "http://t",
            db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
            partners_path=tmp_path / "partners.yaml",
            **kw,
        )
        for s in specs:
            host.add(s)
        await host.startup()
        hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
        made.append((host, hc))
        return host, hc

    yield _make
    for host, hc in made:
        await hc.aclose()
        await host.shutdown()


async def send(host: AgentHost, agent_id: str, text: str = "hi", **headers) -> dict:
    """SendMessage (blocking) as the given caller; returns the task as a dict."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()), base_url="http://t", headers=headers
    ) as authed:
        c = ClientFactory(ClientConfig(httpx_client=authed, streaming=False)).create(
            host.cards[agent_id]
        )
        req = SendMessageRequest(message=msg(text))
        req.configuration.CopyFrom(SendMessageConfiguration(return_immediately=False))
        events = [ev async for ev in c.send_message(req)]
    return MessageToDict(events[-1].task)


# -- task detail ----------------------------------------------------------------------------


async def test_task_detail_shape_and_caps(make):
    host, hc = await make(spec("alpha", Fn(busy)))
    task = await send(host, "alpha", **USER)
    tid = task["id"]
    r = await hc.get(f"{A}/tasks/alpha/{tid}", headers=ADMIN)
    assert r.status_code == 200, r.text
    body = r.json()
    t = body["task"]
    assert set(t) == {
        "id",
        "context_id",
        "state",
        "owner",
        "updated_at",
        "trace_id",
        "status_message",
        "history",
        "artifacts",
    }
    assert t["id"] == tid and t["context_id"] == task["contextId"]
    assert t["state"] == "TASK_STATE_INPUT_REQUIRED" and t["owner"] == "key:user"
    assert isinstance(t["updated_at"], float)
    assert t["trace_id"] is None or len(t["trace_id"]) == 32
    assert t["status_message"] == "what next?"
    assert body["pending_prompt"] == "what next?"
    assert body["partner_tasks"] == []
    # Capped at the last 50 of each.
    assert len(t["history"]) == 50 and len(t["artifacts"]) == 50
    assert t["artifacts"][-1]["artifact_id"] == "file-url"
    assert t["artifacts"][0]["artifact_id"] == "art-12"
    assert t["history"][-1]["parts"] == [{"kind": "text", "text": "step 59"}]
    assert t["history"][-1]["role"] == "agent"
    files = {a["artifact_id"]: a["parts"] for a in t["artifacts"][-2:]}
    assert files == {
        "file-raw": [
            {
                "kind": "file",
                "name": "f.bin",
                "media_type": "application/octet-stream",
                "size": len(b"TOP-SECRET-BYTES"),
            }
        ],
        "file-url": [{"kind": "file", "name": "u.txt", "media_type": "text/plain", "size": None}],
    }
    text = r.text
    assert "TOP-SECRET-BYTES" not in text
    assert base64.b64encode(b"TOP-SECRET-BYTES").decode() not in text
    assert "SECRET-URL" not in text
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "admin.read"})
    reads = [r for r in rows if r["detail"].get("reason") == "tasks.detail"]
    assert [(r["actor"], r["agent_id"], r["task_id"]) for r in reads] == [(OPS, "alpha", tid)]


async def test_task_detail_404_does_not_leak_existence(make, monkeypatch):
    host, hc = await make(spec("alpha", Fn(finished)), spec("beta", Fn(finished)))
    tid = (await send(host, "alpha", **USER))["id"]
    # One index lookup on every path, found or not (the same timing class).
    calls: list[tuple] = []
    real_get = host.index.get

    async def counting_get(agent_id, task_id):
        calls.append((agent_id, task_id))
        return await real_get(agent_id, task_id)

    monkeypatch.setattr(host.index, "get", counting_get)
    responses = []
    for path in (
        f"tasks/ghost/{tid}",  # unknown agent, real task id
        "tasks/alpha/nope",  # known agent, unknown task
        f"tasks/beta/{tid}",  # another agent's task
    ):
        for method, suffix, headers in (
            ("GET", "", ADMIN),
            ("POST", "/cancel", ADMIN_POST),
            ("POST", "/answer", ADMIN_POST),
        ):
            kw = {"json": {"text": "x"}} if suffix == "/answer" else {}
            r = await hc.request(method, f"{A}/{path}{suffix}", headers=headers, **kw)
            responses.append((r.status_code, r.content))
    assert set(responses) == {(404, b'{"error":"not found"}')}
    assert len(calls) == 9  # each request did exactly one index lookup
    # The real one is found.
    assert (await hc.get(f"{A}/tasks/alpha/{tid}", headers=ADMIN)).status_code == 200


# -- cancel ---------------------------------------------------------------------------------


class Blocker:
    durable_sessions = False

    async def run(self, ctx):
        await asyncio.Event().wait()
        yield Done(text="never")


async def until(predicate, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.02)


async def test_cancel_running_task_cascades_to_partner_tasks(env):
    seen: dict = {}
    consulted = asyncio.Event()

    async def a_run(ctx):
        seen["result"] = await host.client.consult("b", "go", wait_seconds=1.0)
        consulted.set()
        await asyncio.Event().wait()
        yield Done(text="never")

    e = await env(cspec("a", Fn(a_run)), cspec("b", Blocker()), admin_without_auth=True)
    host = e.host
    await e.register("b")
    events = await e.send("a", "start", return_immediately=True)
    a_task = events[0].task.id
    await asyncio.wait_for(consulted.wait(), 5)
    b_task = seen["result"].task_id
    assert seen["result"].state == "working" and b_task

    detail = (await e.hc.get(f"{A}/tasks/a/{a_task}")).json()
    assert [(p["partner_id"], p["task_id"]) for p in detail["partner_tasks"]] == [("b", b_task)]

    r = await e.hc.post(f"{A}/tasks/a/{a_task}/cancel", headers={"X-A2AGW-Admin": "1"})
    assert r.status_code == 200, r.text
    assert r.json() == {"state": CANCELED}

    async def b_canceled() -> bool:
        rows, _ = await host.index.list(agent_id="b")
        return [r["state"] for r in rows if r["task_id"] == b_task] == [CANCELED]

    await until(b_canceled)
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "task.cancel"})
    assert [(r["actor"], r["agent_id"], r["task_id"], r["outcome"]) for r in rows] == [
        ("anonymous", "a", a_task, "ok")
    ]


async def test_cancel_final_task_409(make):
    host, hc = await make(spec("alpha", Fn(finished)))
    tid = (await send(host, "alpha", **USER))["id"]
    r = await hc.post(f"{A}/tasks/alpha/{tid}/cancel", headers=ADMIN_POST)
    assert r.status_code == 409 and r.json() == {"error": "task is final"}
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "task.cancel"})
    assert [(r["actor"], r["outcome"]) for r in rows] == [(OPS, "refused")]


# -- partners -------------------------------------------------------------------------------


async def test_partner_crud_round_trip(make, monkeypatch):
    host, hc = await make(spec("alpha", Fn(finished)))

    async def refresh(id):  # no network: re-fetch stages a changed card
        rec = host.partners.get(id)
        rec.pending_card = {**copy.deepcopy(CARD), "description": "now evil"}
        rec.status = "quarantined"
        host.partners._changed(rec, "quarantined")
        return "quarantined"

    monkeypatch.setattr(host.partners, "refresh", refresh)

    r = await hc.post(
        f"{A}/partners",
        headers=ADMIN_POST,
        json={"id": "p1", "card": CARD, "tier": "partner", "tags": ["eu"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["id"] == "p1" and r.json()["status"] == "active"
    dup = await hc.post(
        f"{A}/partners", headers=ADMIN_POST, json={"id": "p1", "card": CARD, "tier": "partner"}
    )
    assert dup.status_code == 409

    r = await hc.post(f"{A}/partners/p1/refresh", headers=ADMIN_POST)
    assert r.status_code == 200 and r.json()["status"] == "quarantined"
    detail = (await hc.get(f"{A}/partners/p1", headers=ADMIN)).json()
    assert detail["diff"] == [
        {
            "path": "description",
            "kind": "changed",
            "old": "does things",
            "new": "now evil",
            "significant": True,
        }
    ]
    pending = detail["pending_hash"]
    assert pending == card_hash(detail["pending_card"])
    r = await hc.post(
        f"{A}/partners/p1/approve", headers=ADMIN_POST, json={"expected_hash": pending}
    )
    assert r.status_code == 200 and r.json()["status"] == "active"
    assert r.json()["card"]["description"] == "now evil"

    await hc.post(f"{A}/partners/p1/refresh", headers=ADMIN_POST)
    r = await hc.post(f"{A}/partners/p1/reject", headers=ADMIN_POST)
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert r.json()["pending_card"] is None
    r = await hc.post(f"{A}/partners/p1/enable", headers=ADMIN_POST)
    assert r.status_code == 200 and r.json()["status"] == "active"
    r = await hc.post(f"{A}/partners/p1/disable", headers=ADMIN_POST)
    assert r.status_code == 200 and r.json()["status"] == "disabled"

    r = await hc.delete(f"{A}/partners/p1", headers=ADMIN_POST)
    assert r.status_code == 200 and r.json()["removed"] == "p1"
    assert (await hc.get(f"{A}/partners/p1", headers=ADMIN)).status_code == 404
    assert (await hc.delete(f"{A}/partners/p1", headers=ADMIN_POST)).status_code == 404


async def test_partner_add_errors(make):
    _, hc = await make(spec("alpha", Fn(finished)))
    bad = await hc.post(f"{A}/partners", headers=ADMIN_POST, json={"id": "p1", "tier": "x"})
    assert bad.status_code == 400 and bad.json()["error"] == "bad request"
    both = await hc.post(
        f"{A}/partners",
        headers=ADMIN_POST,
        json={"id": "p1", "card": CARD, "card_url": "https://x", "tier": "public"},
    )
    assert both.status_code == 400
    broken = await hc.post(
        f"{A}/partners",
        headers=ADMIN_POST,
        json={"id": "p1", "card": {"name": 5}, "tier": "public"},
    )
    assert broken.status_code == 422 and broken.json()["error"] == "card not accepted"


async def test_partner_delete_with_open_handles_409(make):
    host, hc = await make(spec("alpha", Fn(finished)))
    await hc.post(
        f"{A}/partners", headers=ADMIN_POST, json={"id": "p1", "card": CARD, "tier": "partner"}
    )
    await host.handles.record("t1", "p1", "c1", None, None, "TASK_STATE_WORKING")
    r = await hc.delete(f"{A}/partners/p1", headers=ADMIN_POST)
    assert r.status_code == 409 and r.json()["open_handles"] == 1
    assert (await hc.delete(f"{A}/partners/p1?force=maybe", headers=ADMIN_POST)).status_code == 400


async def test_approve_wrong_hash_409(make, monkeypatch):
    host, hc = await make(spec("alpha", Fn(finished)))
    await hc.post(
        f"{A}/partners", headers=ADMIN_POST, json={"id": "p1", "card": CARD, "tier": "partner"}
    )
    rec = host.partners.get("p1")
    rec.pending_card = {**copy.deepcopy(CARD), "description": "now evil"}
    rec.status = "quarantined"
    r = await hc.post(
        f"{A}/partners/p1/approve", headers=ADMIN_POST, json={"expected_hash": "0" * 64}
    )
    assert r.status_code == 409
    assert r.json() == {"error": "pending card changed since it was reviewed"}
    assert host.partners.get("p1").status == "quarantined"  # unchanged
    assert (
        await hc.post(f"{A}/partners/p1/approve", headers=ADMIN_POST, json={})
    ).status_code == 400
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "partner.approve"})
    assert [(r["actor"], r["outcome"]) for r in rows] == [(OPS, "refused")]


# -- policy ---------------------------------------------------------------------------------

LOCKDOWN = {
    "version": 1,
    "authz": [{"id": "lock", "principal": "*", "agents": ["alpha"], "effect": "deny"}],
}


async def test_policy_put_validates_and_swaps(make):
    host, hc = await make(spec("alpha", Fn(finished)))
    r = await hc.get(f"{A}/policy", headers=ADMIN)
    assert r.json() == {"managed": False, "source": None, "policy": None}

    bad = await hc.put(
        f"{A}/policy",
        headers=ADMIN_POST,
        json={"version": 1, "authz": [{"principal": "s3cret", "effect": "nope"}]},
    )
    assert bad.status_code == 422
    assert bad.json()["error"] == "invalid policy"
    assert "authz.0.effect" in bad.json()["fields"] and "authz.0.agents" in bad.json()["fields"]
    assert "s3cret" not in bad.text and "nope" not in bad.text
    assert host.policy is None
    for doc in (b"null", b"[1]"):  # never clears or crashes: only a mapping is a policy
        r = await hc.put(f"{A}/policy", headers=ADMIN_POST, content=doc)
        assert r.status_code == 422 and r.json()["fields"] == ["<root>"]

    r = await hc.put(f"{A}/policy", headers=ADMIN_POST, json=LOCKDOWN)
    assert r.status_code == 200, r.text
    assert r.json()["policy"]["authz"][0]["id"] == "lock"
    # In force at once: the user is refused at the agent mount.
    refused = await hc.post("/agents/alpha/", json={}, headers=USER)
    assert refused.status_code == 403
    got = (await hc.get(f"{A}/policy", headers=ADMIN)).json()
    assert got["managed"] is False and got["source"] == "admin"
    assert got["policy"]["authz"][0]["effect"] == "deny"
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "policy.update"})
    assert [(r["actor"], r["outcome"]) for r in rows] == [(OPS, "applied")] + [
        (OPS, "rejected")
    ] * 3


async def test_policy_put_409_when_managed(make):
    host, hc = await make(spec("alpha", Fn(finished)))
    host.policy_managed = True
    r = await hc.put(f"{A}/policy", headers=ADMIN_POST, json=LOCKDOWN)
    assert r.status_code == 409 and r.json() == {"error": "policy is managed by the control plane"}
    assert host.policy is None
    assert (await hc.get(f"{A}/policy", headers=ADMIN)).json()["managed"] is True
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": "policy.update"})
    assert [(r["actor"], r["outcome"]) for r in rows] == [(OPS, "refused")]


# -- auth, CSRF and audit -------------------------------------------------------------------

WRITES = [
    ("POST", "partners", {"id": "p9", "card": CARD, "tier": "partner"}),
    ("POST", "partners/p1/approve", {"expected_hash": "x"}),
    ("POST", "partners/p1/reject", None),
    ("POST", "partners/p1/disable", None),
    ("POST", "partners/p1/enable", None),
    ("POST", "partners/p1/refresh", None),
    ("DELETE", "partners/p1", None),
    ("PUT", "policy", {"version": 1}),
    ("POST", "tasks/alpha/t1/cancel", None),
    ("POST", "tasks/alpha/t1/answer", {"text": "x"}),
]
READS = ["partners/p1", "policy", "tasks/alpha/t1"]


async def test_writes_need_csrf_header_and_admin_scope(make):
    host, hc = await make(spec("alpha", Fn(finished)))
    await hc.post(
        f"{A}/partners", headers=ADMIN_POST, json={"id": "p1", "card": CARD, "tier": "partner"}
    )
    for method, path, body in WRITES:
        kw = {"json": body} if body is not None else {}
        assert (await hc.request(method, f"{A}/{path}", **kw)).status_code == 401
        r = await hc.request(method, f"{A}/{path}", headers={**USER, "X-A2AGW-Admin": "1"}, **kw)
        assert r.status_code == 403, (method, path)
        r = await hc.request(method, f"{A}/{path}", headers=ADMIN, **kw)
        assert r.status_code == 403, (method, path)
        assert "X-A2AGW-Admin" in r.json()["error"]
    for path in READS:
        assert (await hc.get(f"{A}/{path}", headers=USER)).status_code == 403
    assert host.partners.get("p1").status == "active"  # nothing changed
    assert host.policy is None


async def test_every_write_audited(make, monkeypatch):
    host, hc = await make(spec("alpha", Fn(busy)))

    async def refresh(id):
        return "unchanged"

    monkeypatch.setattr(host.partners, "refresh", refresh)
    tid = (await send(host, "alpha", **USER))["id"]
    calls = [
        ("POST", "partners", {"id": "p1", "card": CARD, "tier": "partner"}, "partner.add"),
        ("POST", "partners/p1/refresh", None, None),  # no change: nothing to audit
        ("POST", "partners/p1/disable", None, "partner.disable"),
        ("POST", "partners/p1/enable", None, "partner.enable"),
        ("PUT", "policy", {"version": 1}, "policy.update"),
        ("POST", f"tasks/alpha/{tid}/answer", {"text": "go on"}, "task.answer"),
        ("POST", f"tasks/alpha/{tid}/cancel", None, "task.cancel"),
        ("DELETE", "partners/p1", None, "partner.remove"),
    ]
    for method, path, body, action in calls:
        kw = {"json": body} if body is not None else {}
        r = await hc.request(method, f"{A}/{path}", headers=ADMIN_POST, **kw)
        assert r.status_code in (200, 409), (path, r.text)
        if action is None:
            continue
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": action})
        assert OPS in [row["actor"] for row in rows], (path, rows)
    # Answer and cancel name the task.
    for action in ("task.answer", "task.cancel"):
        rows, _ = await host.audit.query({"action": action})
        assert {(r["agent_id"], r["task_id"]) for r in rows} == {("alpha", tid)}
    json.dumps(rows)
