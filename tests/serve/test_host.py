"""AgentHost end to end: routing, auth, limits and restart recovery."""

from __future__ import annotations

import asyncio
import hashlib
import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import (
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    TaskState,
)
from a2a.utils.errors import InvalidParamsError, TaskNotFoundError

from a2agw.core.events import Done
from a2agw.security.auth import AgentAccess, ApiKeyEntry, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Blocker:
    durable_sessions = False

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def run(self, ctx):
        self.started.set()
        await asyncio.Event().wait()
        yield Done(text="never")


def spec(agent_id: str, adapter=None, **kw) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test agent",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter or Echo(),
        **kw,
    )


def msg(text: str = "hi", parts: int = 1) -> Message:
    return Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text=text) for _ in range(parts)],
    )


def key_auth(**keys: str) -> AuthConfig:
    return AuthConfig(
        api_keys={
            hashlib.sha256(secret.encode()).hexdigest(): ApiKeyEntry(principal_id=pid)
            for pid, secret in keys.items()
        }
    )


class Env:
    def __init__(self, tmp_path, **host_kwargs) -> None:
        self.host = AgentHost(
            "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'host.db'}", **host_kwargs
        )
        self._clients: list[httpx.AsyncClient] = []

    async def start(self) -> None:
        await self.host.startup()

    def http(self, *, root_path: str = "", **headers: str) -> httpx.AsyncClient:
        hc = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.host.app(), root_path=root_path),
            base_url="http://t",
            headers=headers,
        )
        self._clients.append(hc)
        return hc

    def client(self, agent_id: str, *, streaming: bool = False, **headers: str):
        hc = self.http(**headers)
        card = self.host.cards[agent_id]
        return ClientFactory(ClientConfig(httpx_client=hc, streaming=streaming)).create(card)

    async def stop(self) -> None:
        for hc in self._clients:
            await hc.aclose()
        await self.host.shutdown()


@pytest.fixture
async def env(tmp_path):
    made: list[Env] = []

    async def _make(*specs: AgentSpec, **host_kwargs) -> Env:
        e = Env(tmp_path, **host_kwargs)
        for s in specs:
            e.host.add(s)
        await e.start()
        made.append(e)
        return e

    yield _make
    for e in made:
        await e.stop()


async def send_one(client, message: Message, **config):
    req = SendMessageRequest(message=message)
    if config:
        req.configuration.CopyFrom(SendMessageConfiguration(**config))
    return [ev async for ev in client.send_message(req)]


def task_id_of(events) -> str:
    return events[0].task.id


async def test_two_agents_isolated_cards_and_rpc(env):
    e = await env(spec("alpha"), spec("beta"))
    hc = e.http()
    for aid in ("alpha", "beta"):
        r = await hc.get(f"/agents/{aid}/.well-known/agent-card.json")
        assert r.status_code == 200 and r.json()["name"] == aid.title()
    events = await send_one(e.client("alpha"), msg("yo"))
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert events[0].task.artifacts[0].parts[0].text == "echo: yo"
    assert (await hc.get("/.well-known/agent-card.json")).status_code == 404
    assert (await hc.post("/agents/nope/", json={})).status_code == 404


async def test_duplicate_and_late_add_rejected(env):
    e = await env(spec("alpha"))
    with pytest.raises(ValueError):
        e.host.add(spec("alpha"))
    e.host.app()
    with pytest.raises(RuntimeError):
        e.host.add(spec("beta"))


async def test_single_agent_root_card(env):
    e = await env(spec("solo"))
    r = await e.http().get("/.well-known/agent-card.json")
    assert r.status_code == 200 and r.json()["name"] == "Solo"


async def test_task_from_agent_a_not_visible_via_agent_b(env):
    e = await env(spec("alpha"), spec("beta"))
    tid = task_id_of(await send_one(e.client("alpha"), msg()))
    with pytest.raises(TaskNotFoundError):
        await e.client("beta").get_task(GetTaskRequest(id=tid))
    assert (await e.client("alpha").get_task(GetTaskRequest(id=tid))).id == tid


async def test_other_principal_cannot_get_task(env):
    e = await env(spec("alpha"), auth=key_auth(a="secret-a", b="secret-b"))
    tid = task_id_of(await send_one(e.client("alpha", **{"X-API-Key": "secret-a"}), msg()))
    got = await e.client("alpha", **{"X-API-Key": "secret-a"}).get_task(GetTaskRequest(id=tid))
    assert got.id == tid
    with pytest.raises(TaskNotFoundError):
        await e.client("alpha", **{"X-API-Key": "secret-b"}).get_task(GetTaskRequest(id=tid))


async def test_unauthenticated_401_and_public_paths(env):
    e = await env(spec("alpha"), auth=key_auth(a="secret-a"))
    hc = e.http()
    assert (await hc.post("/agents/alpha/", json={})).status_code == 401
    assert (await hc.get("/agents/alpha/.well-known/agent-card.json")).status_code == 200
    assert (await hc.get("/.well-known/agent-card.json")).status_code == 200


async def test_forbidden_principal_403(env):
    e = await env(
        spec("alpha", access=AgentAccess(allowed_principals=frozenset({"key:a"}))),
        auth=key_auth(a="secret-a", b="secret-b"),
    )
    r = await e.http(**{"X-API-Key": "secret-b"}).post("/agents/alpha/", json={})
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    events = await send_one(e.client("alpha", **{"X-API-Key": "secret-a"}), msg())
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    # An unknown agent is 404 even when authenticated.
    r = await e.http(**{"X-API-Key": "secret-a"}).post("/agents/zzz/", json={})
    assert r.status_code == 404 and r.json() == {"error": "not found"}


async def test_body_too_large_413(env):
    e = await env(spec("alpha"), max_body_bytes=1000)
    hc = e.http()
    r = await hc.post("/agents/alpha/", content=b"x" * 2000)
    assert r.status_code == 413 and r.json() == {"error": "payload too large"}

    async def chunks():
        for _ in range(4):
            yield b"x" * 500

    r = await hc.post("/agents/alpha/", content=chunks())  # no Content-Length
    assert r.status_code == 413 and r.json() == {"error": "payload too large"}


@pytest.mark.parametrize("streaming", [False, True])
async def test_too_many_parts_invalid_params(env, streaming):
    e = await env(spec("alpha"), max_parts=3)
    client = e.client("alpha", streaming=streaming)
    with pytest.raises(InvalidParamsError, match="too many parts"):
        await send_one(client, msg(parts=4))
    events = await send_one(client, msg(parts=3))
    assert events


async def test_restart_recovers(tmp_path):
    blocker = Blocker()
    e1 = Env(tmp_path)
    e1.host.add(spec("alpha", blocker))
    await e1.start()
    events = await send_one(e1.client("alpha"), msg(), return_immediately=True)
    tid = task_id_of(events)
    await asyncio.wait_for(blocker.started.wait(), 5)
    working = TaskState.Name(TaskState.TASK_STATE_WORKING)
    rows, _ = await e1.host.index.list(agent_id="alpha")
    assert [(r["task_id"], r["state"]) for r in rows] == [(tid, working)]
    await e1.stop()

    e2 = Env(tmp_path)
    e2.host.add(spec("alpha"))
    await e2.start()
    try:
        assert e2.host.last_recovery.failed == [tid]
        # Same principal as the original (anonymous, no auth configured).
        got = await e2.client("alpha").get_task(GetTaskRequest(id=tid))
        assert got.status.state == TaskState.TASK_STATE_FAILED
        rows, _ = await e2.host.index.list(agent_id="alpha")
        assert rows[0]["state"] == TaskState.Name(TaskState.TASK_STATE_FAILED)
    finally:
        await e2.stop()


def _restricted(**kw):
    return dict(
        specs=(spec("alpha", access=AgentAccess(allowed_principals=frozenset({"key:a"}))),),
        auth=key_auth(a="secret-a", b="secret-b"),
        **kw,
    )


async def test_root_path_does_not_bypass_authz(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    bad = e.http(root_path="/api", **{"X-API-Key": "secret-b"})
    assert (await bad.post("/api/agents/alpha/", json={})).status_code == 403
    assert (await bad.get("/api/agents/alpha/rest/tasks")).status_code == 403
    good = e.http(root_path="/api", **{"X-API-Key": "secret-a"})
    assert (
        await good.get("/api/agents/alpha/rest/tasks", headers={"A2A-Version": "1.0"})
    ).status_code == 200
    # The card stays public under a root_path too.
    anon = e.http(root_path="/api")
    assert (await anon.get("/api/agents/alpha/.well-known/agent-card.json")).status_code == 200


async def test_rest_binding_forbidden(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    r = await e.http(**{"X-API-Key": "secret-b"}).get("/agents/alpha/rest/tasks")
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}


async def test_healthz_path_exempt_from_auth(tmp_path):
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def health(request):
        return PlainTextResponse("ok")

    e = Env(tmp_path, auth=key_auth(a="secret-a"))
    e.host.add(spec("alpha"))
    e.host.extra_routes.append(Route("/a2agw/admin/healthz", health))
    e.host.extra_routes.append(Route("/a2agw/admin/other", health))
    await e.start()
    try:
        hc = e.http()
        assert (await hc.get("/a2agw/admin/healthz")).text == "ok"
        assert (await hc.get("/a2agw/admin/other")).status_code == 401
    finally:
        await e.stop()


async def test_post_to_card_path_not_exempt(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    hc = e.http()
    for path in ("/agents/alpha/.well-known/agent-card.json", "/.well-known/agent-card.json"):
        assert (await hc.post(path, json={})).status_code in (401, 404, 405)


async def test_unknown_agent_404_json(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    r = await e.http(**{"X-API-Key": "secret-a"}).post("/agents/zzz/", json={})
    assert r.status_code == 404 and r.json() == {"error": "not found"}


async def test_lying_content_length_413(env):
    e = await env(spec("alpha"), max_body_bytes=1000)

    async def chunks():
        for _ in range(4):
            yield b"x" * 500

    r = await e.http().post("/agents/alpha/", content=chunks(), headers={"Content-Length": "10"})
    assert r.status_code == 413


async def test_add_after_startup_rejected(env):
    e = await env(spec("alpha"))
    with pytest.raises(RuntimeError):
        e.host.add(spec("beta"))


async def test_app_is_cached(env):
    e = await env(spec("alpha"))
    assert e.host.app() is e.host.app()


# -- REST binding conformance (A2A spec 1.0 sections 5.4 and 11.1) -------------------------

REST_HEADERS = {"A2A-Version": "1.0"}


async def _rest_send(hc: httpx.AsyncClient, agent_id: str = "alpha") -> httpx.Response:
    body = {
        "message": {
            "messageId": uuid.uuid4().hex,
            "role": "ROLE_USER",
            "parts": [{"text": "hi"}],
        }
    }
    return await hc.post(f"/agents/{agent_id}/rest/message:send", json=body, headers=REST_HEADERS)


async def test_rest_responses_use_application_json(env):
    e = await env(spec("alpha"))
    r = await _rest_send(e.http())
    assert r.status_code == 200
    assert r.headers["content-type"].split(";")[0] == "application/json"
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_COMPLETED"


async def test_rest_cancel_of_terminal_task_is_409(env):
    e = await env(spec("alpha"))
    hc = e.http()
    tid = (await _rest_send(hc)).json()["task"]["id"]
    r = await hc.post(f"/agents/alpha/rest/tasks/{tid}:cancel", headers=REST_HEADERS)
    assert r.status_code == 409
    assert r.headers["content-type"].split(";")[0] == "application/json"
    err = r.json()["error"]
    assert err["code"] == 409
    assert any(d.get("reason") == "TASK_NOT_CANCELABLE" for d in err["details"])
    assert int(r.headers["content-length"]) == len(r.content)


async def test_rest_other_errors_keep_their_status(env):
    e = await env(spec("alpha"))
    r = await e.http().get("/agents/alpha/rest/tasks/nope", headers=REST_HEADERS)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == 404


async def test_rest_cancel_via_sdk_client_maps_to_not_cancelable(env):
    from a2a.client import ClientConfig as _Config
    from a2a.types import CancelTaskRequest
    from a2a.utils.errors import TaskNotCancelableError

    e = await env(spec("alpha"))
    card = e.host.cards["alpha"]
    client = ClientFactory(
        _Config(httpx_client=e.http(), streaming=False, supported_protocol_bindings=["HTTP+JSON"])
    ).create(card)
    events = await send_one(client, msg())
    with pytest.raises(TaskNotCancelableError):
        await client.cancel_task(CancelTaskRequest(id=task_id_of(events)))


async def test_jsonrpc_errors_unchanged(env):
    e = await env(spec("alpha"))
    hc = e.http()
    tid = (await _rest_send(hc)).json()["task"]["id"]
    body = {"jsonrpc": "2.0", "id": 1, "method": "CancelTask", "params": {"id": tid}}
    r = await hc.post("/agents/alpha/", json=body, headers=REST_HEADERS)
    assert r.status_code == 200
    assert r.json()["error"]["code"] == -32002


async def test_rest_conformance_passes_large_error_bodies_through():
    from starlette.responses import Response

    from a2agw.serve.host import _RestConformance

    big = b'{"error": {"code": 400, "details": [{"reason": "TASK_NOT_CANCELABLE"}]}' + b" " * 70000
    big += b"}"
    app = _RestConformance(Response(big, status_code=400, media_type="application/a2a+json"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as hc:
        r = await hc.get("/")
    assert r.status_code == 400 and r.content == big
    assert r.headers["content-type"].startswith("application/json")


async def test_rest_conformance_leaves_non_json_errors_alone():
    from starlette.responses import PlainTextResponse

    from a2agw.serve.host import _RestConformance

    app = _RestConformance(PlainTextResponse("nope", status_code=400))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as hc:
        r = await hc.get("/")
    assert r.status_code == 400 and r.text == "nope"


async def test_card_cache_control_default_and_override(env):
    e = await env(spec("alpha"))
    hc = e.http()
    for path in ("/.well-known/agent-card.json", "/agents/alpha/.well-known/agent-card.json"):
        r = await hc.get(path)
        assert r.headers["cache-control"] == "public, max-age=300"
    e2 = await env(spec("beta"), card_cache_control=None)
    r = await e2.http().get("/agents/beta/.well-known/agent-card.json")
    assert "cache-control" not in r.headers


async def test_partners_path_accepts_str(tmp_path):
    path = tmp_path / "partners.yaml"
    path.write_text("partners: []\n")
    host = AgentHost(
        "http://t", partners_path=str(path), db_url=f"sqlite+aiosqlite:///{tmp_path}/a.db"
    )
    host.partners.load()  # raised AttributeError when the str was passed through
    assert host.partners.all() == []


def test_run_binds_localhost_by_default(monkeypatch):
    """Finding 3: AgentHost.run() must not expose the host on every interface by default."""
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    host = AgentHost("http://localhost:8000")
    host.run()
    host.run(host="0.0.0.0", port=9000)
    assert calls == [
        {"host": "127.0.0.1", "port": 8000},
        {"host": "0.0.0.0", "port": 9000},
    ]


async def test_startup_failure_disposes_engine(tmp_path, monkeypatch):
    """Finding 11: a bad partners file must not leak the engine opened before it."""
    from sqlalchemy.ext.asyncio import AsyncEngine

    bad = tmp_path / "partners.yaml"
    bad.write_text("not: a partner list\n")
    disposed: list[AsyncEngine] = []
    real_dispose = AsyncEngine.dispose

    async def dispose(self, *args, **kwargs):
        disposed.append(self)
        return await real_dispose(self, *args, **kwargs)

    monkeypatch.setattr(AsyncEngine, "dispose", dispose)
    host = AgentHost(
        "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", partners_path=bad
    )
    host.add(spec("alpha"))
    with pytest.raises(ValueError, match="partners"):
        await host.startup()
    assert len(disposed) == 1
    assert host.engine is None and host.client is None
