"""Phase 4a "done when": a control plane and two gateways in process, every Console
operation through ``/api/v1`` with role checks.

The control plane (``cp.example``) runs through its lifespan with sign-in through the fake
OIDC provider; ``gw-east`` and ``gw-west`` are real ``AgentHost`` gateways whose connectors
reach it over the test network. ``gw-east`` hosts ``planner`` (consults ``p``) and
``legacy``; ``gw-west`` hosts ``p`` (the partner every gateway is assigned), ``asker``
(asks a question) and ``legacy``. A call from ``gw-east`` to ``p`` is a real A2A call to
``gw-west``, so its trace spans both gateways.

``Net`` is the network: hosts served by ASGI apps (really streaming), anything else through
an ordinary transport that respx answers (the fake identity provider). A host can be taken
down (its open requests end, new ones are refused) and brought back with another app (the
control plane restarted on its database). Every response body that crosses it is recorded,
so ``test_no_secret_reaches_any_response_log_or_audit`` can scan them.

Clocks: gateway events and audit rows carry wall-clock timestamps (the bus and the audit
log stamp them), so every service reads the real clock; nothing in the test sleeps on it.
The services' own pacing sleeps (stream polls, report intervals, back-offs) are injected
and scaled down, and the test waits with bounded ``until`` polls.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import itertools
import json
import logging
import sys
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

pytest.importorskip("fastapi")

sys.path.insert(0, str(Path(__file__).parents[1] / "control"))  # oidc_fake

from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageConfiguration, SendMessageRequest, TaskState
from google.protobuf.json_format import MessageToDict
from oidc_fake import CLIENT_SECRET, CLIENT_SECRET_ENV, COOKIE, FakeIdP, login, oidc_settings
from sqlalchemy import func, select, text
from starlette.responses import JSONResponse
from streaming_asgi import StreamingASGITransport

from a2agw.config import ControlPlaneConfig
from a2agw.consult import client as client_mod
from a2agw.consult import netguard
from a2agw.consult.registry import _normalize, card_hash
from a2agw.control.store import GATEWAY_AUDIT, token_digest
from a2agw.core.events import Done, NeedInput
from a2agw.ops.cp_client import LOCKDOWN_RULE_ID, ControlPlaneConnector
from a2agw.security.policy import policy_hash
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

CP_HOST = "cp.example"
CP = f"https://{CP_HOST}"
EAST_HOST = "gw-east.example.com"
WEST_HOST = "gw-west.example.com"
PUBLIC_IP = "93.184.216.34"
P_CARD_PATH = "/agents/p/.well-known/agent-card.json"

OPEN_POLICY = {
    "version": 1,
    "authz": [{"id": "anon", "principal": "anonymous", "agents": "*", "effect": "allow"}],
}
# Stricter: `legacy` is closed to everyone (a deny wins over the allow).
STRICT_POLICY = {
    "version": 1,
    "authz": [
        {"id": "anon", "principal": "anonymous", "agents": "*", "effect": "allow"},
        {"id": "no-legacy", "principal": "*", "agents": ["legacy"], "effect": "deny"},
    ],
}
COMPLETED = TaskState.Name(TaskState.TASK_STATE_COMPLETED)
CANCELED = TaskState.Name(TaskState.TASK_STATE_CANCELED)
WORKING = TaskState.Name(TaskState.TASK_STATE_WORKING)
INPUT_REQUIRED = TaskState.Name(TaskState.TASK_STATE_INPUT_REQUIRED)


async def until(pred: Callable[[], Any], timeout: float = 30.0, what: str = "") -> None:
    """Poll ``pred`` (sync or async) until it is true, for at most ``timeout`` seconds."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        value = pred()
        if asyncio.iscoroutine(value):
            value = await value
        if value:
            return
        assert loop.time() < deadline, f"condition not reached: {what or pred}"
        await asyncio.sleep(0.01)


def scaled(factor: float) -> Callable[[float], Any]:
    """A service's pacing sleep, ``factor`` times shorter (its clock stays the real one)."""

    async def sleep(seconds: float) -> None:
        await asyncio.sleep(max(0.001, seconds * factor))

    return sleep


# -- the network ---------------------------------------------------------------------------


@dataclass
class Exchange:
    method: str
    host: str
    path: str
    status: int
    chunks: list[bytes] = field(default_factory=list)

    @property
    def body(self) -> bytes:
        return b"".join(self.chunks)


class _Tee(httpx.AsyncByteStream):
    def __init__(self, inner: Any, sink: list[bytes]) -> None:
        self.inner = inner
        self.sink = sink

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self.inner:
            self.sink.append(chunk)
            yield chunk

    async def aclose(self) -> None:
        await self.inner.aclose()


class Net(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.hosts: dict[str, StreamingASGITransport | None] = {}
        self.other = httpx.AsyncHTTPTransport()  # respx answers (the identity provider)
        self.exchanges: list[Exchange] = []
        self.clients: list[httpx.AsyncClient] = []

    def up(self, host: str, app: Any) -> None:
        self.hosts[host] = StreamingASGITransport({host: app})

    async def down(self, host: str) -> None:
        """Like a server going away: its open requests end, new ones are refused."""
        transport = self.hosts.get(host)
        self.hosts[host] = None
        if transport is not None:
            await transport.stop_serving()

    def client(self, base_url: str = "", **headers: str) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=self, base_url=base_url, headers=headers)
        self.clients.append(c)
        return c

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.hosts:
            transport = self.hosts[host]
            if transport is None:
                raise httpx.ConnectError(f"{host} unreachable", request=request)
            response = await transport.handle_async_request(request)
        else:
            response = await self.other.handle_async_request(request)
        ex = Exchange(request.method, host, request.url.path, response.status_code)
        self.exchanges.append(ex)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_Tee(response.stream, ex.chunks),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:  # shared by every client: closed once, by shutdown()
        pass

    async def shutdown(self) -> None:
        for host in list(self.hosts):
            await self.down(host)
        for c in self.clients:
            await c.aclose()
        await self.other.aclose()


# -- agents --------------------------------------------------------------------------------


class Fn:
    durable_sessions = False

    def __init__(self, fn: Callable[[Any], Any]) -> None:
        self.fn = fn

    def run(self, ctx: Any) -> Any:
        return self.fn(ctx)


def spec(agent_id: str, fn: Callable[[Any], Any]) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description=f"{agent_id} agent",
        skills=[SkillSpec(id=f"{agent_id}-skill", name="S", description="d")],
        adapter=Fn(fn),
    )


async def echo(ctx: Any) -> AsyncIterator[Any]:
    yield Done(text=f"echo: {ctx.text}")


async def asker(ctx: Any) -> AsyncIterator[Any]:
    if not ctx.resumed:
        yield NeedInput(question="which colour?")
        return
    yield Done(text=f"painting it {ctx.text}")


async def partner_p(ctx: Any) -> AsyncIterator[Any]:
    if ctx.text == "block":
        await asyncio.Event().wait()  # until cancelled
    yield Done(text=f"p says: {ctx.text}")


class CardSwitch:
    """The partner's card, changeable: while ``card`` is set, it is served instead."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.card: dict[str, Any] | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if self.card is not None and scope["type"] == "http" and scope["path"] == P_CARD_PATH:
            await JSONResponse(self.card)(scope, receive, send)
            return
        await self.app(scope, receive, send)


@dataclass
class Gateway:
    name: str
    id: str
    host: AgentHost
    conn: ControlPlaneConnector
    a2a: httpx.AsyncClient  # callers of its agents

    def client(self, agent_id: str) -> Any:
        card = self.host.cards[agent_id]
        return ClientFactory(ClientConfig(httpx_client=self.a2a, streaming=False)).create(card)

    async def send(self, agent_id: str, text: str, **config: Any) -> Any:
        message = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])
        req = SendMessageRequest(message=message)
        if config:
            req.configuration.CopyFrom(SendMessageConfiguration(**config))
        events = [ev async for ev in self.client(agent_id).send_message(req)]
        return events[-1].task

    async def raw_send(self, agent_id: str) -> httpx.Response:
        """A JSON-RPC send as raw HTTP (to see a policy refusal's status)."""
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "messageId": uuid.uuid4().hex,
                    "role": "ROLE_USER",
                    "parts": [{"text": "hi"}],
                }
            },
        }
        return await self.a2a.post(
            f"/agents/{agent_id}/", json=body, headers={"A2A-Version": "1.0"}
        )

    async def healthz(self) -> dict[str, Any]:
        return (await self.a2a.get("/a2agw/admin/healthz")).json()

    async def audit_max_seq(self) -> int:
        assert self.host.audit is not None and self.host.engine is not None
        await self.host.audit.drain()
        t = self.host.audit.table
        async with self.host.engine.connect() as c:
            return int((await c.execute(select(func.max(t.c.seq)))).scalar() or 0)


# -- the world -----------------------------------------------------------------------------


@dataclass
class World:
    net: Net
    tmp: Path
    idp: FakeIdP
    monkeypatch: Any
    stack: contextlib.AsyncExitStack
    cp_stack: contextlib.AsyncExitStack | None = None
    app: Any = None
    gateways: dict[str, Gateway] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)  # name -> secret, for the scan
    # one-time creation responses: (exchange index, the secret it shows)
    creations: list[tuple[int, str]] = field(default_factory=list)
    card_switch: CardSwitch | None = None

    def settings(self) -> Any:
        return oidc_settings(
            f"sqlite+aiosqlite:///{self.tmp / 'cp.db'}",
            limits={"stream_keepalive_s": 15.0},
        )

    async def start_cp(self) -> Any:
        from a2agw.control.app import create_app

        http = self.net.client()  # outbound: partner cards (gw-west) and the IdP (respx)
        app = create_app(
            self.settings(),
            http=http,
            clock=time.time,
            sleep=scaled(0.1),
            maintenance_interval_s=3600,
        )
        stack = contextlib.AsyncExitStack()
        await stack.enter_async_context(app.router.lifespan_context(app))
        self.net.up(CP_HOST, app)
        self.app, self.cp_stack = app, stack
        return app

    async def stop_cp(self) -> None:
        await self.net.down(CP_HOST)  # its open requests end before the app does
        assert self.cp_stack is not None
        stack, self.cp_stack = self.cp_stack, None
        await stack.aclose()

    async def start_gateway(
        self, name: str, gateway_id: str, token: str, host_name: str, specs: list[AgentSpec]
    ) -> Gateway:
        env = f"A2AGW_TEST_CP_TOKEN_{name.upper().replace('-', '_')}"
        self.monkeypatch.setenv(env, token)
        host = AgentHost(
            f"https://{host_name}",
            db_url=f"sqlite+aiosqlite:///{self.tmp / f'{name}.db'}",
            partner_http=self.net.client(),
        )
        for s in specs:
            host.add(s)
        conn = ControlPlaneConnector(
            host,
            ControlPlaneConfig(url=CP, token_env=env, health_interval_s=0.5),
            http=self.net.client(),
            sleep=scaled(0.05),
        )
        app: Any = host.app()
        if name == "gw-west":
            app = self.card_switch = CardSwitch(app)
        self.net.up(host_name, app)
        await host.startup()
        gw = Gateway(name, gateway_id, host, conn, self.net.client(f"https://{host_name}"))
        self.gateways[name] = gw
        return gw

    async def shutdown(self) -> None:
        for gw in self.gateways.values():  # stop serving first: running requests end
            await self.net.down(gw.host.base_url.removeprefix("https://"))
        for gw in self.gateways.values():
            await gw.host.shutdown()
        if self.cp_stack is not None:
            await self.stop_cp()
        await self.net.shutdown()


@pytest.fixture
async def world(tmp_path, monkeypatch, spans) -> AsyncIterator[World]:
    """The control plane's and the gateways' world. ``spans``: an OTel tracer provider
    is installed, so turns have trace ids (as a deployment exporting traces does)."""

    async def resolve(_host: str) -> list[str]:
        return [PUBLIC_IP]

    monkeypatch.delenv("A2AGW_DEV", raising=False)
    monkeypatch.setattr(netguard, "_resolve", resolve)
    monkeypatch.setenv(CLIENT_SECRET_ENV, CLIENT_SECRET)
    # partner tasks that outlive a consult's wait are polled quickly
    monkeypatch.setattr(client_mod, "POLL_MIN_S", 0.02)
    monkeypatch.setattr(client_mod, "POLL_MAX_S", 0.05)
    idp = FakeIdP(clock=time.time, sub="sam", groups=["cp-security"], name="Sam", email="s@x")
    with respx.mock(assert_all_called=False) as rx:
        idp.routes = idp.install(rx)  # type: ignore[attr-defined]
        async with contextlib.AsyncExitStack() as stack:
            w = World(Net(), tmp_path, idp, monkeypatch, stack)
            try:
                yield w
            finally:
                await w.shutdown()


def partner_ids(gw: Gateway) -> set[str]:
    return {r.id for r in gw.host.partners.all()}


def bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


def ok(r: httpx.Response, *codes: int) -> Any:
    assert r.status_code in (codes or (200,)), (r.status_code, r.text)
    return r.json()


async def finished(cp: httpx.AsyncClient, r: httpx.Response) -> dict[str, Any]:
    """The command of an operator action once it finished (the action may answer 202)."""
    cid = ok(r, 200, 202, 409)["command_id"]
    box: dict[str, Any] = {}

    async def done() -> bool:
        box.update(ok(await cp.get(f"/api/v1/commands/{cid}")))
        return box["status"] in ("done", "failed", "expired")

    await until(done, what=f"command {cid}")
    return box


# -- the scenario --------------------------------------------------------------------------


async def run_scenario(w: World) -> None:
    app = await w.start_cp()
    net = w.net

    # 1. An admin creates the gateways and an API key for each role; each gateway connects
    #    with its token. A security user signs in through the identity provider.
    _kid, bootstrap = await app.state.store.create_api_key("bootstrap", "admin", actor="cli")
    w.secrets["bootstrap key"] = bootstrap
    admin = net.client(CP, **bearer(bootstrap))

    async def versions() -> dict[str, int]:
        listed = ok(await admin.get("/api/v1/gateways"))["gateways"]
        return {g["id"]: g["version_desired"] for g in listed}  # before a change is made

    async def applied_beyond(before: dict[str, int]) -> bool:
        """Every gateway applied a desired state newer than ``before`` and is up to date."""
        listed = ok(await admin.get("/api/v1/gateways"))["gateways"]
        return len(listed) == 2 and all(
            g["version_applied"] == g["version_desired"] > before[g["id"]]
            and g["last_rejection"] is None
            for g in listed
        )

    tokens: dict[str, tuple[str, str]] = {}
    for name in ("gw-east", "gw-west"):
        created = ok(await admin.post("/api/v1/gateways", json={"name": name}), 201)
        tokens[name] = (created["id"], created["token"])
        w.secrets[f"{name} token"] = created["token"]
        w.creations.append((len(net.exchanges) - 1, created["token"]))
    keys: dict[str, str] = {}
    for role in ("viewer", "operator", "security"):
        created = ok(await admin.post("/api/v1/api-keys", json={"name": role, "role": role}), 201)
        keys[role] = created["key"]
        w.secrets[f"{role} key"] = created["key"]
        w.creations.append((len(net.exchanges) - 1, created["key"]))
    viewer = net.client(CP, **bearer(keys["viewer"]))
    operator = net.client(CP, **bearer(keys["operator"]))
    sec_key = net.client(CP, **bearer(keys["security"]))
    # nobody makes a key above their own permissions
    r = await operator.post("/api/v1/api-keys", json={"name": "x", "role": "admin"})
    assert r.status_code == 403
    # a key that is revoked stops working
    spare = ok(await admin.post("/api/v1/api-keys", json={"name": "spare", "role": "viewer"}), 201)
    w.secrets["revoked key"] = spare["key"]
    w.creations.append((len(net.exchanges) - 1, spare["key"]))
    ok(await admin.post(f"/api/v1/api-keys/{spare['id']}/revoke"))
    assert (await net.client(CP, **bearer(spare["key"])).get("/api/v1/overview")).status_code == 401
    listed = ok(await admin.get("/api/v1/api-keys"))["items"]
    assert {k["name"] for k in listed} == {"bootstrap", "viewer", "operator", "security", "spare"}
    assert all("key" not in k and "digest" not in k for k in listed)

    sec = net.client(CP)  # the signed-in security user (session cookie + CSRF header)
    r = await login(sec, w.idp)
    assert r.status_code == 302, r.text
    session_id = sec.cookies.get(COOKIE)
    assert session_id
    w.secrets["session id"] = session_id
    me = ok(await sec.get("/api/v1/me"))
    assert me["roles"] == ["security"] and me["id"] == "oidc:sam"
    sec.headers["x-a2agw-csrf"] = me["csrf_token"]
    users = ok(await admin.get("/api/v1/users"))["items"]
    assert [(u["id"], u["roles"], u["disabled"]) for u in users] == [
        ("oidc:sam", ["security"], False)
    ]
    assert (await viewer.get("/api/v1/users")).status_code == 403

    async def planner(ctx: Any) -> AsyncIterator[Any]:
        """Consults `p` on gw-west; "hold" leaves its partner task open and waits."""
        client = w.gateways["gw-east"].host.client
        assert client is not None
        if ctx.text == "hold":
            got = await client.consult("p", "block", wait_seconds=0.3)
            assert got.state == "working", got
            await asyncio.Event().wait()  # until the operator cancels
        got = await client.consult("p", ctx.text, wait_seconds=10)
        yield Done(text=f"planner: {got.text}")

    east_id, east_token = tokens["gw-east"]
    west_id, west_token = tokens["gw-west"]
    east = await w.start_gateway(
        "gw-east",
        east_id,
        east_token,
        EAST_HOST,
        [spec("planner", planner), spec("legacy", echo)],
    )
    west = await w.start_gateway(
        "gw-west",
        west_id,
        west_token,
        WEST_HOST,
        [spec("p", partner_p), spec("asker", asker), spec("legacy", echo)],
    )

    for gw in (east, west):
        await until(lambda gw=gw: gw.conn.status()["connected"], what=f"{gw.name} connects")
    # no policy assigned yet: a managed gateway is locked down
    for gw in (east, west):
        assert gw.host.policy is not None
        assert [r.id for r in gw.host.policy.policy.authz] == [LOCKDOWN_RULE_ID]
        assert (await gw.raw_send("legacy")).status_code == 403
    gateways = ok(await admin.get("/api/v1/gateways"))["gateways"]
    assert {g["name"] for g in gateways} == {"gw-east", "gw-west"}
    assert (await viewer.get("/api/v1/gateways")).status_code == 403

    # 2. Partner `p` is registered and shows as pending. A viewer cannot approve it; a
    #    security user approves it, pinned to the card's hash. (Registering is
    #    `partners.register`, an admin permission: security reviews and trusts.)
    p_body = {"id": "p", "tier": "partner", "card_url": f"https://{WEST_HOST}/agents/p"}
    assert (await sec.post("/api/v1/partners", json=p_body)).status_code == 403
    p = ok(await admin.post("/api/v1/partners", json=p_body), 201)
    v1 = p["versions"][0]
    pending = ok(await sec.get("/api/v1/partners", params={"status": "pending"}))["partners"]
    assert [(x["id"], x["status"]) for x in pending] == [("p", "pending")]
    assert ok(await sec.get("/api/v1/partners"))["partners"] == []  # approved only
    approve = {"version": 1, "expected_hash": v1["card_hash"]}
    assert (await viewer.post("/api/v1/partners/p/approve", json=approve)).status_code == 403
    no_csrf = net.client(CP)
    no_csrf.cookies.set(COOKIE, session_id, domain=CP_HOST)
    r = await no_csrf.post("/api/v1/partners/p/approve", json=approve)
    assert r.status_code == 403 and r.json()["error"] == "csrf"
    stale = {"version": 1, "expected_hash": "0" * 64}
    assert (await sec.post("/api/v1/partners/p/approve", json=stale)).status_code == 409
    assert ok(await sec.post("/api/v1/partners/p/approve", json=approve))["status"] == "approved"

    # 3. An admin assigns `p` and a policy to both gateways; both apply them (the applied
    #    version shows in the gateway list).
    before = await versions()
    open_policy = ok(
        await sec.post("/api/v1/policies", json={"name": "open", "doc": OPEN_POLICY}), 201
    )
    for gw in (east, west):
        ok(await admin.put(f"/api/v1/gateways/{gw.id}/partners", json={"partner_ids": ["p"]}))
        assign = {"policy_id": open_policy["id"], "version": None}
        ok(await admin.put(f"/api/v1/gateways/{gw.id}/policy", json=assign))
    assert (
        await viewer.put(f"/api/v1/gateways/{east.id}/partners", json={"partner_ids": []})
    ).status_code == 403

    await until(lambda: applied_beyond(before), what="both gateways applied p and the policy")
    # each gateway's effective limits are shown read-only (they stay in its config file)
    for g in ok(await admin.get("/api/v1/gateways"))["gateways"]:
        assert g["info"]["limits"]["max_consults_per_task"] == 16
    for gw in (east, west):
        assert sorted(r.id for r in gw.host.partners.all()) == ["p"]
        assert gw.host.partners.get("p").card_hash == v1["card_hash"]
        assert [r.id for r in gw.host.policy.policy.authz] == ["anon"]  # type: ignore[union-attr]
    # traffic under the open policy: `legacy` is open on both gateways
    for gw in (east, west):
        assert (await gw.send("legacy", "hello")).status.state == TaskState.TASK_STATE_COMPLETED

    async def legacy_admits_reported() -> bool:
        rows = ok(
            await sec.get("/api/v1/audit", params={"action": "inbound.admit", "agent": "legacy"})
        )["items"]
        return {r["gateway_id"] for r in rows} == {east.id, west.id}

    await until(legacy_admits_reported, what="the gateways' audit rows reach the control plane")

    # 4. A dry-run of a stricter policy lists the calls it would block; saved and assigned,
    #    it changes behaviour on both gateways.
    assert (
        await operator.post("/api/v1/policies/dry-run", json={"doc": STRICT_POLICY})
    ).status_code == 403
    dry = ok(await sec.post("/api/v1/policies/dry-run", json={"doc": STRICT_POLICY}))
    blocked = dry["newly_blocked"]
    assert blocked and {(b["gateway_id"], b["agent_id"]) for b in blocked} == {
        (east.id, "legacy"),
        (west.id, "legacy"),
    }
    assert {b["actor_kind"] for b in blocked} == {"anonymous"}
    assert {b["rule"] for b in blocked} == {"no-legacy"}
    assert dry["newly_allowed"] == [] and "egress content checks" in dry["not_replayable"]
    strict = ok(
        await sec.post("/api/v1/policies", json={"name": "strict", "doc": STRICT_POLICY}), 201
    )
    strict_hash = strict["versions"][0]["doc_hash"]
    before = await versions()
    for gw in (east, west):
        assign = {"policy_id": strict["id"], "version": 1}
        ok(await admin.put(f"/api/v1/gateways/{gw.id}/policy", json=assign))

    async def strict_everywhere() -> bool:
        return all(
            gw.host.policy is not None
            and [r.id for r in gw.host.policy.policy.authz] == ["anon", "no-legacy"]
            for gw in (east, west)
        ) and await applied_beyond(before)

    await until(strict_everywhere, what="both gateways apply the strict policy")
    for gw in (east, west):
        assert (await gw.raw_send("legacy")).status_code == 403
    for gw in (east, west):
        assert gw.host.policy is not None
        assert policy_hash(gw.host.policy.policy) == strict_hash  # the version saved
    [listed_strict] = [
        x for x in ok(await viewer.get("/api/v1/policies"))["policies"] if x["id"] == strict["id"]
    ]
    assert {g["gateway_id"] for g in listed_strict["gateways"]} == {east.id, west.id}

    # 5. Agents on gw-east call `p` (on gw-west). The overview, the tasks, the topology and
    #    the task's timeline across both gateways all show it.
    task = await east.send("planner", "plan the trip")
    assert task.status.state == TaskState.TASK_STATE_COMPLETED, task
    assert [pt.text for a in task.artifacts for pt in a.parts] == ["planner: p says: plan the trip"]

    async def east_task() -> dict[str, Any] | None:
        items = ok(await viewer.get("/api/v1/tasks", params={"gateway_id": east.id}))["items"]
        return next((t for t in items if t["task_id"] == task.id), None)

    async def traced_both_ways() -> bool:
        mine = await east_task()
        if mine is None or mine["state"] != COMPLETED or not mine["trace_id"]:
            return False
        traced = ok(await viewer.get("/api/v1/tasks", params={"trace_id": mine["trace_id"]}))
        return {(t["gateway_id"], t["agent_id"], t["state"]) for t in traced["items"]} == {
            (east.id, "planner", COMPLETED),
            (west.id, "p", COMPLETED),
        }

    # the task list finds the planner's task and, by its trace, p's task on gw-west
    await until(traced_both_ways, what="both gateways' tasks of one trace reach the control plane")
    mine = await east_task()
    assert mine is not None and mine["agent_id"] == "planner"

    async def calls_reported() -> bool:
        over = ok(await viewer.get("/api/v1/overview"))
        return any(x["partner_id"] == "p" and x["calls"] >= 1 for x in over["top_partners"])

    await until(calls_reported, what="the partner call reaches the control plane")
    over = ok(await viewer.get("/api/v1/overview"))
    assert over["gateways"] == {"total": 2, "connected": 2, "stale": 0}
    assert sum(b["count"] for b in over["tasks_per_min"]) >= 3  # legacy x2, planner, p
    topo = ok(await viewer.get("/api/v1/topology", params={"window_m": 60}))
    [edge] = [e for e in topo["edges"] if e["from"] == f"{east.id}/planner"]
    assert edge["to"] == "p" and edge["calls"] >= 1 and edge["policy"] == "allowed"
    agents = ok(await viewer.get("/api/v1/agents", params={"kind": "hosted"}))["items"]
    assert {(a["gateway_id"], a["id"]) for a in agents} == {
        (east.id, "planner"),
        (east.id, "legacy"),
        (west.id, "p"),
        (west.id, "asker"),
        (west.id, "legacy"),
    }
    detail = ok(await viewer.get(f"/api/v1/tasks/{east.id}/planner/{task.id}"))
    assert detail["task"]["state"] == COMPLETED and detail["task"]["owner_kind"] == "anonymous"
    assert "owner" not in detail["task"]
    assert [h["partner_id"] for h in detail["partner_tasks"]] == ["p"]
    timeline = detail["timeline"]
    assert {e["gateway_id"] for e in timeline} == {east.id, west.id}
    assert any(e["kind"] == "partner.call" and e["partner_id"] == "p" for e in timeline)
    assert any(
        e["gateway_id"] == west.id and e["agent_id"] == "p" and e["state"] == COMPLETED
        for e in timeline
    )

    # 6. The partner's card changes. gw-west quarantines it on refresh; the control plane
    #    shows the quarantine and the diff. Security approves the new card, and the command
    #    clears the quarantine on gw-west.
    assert w.card_switch is not None
    changed = MessageToDict(west.host.cards["p"])
    changed["description"] = "p now also books hotels"
    w.card_switch.card = changed
    r = await operator.post(f"/api/v1/partners/p/gateways/{west.id}/refresh")
    refreshed = await finished(operator, r)
    assert refreshed["status"] == "done", refreshed
    assert west.host.partners.get("p").status == "quarantined"
    local_pending = card_hash(west.host.partners.get("p").pending_card or {})

    async def quarantine_shown() -> bool:
        d = ok(await viewer.get("/api/v1/partners/p"))
        return any(
            g["gateway_id"] == west.id and g["status"] == "quarantined" for g in d["gateways"]
        )

    await until(quarantine_shown, what="the quarantine reaches the control plane")
    alerts = ok(await viewer.get("/api/v1/overview"))["alerts"]
    assert {
        "kind": "partner_quarantined",
        "gateway_id": west.id,
        "partner_id": "p",
    }.items() <= next(a for a in alerts if a["kind"] == "partner_quarantined").items()
    fetched = ok(await admin.post("/api/v1/partners/p/refresh"))
    assert fetched["outcome"] == "pending"
    v2 = fetched["pending_version"]
    assert v2["card_hash"] == local_pending
    assert "description" in json.dumps(fetched["diff"])
    assert east.host.partners.get("p").card_hash == v1["card_hash"]  # still the approved card
    approved = ok(
        await sec.post(
            "/api/v1/partners/p/approve", json={"version": 2, "expected_hash": v2["card_hash"]}
        )
    )
    [queued] = approved["commands"]
    assert queued["gateway_id"] == west.id
    cmd: dict[str, Any] = {}

    async def approve_done() -> bool:
        cmd.update(ok(await viewer.get(f"/api/v1/commands/{queued['command_id']}")))
        return cmd["status"] in ("done", "failed")

    await until(approve_done, what="partner.approve on gw-west")
    assert cmd["status"] == "done", cmd
    for gw in (east, west):
        await until(
            lambda gw=gw: gw.host.partners.get("p").card_hash == v2["card_hash"],
            what=f"{gw.name} has the new card",
        )
    rec = west.host.partners.get("p")
    assert rec.status == "active" and rec.pending_card is None
    # quarantine and reject, centrally: a second partner, given inline, leaves gw-west
    spare_card = _normalize(
        {
            "name": "Spare",
            "description": "spare does things",
            "version": "1.0",
            "supportedInterfaces": [
                {
                    "url": "https://spare.example.com/rpc",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }
            ],
            "capabilities": {},
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
        }
    )[0]
    registered = ok(
        await admin.post(
            "/api/v1/partners", json={"id": "spare", "tier": "partner", "card": spare_card}
        ),
        201,
    )
    spare_hash = registered["versions"][0]["card_hash"]
    ok(
        await sec.post(
            "/api/v1/partners/spare/approve", json={"version": 1, "expected_hash": spare_hash}
        )
    )
    ok(
        await admin.put(
            f"/api/v1/gateways/{west.id}/partners", json={"partner_ids": ["p", "spare"]}
        )
    )
    await until(lambda: "spare" in partner_ids(west), what="spare on gw-west")
    assert ok(await sec.post("/api/v1/partners/spare/quarantine"))["status"] == "quarantined"
    await until(lambda: "spare" not in partner_ids(west), what="spare leaves gw-west")
    assert ok(await sec.post("/api/v1/partners/spare/reject"))["status"] == "rejected"
    rejected = ok(await viewer.get("/api/v1/partners", params={"status": "rejected"}))["partners"]
    assert [x["id"] for x in rejected] == ["spare"]

    # 7. An operator cancels a running task on gw-east (its partner task on gw-west is
    #    cancelled too), then answers an input-required task on gw-west, which completes.
    held = await east.send("planner", "hold", return_immediately=True)

    async def holding() -> bool:
        assert east.host.handles is not None
        return bool(await east.host.handles.by_inbound(held.id))

    await until(holding, what="the planner's partner task is open")
    [handle] = await east.host.handles.by_inbound(held.id)
    p_task = handle["task_id"]
    assert (
        await viewer.post(f"/api/v1/tasks/{east.id}/planner/{held.id}/cancel")
    ).status_code == 403
    cancelled = await finished(
        operator, await operator.post(f"/api/v1/tasks/{east.id}/planner/{held.id}/cancel")
    )
    assert cancelled["status"] == "done" and cancelled["result"] == {"state": CANCELED}

    async def p_task_cancelled() -> bool:
        rows, _ = await west.host.index.list(agent_id="p")
        return [r["state"] for r in rows if r["task_id"] == p_task] == [CANCELED]

    await until(p_task_cancelled, what="the partner task on gw-west is cancelled")
    asked = await west.send("asker", "paint the fence")
    assert asked.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    answered = await finished(
        operator,
        await operator.post(
            f"/api/v1/tasks/{west.id}/asker/{asked.id}/answer", json={"text": "teal"}
        ),
    )
    assert answered["status"] == "done", answered

    async def asker_completed() -> bool:
        items = ok(await viewer.get("/api/v1/tasks", params={"agent_id": "asker"}))["items"]
        return [t["state"] for t in items if t["task_id"] == asked.id] == [COMPLETED]

    await until(asker_completed, what="the answered task completes")
    done_task = await west.client("asker").get_task(_get(asked.id))
    assert [pt.text for a in done_task.artifacts for pt in a.parts] == ["painting it teal"]

    # 8. The control plane stops. Both gateways keep serving with their applied state. It
    #    restarts on its database; they reconnect and resend the audit rows it never
    #    acknowledged.
    await w.stop_cp()
    for gw in (east, west):
        await until(lambda gw=gw: not gw.conn.status()["connected"], what=f"{gw.name} disconnects")
    offline = await east.send("planner", "while the control plane is away")
    assert offline.status.state == TaskState.TASK_STATE_COMPLETED
    for gw in (east, west):
        assert (await gw.raw_send("legacy")).status_code == 403  # still the strict policy
        assert gw.host.partners.get("p").card_hash == v2["card_hash"]
    unacked = {}
    for gw in (east, west):
        top = await gw.audit_max_seq()
        assert top > gw.conn._acked  # rows written while it was away
        unacked[gw.id] = top
    app = await w.start_cp()

    async def resent() -> bool:
        async with app.state.engine.connect() as c:
            got = dict(
                (
                    await c.execute(
                        select(GATEWAY_AUDIT.c.gateway_id, func.max(GATEWAY_AUDIT.c.seq)).group_by(
                            GATEWAY_AUDIT.c.gateway_id
                        )
                    )
                ).all()
            )
        return all(got.get(g, 0) >= seq for g, seq in unacked.items())

    for gw in (east, west):
        await until(lambda gw=gw: gw.conn.status()["connected"], what=f"{gw.name} reconnects")
    await until(resent, what="the unacknowledged audit rows are resent")
    async with app.state.engine.connect() as c:
        copies = (await c.execute(select(GATEWAY_AUDIT.c.gateway_id, GATEWAY_AUDIT.c.seq))).all()
    assert len(copies) == len(set(copies))  # stored once
    assert ok(await sec.get("/api/v1/me"))["id"] == "oidc:sam"  # the session survived

    # 9. A security user exports the audit log (JSONL and CSV): control-plane rows and both
    #    gateways' rows are there, and the chains verify.
    assert (await viewer.get("/api/v1/audit/export")).status_code == 403
    r = await sec.get("/api/v1/audit/export", params={"format": "jsonl"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in r.text.splitlines()]
    sources = {(x["source"], x["gateway_id"]) for x in rows}
    assert sources == {("control", None), ("gateway", east.id), ("gateway", west.id)}
    actions = {x["action"] for x in rows if x["source"] == "control"}
    assert {"cp.partner.register", "cp.partner.approve", "cp.assign", "cp.policy.save"} <= actions
    r = await sec_key.get("/api/v1/audit/export", params={"format": "csv"})  # a key too
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    table = list(csv.DictReader(io.StringIO(r.text)))
    assert {(x["source"], x["gateway_id"]) for x in table} == {
        ("control", ""),
        ("gateway", east.id),
        ("gateway", west.id),
    }
    assert ok(await sec.get("/api/v1/audit/verify")) == {"ok": True, "first_bad_seq": None}
    for gw in (east, west):
        assert gw.host.audit is not None
        assert await gw.host.audit.verify_chain() is None
        # the control plane holds the gateway's whole chain, unbroken
        chain = sorted((x for x in rows if x["gateway_id"] == gw.id), key=lambda x: x["seq"])
        assert [x["seq"] for x in chain] == list(range(1, len(chain) + 1))
        assert all(b["prev_hash"] == a["hash"] for a, b in itertools.pairwise(chain))

    # 10. An admin revokes gw-west's token. Its stream ends and it reports `unauthorized`;
    #     gw-east is unaffected. (Then the admin disables the security user.)
    assert (await sec.post(f"/api/v1/gateways/{west.id}/revoke")).status_code == 403
    ok(await admin.post(f"/api/v1/gateways/{west.id}/revoke"))
    await until(
        lambda: west.conn.status()["last_error_kind"] == "unauthorized", what="gw-west refused"
    )
    await until(lambda: west.conn.stopped, what="gw-west's connector stops")
    assert (await west.healthz())["control_plane"]["last_error_kind"] == "unauthorized"
    assert (
        await west.send("asker", "still serving")
    ).status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    last = await east.send("planner", "after the revocation")
    assert last.status.state == TaskState.TASK_STATE_COMPLETED

    async def east_still_reports() -> bool:
        items = ok(await viewer.get("/api/v1/tasks", params={"gateway_id": east.id}))["items"]
        return any(t["task_id"] == last.id and t["state"] == COMPLETED for t in items)

    await until(east_still_reports, what="gw-east keeps reporting")
    assert east.conn.status()["connected"] is True
    listed = {g["name"]: g for g in ok(await admin.get("/api/v1/gateways"))["gateways"]}
    assert listed["gw-west"]["status"] == "revoked" and listed["gw-east"]["status"] == "active"
    # and a user an admin disables is signed out at once
    ok(await admin.patch("/api/v1/users/oidc:sam", json={"disabled": True}))
    assert (await sec.get("/api/v1/me")).status_code == 401


def _get(task_id: str) -> Any:
    from a2a.types import GetTaskRequest

    return GetTaskRequest(id=task_id)


async def test_console_operations_across_two_gateways(world):
    await run_scenario(world)


# -- security pass -------------------------------------------------------------------------


async def test_no_secret_reaches_any_response_log_or_audit(world, caplog):
    """The scenario again, then a scan: every response body that crossed the network, every
    log record and every audit row (the control plane's own, the rows it copied and each
    gateway's) is free of every gateway token, API key, the session id and the OIDC client
    secret, and of their stored digests. The one-time creation responses show only the
    secret they create."""
    caplog.set_level(logging.DEBUG)
    w = world
    await run_scenario(w)
    secrets = {**w.secrets, "client secret": CLIENT_SECRET}
    # the ID and access tokens the control plane got from the provider (the authorization
    # code travels in the callback URL by design, and is single use)
    tokens = [t for t in w.idp.issued if not t.startswith("code-")]
    assert len(tokens) == 2
    secrets.update({f"idp token {i}": t for i, t in enumerate(tokens)})
    digests = {f"{k} digest": token_digest(v) for k, v in secrets.items()}
    needles = {**secrets, **digests}
    assert len(w.secrets) == 8  # 2 gateway tokens, 5 API keys, the session id

    allowed = dict(w.creations)
    leaks: list[str] = []
    for i, ex in enumerate(w.net.exchanges):
        if ex.host == "idp.example":  # the provider's own answers (it issues the tokens)
            continue
        body = ex.body.decode("utf-8", "replace")
        shown = allowed.get(i)
        if shown is not None:
            assert shown in body, (ex.method, ex.path)
            body = body.replace(shown, "")
        leaks += [
            f"{name} in {ex.method} {ex.host}{ex.path}" for name, s in needles.items() if s in body
        ]
    records = "\n".join(f"{r.getMessage()} {r.args!r} {r.exc_text or ''}" for r in caplog.records)
    leaks += [f"{name} in the log" for name, s in secrets.items() if s in records]

    async with w.app.state.engine.connect() as c:
        cp_rows = (await c.execute(text("SELECT * FROM cp_audit"))).all()
        copied = (await c.execute(select(GATEWAY_AUDIT))).all()
        events = (await c.execute(text("SELECT * FROM cp_events"))).all()
    stored = {"cp_audit": cp_rows, "cp_gateway_audit": copied, "cp_events": events}
    for gw in w.gateways.values():
        assert gw.host.engine is not None and gw.host.audit is not None
        async with gw.host.engine.connect() as c:
            stored[f"{gw.name} audit"] = (await c.execute(select(gw.host.audit.table))).all()
    assert all(stored.values())
    for where, found in stored.items():
        dump = json.dumps([[str(v) for v in r] for r in found])
        leaks += [f"{name} in {where}" for name, s in needles.items() if s in dump]
    assert leaks == []


# -- the walkthrough's configs (examples/control_plane) ------------------------------------

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "control_plane"


async def test_walkthrough_configs_load(monkeypatch):
    """The walkthrough's control.yaml and its two gateway configs load as they are: the
    gateways are managed (no local partners or policy), name their token only by its
    variable, and serve their agents."""
    from a2agw.config import build_host, load_config
    from a2agw.control.settings import load_control_settings

    monkeypatch.delenv("A2AGW_DEV", raising=False)
    settings = load_control_settings(EXAMPLE / "control.yaml", env={})
    assert settings.oidc is None and settings.base_url == "http://localhost:8100"
    monkeypatch.syspath_prepend(str(EXAMPLE))
    # recorded as absent, then removed: undoing both leaves no module behind
    monkeypatch.setitem(sys.modules, "walkthrough_agents", None)
    monkeypatch.delitem(sys.modules, "walkthrough_agents")
    env = {"A2AGW_CONTROL_URL": "https://cp.example.com"}  # plain http needs A2AGW_DEV=1
    for name, agent_id in (("gw-east", "planner"), ("gw-west", "p")):
        cfg = load_config(EXAMPLE / f"{name}.yaml", env=env)
        assert cfg.control_plane is not None
        assert cfg.control_plane.token_env == "A2AGW_CP_TOKEN"
        assert sorted(cfg.control_plane.manage) == ["partners", "policy"]
        assert not cfg.partners and cfg.policy_file is None
        cfg.db_url = "sqlite+aiosqlite://"
        host = build_host(cfg, config_dir=EXAMPLE)
        assert list(host.specs) == [agent_id] and host.control_plane is not None
