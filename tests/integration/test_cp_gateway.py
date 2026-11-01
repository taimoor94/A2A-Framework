"""A real control plane (Tasks 4-6) and a real gateway in-process, joined by the connector.

The control plane runs through its lifespan on a fake epoch clock whose sleeps move it; the
gateway's connector has its own fake clock and sleep. ``Link`` is the network between them:
``down()`` cuts it (the open stream breaks, new requests are refused) and ``up()`` restores
it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

pytest.importorskip("fastapi")

from sqlalchemy import delete, select
from streaming_asgi import StreamingASGITransport

from a2agw.config import ControlPlaneConfig
from a2agw.consult import netguard
from a2agw.consult.registry import _normalize, card_hash
from a2agw.control import channel
from a2agw.control.settings import ControlSettings
from a2agw.control.store import (
    ASSIGNMENTS,
    GATEWAY_AUDIT,
    GATEWAYS,
    HEALTH,
    PARTNER_VERSIONS,
    PARTNERS,
    POLICIES,
    POLICY_VERSIONS,
)
from a2agw.ops.cp_client import LOCKDOWN_RULE_ID, ControlPlaneConnector
from a2agw.security.policy import parse_policy, policy_hash
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

CP_HOST = "cp.example"
CP = f"https://{CP_HOST}"
TOKEN_ENV = "A2AGW_CP_TOKEN"
POLICY = {
    "version": 1,
    "authz": [{"id": "ops", "principal": "*", "agents": "*", "effect": "allow"}],
}


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def sleeper(clock: Clock) -> Callable[[float], Any]:
    async def sleep(seconds: float) -> None:
        clock.t += seconds
        await asyncio.sleep(0.002)

    return sleep


async def until(pred: Callable[[], Any], timeout: float = 20.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not await _value(pred()):
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


async def _value(v: Any) -> Any:
    return await v if asyncio.iscoroutine(v) else v


class Link(httpx.AsyncBaseTransport):
    """The network between gateway and control plane: a streaming ASGI transport that can
    be cut (``down``: streams break, requests are refused) and restored (``up``)."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.inner: StreamingASGITransport | None = StreamingASGITransport({CP_HOST: app})
        self.old: list[StreamingASGITransport] = []

    async def down(self) -> None:
        if self.inner is not None:
            inner, self.inner = self.inner, None
            self.old.append(inner)
            await inner.stop_serving()

    def up(self) -> None:
        if self.inner is None:
            self.inner = StreamingASGITransport({CP_HOST: self.app})

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.inner is None:
            raise httpx.ConnectError("control plane unreachable", request=request)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.down()


def make_card(name: str) -> dict[str, Any]:
    raw = {
        "name": name,
        "description": f"{name} does things",
        "version": "1.0",
        "supportedInterfaces": [
            {
                "url": f"https://{name.lower()}.example.com/rpc",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
    }
    return _normalize(raw)[0]


async def seed_partner(app: Any, gateway_id: str, pid: str) -> None:
    now = app.state.clock()
    c = make_card(pid)
    async with app.state.engine.begin() as conn:
        await conn.execute(
            PARTNERS.insert().values(
                id=pid,
                card_url=f"https://{pid}.example.com/.well-known/agent-card.json",
                tier="partner",
                credential_ref=None,
                tls_ref=None,
                tags_json=json.dumps(["blue"]),
                status="approved",
                current_version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await conn.execute(
            PARTNER_VERSIONS.insert().values(
                partner_id=pid,
                version=1,
                card_json=json.dumps(c),
                card_hash=card_hash(c),
                fetched_at=now,
                approved_by="oidc:sec",
                approved_at=now,
            )
        )
        await conn.execute(
            ASSIGNMENTS.insert().values(
                gateway_id=gateway_id, kind="partner", ref_id=pid, ref_version=None
            )
        )
    await channel.mark_dirty(app.state.store, [gateway_id])


async def unassign(app: Any, gateway_id: str, pid: str) -> None:
    async with app.state.engine.begin() as conn:
        await conn.execute(
            delete(ASSIGNMENTS).where(
                ASSIGNMENTS.c.gateway_id == gateway_id, ASSIGNMENTS.c.ref_id == pid
            )
        )
    await channel.mark_dirty(app.state.store, [gateway_id])


async def seed_policy(app: Any, gateway_id: str, doc: dict[str, Any]) -> None:
    now = app.state.clock()
    async with app.state.engine.begin() as conn:
        await conn.execute(POLICIES.insert().values(id="pol", name="pol", created_at=now))
        await conn.execute(
            POLICY_VERSIONS.insert().values(
                policy_id="pol",
                version=1,
                doc_json=json.dumps(doc),
                doc_hash="p1",
                created_by="oidc:sec",
                created_at=now,
                comment="",
            )
        )
        await conn.execute(
            ASSIGNMENTS.insert().values(
                gateway_id=gateway_id, kind="policy", ref_id="pol", ref_version=None
            )
        )
    await channel.mark_dirty(app.state.store, [gateway_id])


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        from a2agw.core.events import Done

        yield Done(text="ok")


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    async def fake(_host: str) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)


@pytest.fixture
async def control_plane(tmp_path) -> AsyncIterator[Any]:
    from a2agw.control.app import create_app

    clock = Clock(1_700_000_000.0)
    settings = ControlSettings(
        base_url=CP,
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}",
        limits={"stream_keepalive_s": 2.0},
    )
    async with httpx.AsyncClient() as cp_http:
        app = create_app(
            settings, http=cp_http, clock=clock, sleep=sleeper(clock), maintenance_interval_s=3600
        )
        async with app.router.lifespan_context(app):
            link = Link(app)
            app.state.link = link
            try:
                yield app
            finally:
                await link.down()  # every request of the gateways ends before the app does


@pytest.fixture
def enroll(control_plane, monkeypatch):
    async def make() -> str:
        gateway_id, token = await control_plane.state.store.create_gateway("gw-a", actor="t")
        monkeypatch.setenv(TOKEN_ENV, token)
        return gateway_id

    return make


@asynccontextmanager
async def gateway(app: Any, db: str) -> AsyncIterator[tuple[AgentHost, ControlPlaneConnector]]:
    host = AgentHost("http://gw.test", db_url=db)
    host.add(
        AgentSpec(
            id="alpha",
            name="Alpha",
            description="d",
            skills=[SkillSpec(id="s", name="S", description="d")],
            adapter=Echo(),
        )
    )
    clock = Clock(500.0)
    http = httpx.AsyncClient(transport=app.state.link)
    conn = ControlPlaneConnector(
        host,
        ControlPlaneConfig(url=CP, token_env=TOKEN_ENV, manage=["partners", "policy"]),
        http=http,
        clock=clock,
        sleep=sleeper(clock),
    )
    await host.startup()
    try:
        yield host, conn
    finally:
        await host.shutdown()
        await http.aclose()


async def gateway_row(app: Any, gateway_id: str) -> Any:
    async with app.state.engine.connect() as c:
        return (await c.execute(select(GATEWAYS).where(GATEWAYS.c.id == gateway_id))).first()


def partner_ids(host: AgentHost) -> list[str]:
    return sorted(r.id for r in host.partners.all())


async def test_gateway_enrolls_receives_partners_and_policy(control_plane, enroll, tmp_path):
    app = control_plane
    gw = await enroll()
    await seed_partner(app, gw, "p1")
    await seed_policy(app, gw, POLICY)
    async with gateway(app, f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}") as (host, conn):
        await until(lambda: conn.status()["applied_version"] == 1)
        assert partner_ids(host) == ["p1"]
        assert host.policy is not None
        assert policy_hash(host.policy.policy) == policy_hash(parse_policy(POLICY))

        async def reported() -> bool:
            row = await gateway_row(app, gw)
            return row.last_version_applied == 1 and bool(json.loads(row.info_json or "{}"))

        await until(reported)
        row = await gateway_row(app, gw)
        assert row.epoch_applied == app.state.store.epoch
        info = json.loads(row.info_json)
        assert [a["id"] for a in info["agents"]] == ["alpha"] and info[
            "base_url"
        ] == "http://gw.test"
        assert info["agents"][0]["name"] and info["agents"][0]["skills"]

        async def audit_and_health() -> bool:
            async with app.state.engine.connect() as c:
                audit = (await c.execute(select(GATEWAY_AUDIT.c.row_json))).all()
                health = (await c.execute(select(HEALTH))).all()
            actions = {json.loads(r.row_json)["action"] for r in audit}
            return "cp.apply" in actions and bool(health)

        await until(audit_and_health)
        assert conn.status()["connected"] is True


async def test_cp_down_gateway_keeps_serving_then_resyncs(control_plane, enroll, tmp_path):
    app = control_plane
    gw = await enroll()
    await seed_partner(app, gw, "p1")
    await seed_policy(app, gw, POLICY)
    async with gateway(app, f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}") as (host, conn):
        await until(lambda: conn.status()["applied_version"] == 1)
        await app.state.link.down()
        await until(lambda: conn.status()["connected"] is False)
        # still serving what it had
        assert partner_ids(host) == ["p1"]
        assert host.policy is not None and host.policy_source == "control_plane"
        await seed_partner(app, gw, "p2")
        app.state.link.up()
        await until(lambda: conn.status()["applied_version"] == 2)
        assert partner_ids(host) == ["p1", "p2"]
        assert conn.status()["connected"] is True


async def test_gateway_restart_with_cp_down_uses_cached_state(control_plane, enroll, tmp_path):
    app = control_plane
    gw = await enroll()
    await seed_partner(app, gw, "p1")
    await seed_policy(app, gw, POLICY)
    db = f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}"
    async with gateway(app, db) as (_host, conn):
        await until(lambda: conn.status()["applied_version"] == 1)
    await app.state.link.down()
    async with gateway(app, db) as (host, conn):
        # before any connection: the last applied state is in force
        assert partner_ids(host) == ["p1"]
        assert host.policy is not None
        assert policy_hash(host.policy.policy) == policy_hash(parse_policy(POLICY))
        assert host.policy_source == "control_plane"
        status = conn.status()
        assert status["applied_version"] == 1 and status["connected"] is False
        assert not conn.waiting_for_state


async def test_first_start_without_cp_is_lockdown(control_plane, enroll, tmp_path, caplog):
    app = control_plane
    await enroll()
    await app.state.link.down()
    async with gateway(app, f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}") as (host, conn):
        assert host.partners.all() == []
        assert host.policy is not None
        [rule] = host.policy.policy.authz
        assert rule.id == LOCKDOWN_RULE_ID == "cp:unconfigured"
        assert rule.effect == "deny" and rule.principal == "*" and rule.agents == "*"
        assert conn.waiting_for_state
        assert any("waiting for its first" in r.getMessage() for r in caplog.records)
        transport = httpx.ASGITransport(app=host.app())
        async with httpx.AsyncClient(transport=transport, base_url="http://gw.test") as c:
            health = (await c.get("/a2agw/admin/healthz")).json()
            assert health["control_plane"]["connected"] is False
            assert "waiting" in health["control_plane"]["warning"]
            r = await c.post(
                "/agents/alpha/",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "SendMessage",
                    "params": {
                        "message": {
                            "messageId": "m1",
                            "role": "ROLE_USER",
                            "parts": [{"text": "hi"}],
                        }
                    },
                },
                headers={"A2A-Version": "1.0"},
            )
            assert r.status_code == 403, r.text
        assert host.audit is not None
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "policy.update"}, limit=10)
        assert rows and rows[0]["detail"]["reason"] == "control_plane"


async def test_removed_partner_with_open_tasks_disabled_then_removed(
    control_plane, enroll, tmp_path
):
    app = control_plane
    gw = await enroll()
    await seed_partner(app, gw, "p1")
    await seed_partner(app, gw, "p2")
    async with gateway(app, f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}") as (host, conn):
        await until(lambda: conn.status()["applied_version"] is not None)
        assert partner_ids(host) == ["p1", "p2"]
        version = conn.status()["applied_version"]
        assert host.handles is not None
        await host.handles.record("pt-1", "p1", "c1", None, None, "TASK_STATE_WORKING")
        await unassign(app, gw, "p1")
        await unassign(app, gw, "p2")
        # the desired state without both partners: wait for that one, not for whichever
        # version follows the first unassign
        final = await channel.compute_desired(app.state.store, gw)
        assert final.version > version and final.partners == []
        await until(lambda: conn.status()["applied_version"] == final.version)
        # p1 has an open partner task: disabled at once, kept until it ends; p2 is gone
        assert partner_ids(host) == ["p1"]
        assert host.partners.get("p1").status == "disabled"
        await host.maintain()
        assert partner_ids(host) == ["p1"]  # still open
        await host.handles.update_state("p1", "pt-1", "TASK_STATE_COMPLETED")
        await host.maintain()
        assert partner_ids(host) == []


async def test_catalogue_approval_of_a_gateway_quarantine_end_to_end(
    control_plane, enroll, tmp_path
):
    """A gateway quarantines a changed card; the catalogue fetches the card itself, and the
    hash it computes is the one the gateway's partner.approve compares: the queued command
    succeeds and the partner is active with the new card."""
    import respx

    from a2agw.control.store import COMMANDS

    app = control_plane
    gw = await enroll()
    _kid, key = await app.state.store.create_api_key("ops", "admin", actor="t")
    admin = {"authorization": f"Bearer {key}"}
    raw = {
        "name": "Acme",
        "description": "acme does things",
        "version": "1.0",
        "supportedInterfaces": [
            {
                "url": "https://acme.example.com/rpc",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
    }
    changed = {**raw, "description": "acme does other things now"}
    with respx.mock(assert_all_called=False) as rx:
        route = rx.get("https://acme.example.com/.well-known/agent-card.json").respond(
            200, json=raw
        )
        async with httpx.AsyncClient(transport=app.state.link, base_url=CP) as cp:
            r = await cp.post(
                "/api/v1/partners",
                json={"id": "acme", "tier": "partner", "card_url": "https://acme.example.com"},
                headers=admin,
            )
            assert r.status_code == 201, r.text
            v1 = r.json()["versions"][0]
            r = await cp.post(
                "/api/v1/partners/acme/approve",
                json={"version": 1, "expected_hash": v1["card_hash"]},
                headers=admin,
            )
            assert r.status_code == 200, r.text
            r = await cp.put(
                f"/api/v1/gateways/{gw}/partners", json={"partner_ids": ["acme"]}, headers=admin
            )
            assert r.status_code == 200, r.text
            async with gateway(app, f"sqlite+aiosqlite:///{tmp_path / 'gw.db'}") as (host, _c):
                await until(lambda: partner_ids(host) == ["acme"])
                assert host.partners.get("acme").card_hash == v1["card_hash"]

                # the gateway sees the card change first and quarantines it locally
                route.respond(200, json=changed)
                assert await host.partners.refresh("acme") == "quarantined"
                local_pending = card_hash(host.partners.get("acme").pending_card or {})

                async def reported() -> bool:
                    d = (await cp.get("/api/v1/partners/acme", headers=admin)).json()
                    return any(g["status"] == "quarantined" for g in d["gateways"])

                await until(reported)
                r = await cp.post("/api/v1/partners/acme/refresh", headers=admin)
                assert r.status_code == 200 and r.json()["outcome"] == "pending", r.text
                v2 = r.json()["pending_version"]
                [gw_state] = r.json()["gateways"]
                assert v2["card_hash"] == local_pending == gw_state["pending_hash"]

                r = await cp.post(
                    "/api/v1/partners/acme/approve",
                    json={"version": 2, "expected_hash": v2["card_hash"]},
                    headers=admin,
                )
                assert r.status_code == 200, r.text
                [queued] = r.json()["commands"]

                async def finished() -> bool:
                    async with app.state.engine.connect() as c:
                        row = (
                            await c.execute(
                                select(COMMANDS).where(COMMANDS.c.id == queued["command_id"])
                            )
                        ).first()
                    return row is not None and row.status in ("done", "failed")

                await until(finished)
                async with app.state.engine.connect() as c:
                    row = (
                        await c.execute(
                            select(COMMANDS).where(COMMANDS.c.id == queued["command_id"])
                        )
                    ).first()
                assert row.status == "done", row.result_json
                await until(lambda: host.partners.get("acme").card_hash == v2["card_hash"])
                rec = host.partners.get("acme")
                assert rec.status == "active" and rec.pending_card is None
