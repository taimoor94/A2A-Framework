"""Read-only management API."""

from __future__ import annotations

import asyncio
import hashlib
import json

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest
from google.protobuf.json_format import MessageToDict

from a2agw.consult.client import PartnerClient
from a2agw.consult.registry import PartnerRegistry
from a2agw.core.events import Done
from a2agw.ops import admin as admin_mod
from a2agw.ops.bus import GatewayEvent
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import HEALTH_PATH, AgentHost


class Echo:
    durable_sessions = True

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


def spec(agent_id: str = "alpha") -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test agent",
        version="1.2.3",
        skills=[SkillSpec(id="s", name="Skill S", description="d")],
        adapter=Echo(),
    )


def auth() -> AuthConfig:
    def h(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()

    return AuthConfig(
        api_keys={
            h("admin-secret"): ApiKeyEntry(principal_id="ops", scopes=["a2agw:admin"]),
            h("user-secret"): ApiKeyEntry(principal_id="user", scopes=["other"]),
        }
    )


ADMIN = {"X-API-Key": "admin-secret"}
USER = {"X-API-Key": "user-secret"}


@pytest.fixture
async def make(tmp_path):
    made: list[tuple[AgentHost, httpx.AsyncClient]] = []

    async def _make(*specs: AgentSpec, **kw) -> tuple[AgentHost, httpx.AsyncClient]:
        host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", **kw)
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


def parse_sse(text: str) -> list[dict]:
    frames = []
    for block in text.split("\n\n"):
        if not block.strip() or block.startswith(":"):
            continue
        fields = dict(line.split(": ", 1) for line in block.split("\n"))
        frames.append(fields)
    return frames


async def test_admin_requires_scope(make):
    _, hc = await make(spec(), auth=auth())
    url = "/a2agw/admin/agents"
    assert (await hc.get(url)).status_code == 401
    r = await hc.get(url, headers=USER)
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    for path in ("partners", "tasks", "events?limit=1"):
        assert (await hc.get(f"/a2agw/admin/{path}", headers=USER)).status_code == 403
    assert (await hc.get(url, headers=ADMIN)).status_code == 200


async def test_admin_fails_closed_without_auth(make):
    _, hc = await make(spec())
    r = await hc.get("/a2agw/admin/agents")
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    assert (await hc.get(HEALTH_PATH)).status_code == 200


async def test_admin_without_auth_opt_in(make):
    _, hc = await make(spec(), admin_without_auth=True)
    assert (await hc.get("/a2agw/admin/agents")).status_code == 200


async def test_admin_can_be_disabled(make):
    _, hc = await make(spec(), admin=False, admin_without_auth=True)
    assert (await hc.get("/a2agw/admin/agents")).status_code == 404


async def test_agents_lists_registered(make):
    _, hc = await make(spec("alpha"), spec("beta"), auth=auth())
    body = (await hc.get("/a2agw/admin/agents", headers=ADMIN)).json()
    assert [a["id"] for a in body] == ["alpha", "beta"]
    assert body[0] == {
        "id": "alpha",
        "name": "Alpha",
        "version": "1.2.3",
        "skills": [{"id": "s", "name": "Skill S"}],
        "card_url": "http://t/agents/alpha/.well-known/agent-card.json",
        "durable": True,
    }


async def test_partners_empty_before_task_15(make):
    _, hc = await make(spec(), auth=auth())
    assert (await hc.get("/a2agw/admin/partners", headers=ADMIN)).json() == []


async def test_partners_hides_credentials(make):
    host, hc = await make(spec(), auth=auth())
    registry = PartnerRegistry()
    card = host.cards["alpha"]
    await registry.add_from_card(
        "p1", MessageToDict(card), "internal", credential_ref="SUPER_SECRET_REF"
    )
    client = PartnerClient(registry)
    for _ in range(5):
        client._breaker("p1").record_failure()  # trips the breaker
    host.partners, host.client = registry, client  # type: ignore[attr-defined]
    r = await hc.get("/a2agw/admin/partners", headers=ADMIN)
    assert "SUPER_SECRET_REF" not in r.text and "credential" not in r.text
    (p,) = r.json()
    rec = registry.get("p1")
    assert p == {
        "id": "p1",
        "tier": "internal",
        "status": "active",
        "card_hash": rec.card_hash,
        "fetched_at": rec.fetched_at,
        "card_url": rec.card_url,
        "breaker_state": "open",
        "in_flight": 0,
    }
    assert client.partner_stats("unknown") == {"breaker_state": "closed", "in_flight": 0}
    assert "unknown" not in client._breakers  # reading stats creates no state
    await client.aclose()


async def test_tasks_filter_by_state(make):
    host, hc = await make(spec("alpha"), spec("beta"), auth=auth())
    idx = host.index
    await idx.upsert("t1", "alpha", "o", "c1", "TASK_STATE_COMPLETED", None)
    await idx.upsert("t2", "alpha", "o", "c2", "TASK_STATE_WORKING", None)
    await idx.upsert("t3", "beta", "o", "c3", "TASK_STATE_COMPLETED", None)
    get = lambda q: hc.get(f"/a2agw/admin/tasks{q}", headers=ADMIN)
    body = (await get("?state=TASK_STATE_COMPLETED")).json()
    assert {t["task_id"] for t in body["tasks"]} == {"t1", "t3"} and body["next_cursor"] is None
    body = (await get("?agent=alpha&state=TASK_STATE_COMPLETED")).json()
    assert [t["task_id"] for t in body["tasks"]] == ["t1"]
    page1 = (await get("?limit=2")).json()
    assert len(page1["tasks"]) == 2 and page1["next_cursor"]
    page2 = (await get(f"?limit=2&cursor={page1['next_cursor']}")).json()
    assert len(page2["tasks"]) == 1 and page2["next_cursor"] is None


@pytest.mark.parametrize(
    ("query", "field"),
    [
        ("state=completed", "state"),
        ("limit=0", "limit"),
        ("limit=101", "limit"),
        ("limit=abc", "limit"),
        ("cursor=%21%21notacursor", "cursor"),
    ],
)
async def test_tasks_bad_params(make, query, field):
    _, hc = await make(spec(), auth=auth())
    r = await hc.get(f"/a2agw/admin/tasks?{query}", headers=ADMIN)
    assert r.status_code == 400
    assert r.json() == {"error": "bad request", "field": field}


async def test_events_sse_streams_task_state(make):
    host, hc = await make(spec(), auth=auth())
    card = host.cards["alpha"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()), base_url="http://t", headers=ADMIN
    ) as authed:
        c = ClientFactory(ClientConfig(httpx_client=authed, streaming=False)).create(card)
        req = SendMessageRequest(
            message=Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text="hi")])
        )
        _ = [ev async for ev in c.send_message(req)]
    n = len(host.bus.recent(50))
    assert n >= 1
    r = await hc.get(f"/a2agw/admin/events?limit={n}", headers=ADMIN)
    assert r.headers["content-type"].startswith("text/event-stream")
    frames = parse_sse(r.text)
    assert len(frames) == n
    assert all(f["event"] == "task.state" for f in frames)
    payload = json.loads(frames[-1]["data"])
    assert payload["kind"] == "task.state" and payload["agent_id"] == "alpha"
    assert set(payload) == {"kind", "agent_id", "data", "ts"}
    assert frames[-1]["id"] == str(payload["ts"])


async def test_events_live_and_limit(make, monkeypatch):
    host, hc = await make(spec(), auth=auth())
    host.bus.publish(GatewayEvent("partner.call", "alpha", {"n": 0}))

    async def later():
        await asyncio.sleep(0.05)
        host.bus.publish(GatewayEvent("partner.state", "alpha", {"n": 1}))
        host.bus.publish(GatewayEvent("partner.state", "alpha", {"n": 2}))

    t = asyncio.create_task(later())
    r = await hc.get("/a2agw/admin/events?limit=2", headers=ADMIN)  # replay 1 + live 1
    await t
    frames = parse_sse(r.text)
    assert [json.loads(f["data"])["data"]["n"] for f in frames] == [0, 1]
    assert host.bus._subscribers == set()  # unsubscribed after the stream ended


async def test_events_keepalive(make, monkeypatch):
    host, hc = await make(spec(), auth=auth())
    monkeypatch.setattr(admin_mod, "KEEPALIVE_S", 0.01)

    async def later():
        await asyncio.sleep(0.1)
        host.bus.publish(GatewayEvent("partner.call", "alpha", {}))

    t = asyncio.create_task(later())
    r = await hc.get("/a2agw/admin/events?limit=1", headers=ADMIN)
    await t
    assert ": keepalive\n\n" in r.text and "event: partner.call" in r.text


@pytest.mark.parametrize("limit", ["0", "1001", "x"])
async def test_events_bad_limit(make, limit):
    _, hc = await make(spec(), auth=auth())
    r = await hc.get(f"/a2agw/admin/events?limit={limit}", headers=ADMIN)
    assert r.status_code == 400 and r.json()["field"] == "limit"


async def test_events_unsubscribes_on_disconnect(make):
    host, _ = await make(spec(), admin_without_auth=True)
    app = host.app()
    sent: list[dict] = []
    disconnect = asyncio.Event()

    async def receive():
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": [],
        "scheme": "http",
        "path": "/a2agw/admin/events",
        "raw_path": b"/a2agw/admin/events",
        "query_string": b"",
        "server": ("t", 80),
        "client": ("127.0.0.1", 1),
        "root_path": "",
    }
    task = asyncio.create_task(app(scope, receive, send))
    for _ in range(100):
        if host.bus._subscribers:
            break
        await asyncio.sleep(0.01)
    assert len(host.bus._subscribers) == 1
    disconnect.set()
    await asyncio.wait_for(task, 2)
    assert host.bus._subscribers == set()


async def test_healthz_public(make):
    _, hc = await make(spec(), auth=auth())
    assert HEALTH_PATH == "/a2agw/admin/healthz"
    r = await hc.get(HEALTH_PATH)
    # audit_errors counts failed audit appends (the audit log is fail-open).
    assert r.status_code == 200 and r.json() == {"status": "ok", "audit_errors": 0}


def _events_scope() -> dict:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "headers": [],
        "scheme": "http",
        "path": "/a2agw/admin/events",
        "raw_path": b"/a2agw/admin/events",
        "query_string": b"",
        "server": ("t", 80),
        "client": ("127.0.0.1", 1),
        "root_path": "",
    }


async def _open_events_stream(host):
    sent: list[dict] = []

    async def receive():
        await asyncio.Event().wait()  # the client never disconnects

    async def send(message):
        sent.append(message)

    task = asyncio.create_task(host.app()(_events_scope(), receive, send))
    for _ in range(100):
        if host.bus._subscribers:
            break
        await asyncio.sleep(0.01)
    assert len(host.bus._subscribers) == 1
    return task, sent


async def test_events_stream_ends_on_close_all(make):
    """Finding 8: an open /events stream with a connected client ends on close_all."""
    host, _ = await make(spec(), admin_without_auth=True)
    task, sent = await _open_events_stream(host)
    host.bus.close_all()
    await asyncio.wait_for(task, 2)
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert host.bus._subscribers == set()


async def test_events_stream_ends_on_host_shutdown(make):
    host, _ = await make(spec(), admin_without_auth=True)
    task, _ = await _open_events_stream(host)
    await host.shutdown()
    await asyncio.wait_for(task, 2)


async def test_exit_signal_ends_events_stream_before_lifespan_shutdown(tmp_path):
    """Uvicorn waits for open responses before the lifespan shutdown: the exit signal itself
    must end /events, then reach the previously installed (uvicorn's) handler."""
    import signal

    host = AgentHost(
        "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'sig.db'}", admin_without_auth=True
    )
    host.add(spec())
    app = host.app()
    seen: list[int] = []

    def uvicorn_handler(sig, frame):
        seen.append(sig)

    original = signal.signal(signal.SIGTERM, uvicorn_handler)
    try:
        async with app.router.lifespan_context(app):
            task, _ = await _open_events_stream(host)
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            await asyncio.wait_for(task, 2)  # ended while the app is still up
            assert seen == [signal.SIGTERM]
        assert signal.getsignal(signal.SIGTERM) is uvicorn_handler  # restored
    finally:
        signal.signal(signal.SIGTERM, original)


async def test_partners_reload_makes_cli_added_partner_usable(make, tmp_path):
    """A partner added to the file by the CLI while the host runs is usable after
    POST /partners/reload, by the host's already running PartnerClient (no restart)."""
    from streaming_asgi import StreamingASGITransport

    partner = AgentHost("http://p", db_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    partner.add(spec("echo"))
    await partner.startup()
    outbound = httpx.AsyncClient(transport=StreamingASGITransport({"p": partner.app()}))
    pf = tmp_path / "partners.yaml"
    pf.write_text("partners: []\n")
    try:
        host, hc = await make(spec(), auth=auth(), partners_path=pf, partner_http=outbound)
        client = host.client
        assert (await client.consult("echo", "hi", wait_seconds=5)).reason == "unknown partner"

        cli = PartnerRegistry(pf)  # `a2agw partners add`, another process
        cli.load()
        await cli.add_from_card("echo", MessageToDict(partner.cards["echo"]), "internal")

        url = "/a2agw/admin/partners/reload"
        assert (await hc.post(url, headers=USER)).status_code == 403
        r = await hc.post(url, headers=ADMIN)
        assert r.status_code == 200
        assert r.json() == {"added": ["echo"], "updated": [], "removed": [], "open_handles": 0}
        assert host.client is client  # same running client
        res = await client.consult("echo", "hi", wait_seconds=5)
        assert res.state == "completed" and res.text == "echo: hi"

        events = (await hc.get("/a2agw/admin/audit?action=partner.reload", headers=ADMIN)).json()
        assert [(e["actor"], e["outcome"]) for e in events["events"]] == [("key:ops", "ok")]
        adds = (await hc.get("/a2agw/admin/audit?action=partner.add", headers=ADMIN)).json()
        assert [e["partner_id"] for e in adds["events"]] == ["echo"]

        # An invalid file is refused and changes nothing.
        pf_before = pf.read_text()
        pf.write_text("partners: {}\n")
        r = await hc.post(url, headers=ADMIN)
        assert r.status_code == 400 and r.json() == {"error": "partners file not reloaded"}
        assert [p.id for p in host.partners.all()] == ["echo"]

        # Removing it from the file removes it from the running host.
        assert "echo" in pf_before
        pf.write_text("partners: []\n")
        r = await hc.post(url, headers=ADMIN)
        assert r.json() == {"added": [], "updated": [], "removed": ["echo"], "open_handles": 0}
        assert (await client.consult("echo", "hi", wait_seconds=5)).reason == "unknown partner"
    finally:
        await outbound.aclose()
        await partner.shutdown()


async def test_partners_reload_broken_yaml_is_400_audited_without_content(make, tmp_path):
    pf = tmp_path / "partners.yaml"
    pf.write_text("partners: []\n")
    host, hc = await make(spec(), auth=auth(), partners_path=pf)
    for broken in (b"partners: [\n  - id: s3cret-line\n  bad: : :\n", b"\xff\xfe s3cret-line"):
        pf.write_bytes(broken)
        r = await hc.post("/a2agw/admin/partners/reload", headers=ADMIN)
        assert r.status_code == 400 and "s3cret" not in r.text
    rows = (await hc.get("/a2agw/admin/audit?action=partner.reload", headers=ADMIN)).json()
    assert [(e["outcome"], e["detail"]["reason"]) for e in rows["events"]] == [
        ("error", "ValueError"),
        ("error", "ValueError"),
    ]
    assert "s3cret" not in json.dumps(rows)
    assert host.partners.all() == []


async def test_partners_reload_refuses_removing_partner_with_open_handles(make, tmp_path):
    from google.protobuf.json_format import MessageToDict as to_dict

    pf = tmp_path / "partners.yaml"
    pf.write_text("partners: []\n")
    host, hc = await make(spec(), auth=auth(), partners_path=pf)
    cli = PartnerRegistry(pf)
    cli.load()
    await cli.add_from_card("ghost", to_dict(host.cards["alpha"]), "internal")
    url = "/a2agw/admin/partners/reload"
    assert (await hc.post(url, headers=ADMIN)).json()["added"] == ["ghost"]
    await host.handles.record("t1", "ghost", "c1", None, None, "TASK_STATE_WORKING")
    await host.handles.record("t2", "ghost", "c1", None, None, "TASK_STATE_COMPLETED")
    pf.write_text("partners: []\n")

    r = await hc.post(url, headers=ADMIN)
    assert r.status_code == 409 and r.json()["open_handles"] == 1
    assert [p.id for p in host.partners.all()] == ["ghost"]  # unchanged
    assert (await hc.post(url + "?force=maybe", headers=ADMIN)).status_code == 400
    r = await hc.post(url + "?force=true", headers=ADMIN)
    assert r.status_code == 200
    assert r.json() == {"added": [], "updated": [], "removed": ["ghost"], "open_handles": 1}
    assert host.partners.all() == []
    rows = (await hc.get("/a2agw/admin/audit?action=partner.reload", headers=ADMIN)).json()
    assert [e["outcome"] for e in rows["events"]][:2] == ["ok", "refused"]
