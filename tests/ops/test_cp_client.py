"""The gateway's control-plane connector against a fake control plane (scripted frames).

The fake control plane is a Starlette app on ``StreamingASGITransport``: each stream
connection sends ``hello`` and then the frames scripted for it, and either ends or stays
open (frames can be pushed to the open stream with ``cp.push``). Reports are recorded and
acknowledged by ``cp.ack``. The connector runs on a fake clock and a fake sleep (every
sleep moves the clock and yields briefly for real), so back-off never waits for real.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from streaming_asgi import StreamingASGITransport

from a2agw.config import ConfigError, ControlPlaneConfig, load_config
from a2agw.consult import netguard
from a2agw.consult.registry import _normalize, card_hash
from a2agw.ops.audit import AuditEvent, canonical_json
from a2agw.ops.cp_client import EVENT_QUEUE_MAX, ControlPlaneConnector, CpStateStore
from a2agw.security.policy import parse_policy, policy_hash
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

CP = "https://cp.example"
TOKEN_ENV = "A2AGW_CP_TOKEN"
TOKEN = "gw-token-SECRET-0123456789"
SERVER_TIME = 1_700_000_000.0
EVIL_HOST = "evil.example.com"


def card(name: str, host: str = "partner.example.com") -> dict[str, Any]:
    raw = {
        "name": name,
        "description": f"{name} does things",
        "version": "1.0",
        "supportedInterfaces": [
            {"url": f"https://{host}/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
    }
    normalized, _ = _normalize(raw)
    return normalized


def partner(pid: str, *, host: str = "partner.example.com", **over: Any) -> dict[str, Any]:
    c = card(pid.upper(), host)
    rec = {
        "id": pid,
        "card": c,
        "card_hash": card_hash(c),
        "tier": "partner",
        "credential_ref": None,
        "tls_ref": None,
        "tags": ["blue"],
        "card_url": f"https://{host}/.well-known/agent-card.json",
    }
    rec.update(over)
    return rec


POLICY = {
    "version": 1,
    "authz": [{"id": "all", "principal": "*", "agents": "*", "effect": "allow"}],
}


def state(
    version: int,
    partners: list[dict[str, Any]],
    policy: dict[str, Any] | None = POLICY,
    *,
    epoch: str = "e1",
) -> dict[str, Any]:
    doc = {"partners": partners, "policy": policy}
    digest = hashlib.sha256(canonical_json(doc).encode()).hexdigest()
    return {"epoch": epoch, "version": version, "hash": digest, **doc}


def command(cid: str, kind: str, args: dict[str, Any], *, ttl: float = 60.0) -> dict[str, Any]:
    return {
        "id": cid,
        "kind": kind,
        "args": args,
        "expires_at": SERVER_TIME + ttl,
        "actor": "oidc:op",
    }


def sse(event: str, data: Any) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


class FakeCP:
    """Scripted control plane. ``script(*frames, end=False)`` sets what the next stream
    connection sends after ``hello``; ``end=True`` closes it afterwards."""

    def __init__(self) -> None:
        self.scripts: list[tuple[list[tuple[str, Any]], bool]] = []
        self.queries: list[dict[str, str]] = []
        self.stream_headers: list[dict[str, str]] = []
        self.urls: list[str] = []
        self.reports: list[dict[str, Any]] = []
        self.stream_status = 200
        self.report_status = 200
        self.refused = 0
        self.report_hang: asyncio.Event | None = None
        self.break_streams = False
        self.live: asyncio.Queue[bytes] = asyncio.Queue()
        self.acked = 0
        self.ack: Callable[[dict[str, Any]], int] = self._ack_all
        self.app = Starlette(
            routes=[
                Route("/cp/v1/stream", self.stream, methods=["GET"]),
                Route("/cp/v1/report", self.report, methods=["POST"]),
            ]
        )

    def _ack_all(self, body: dict[str, Any]) -> int:
        seqs = [r["seq"] for r in body.get("audit", [])]
        self.acked = max([self.acked, *seqs])
        return self.acked

    def script(self, *frames: tuple[str, Any], end: bool = False) -> None:
        self.scripts.append((list(frames), end))

    def push(self, event: str, data: Any) -> None:
        self.live.put_nowait(sse(event, data))

    async def stream(self, request: Request) -> Response:
        self.urls.append(str(request.url))
        self.queries.append(dict(request.query_params))
        self.stream_headers.append(dict(request.headers))
        if self.stream_status != 200:
            return JSONResponse({"error": "nope"}, status_code=self.stream_status)
        n = len(self.queries) - 1
        frames, end = self.scripts[n] if n < len(self.scripts) else ([], False)

        async def body():
            yield sse("hello", {"gateway_id": "gw-1", "server_time": SERVER_TIME})
            for event, data in frames:
                yield sse(event, data)
            if self.break_streams:
                raise ConnectionError("dropped")  # the connection breaks mid-stream
            if end:
                return
            while True:
                try:
                    yield await asyncio.wait_for(self.live.get(), 0.01)
                except TimeoutError:
                    if await request.is_disconnected():
                        return

        return StreamingResponse(body(), media_type="text/event-stream")

    async def report(self, request: Request) -> Response:
        body = await request.json()
        if self.report_hang is not None:
            await self.report_hang.wait()
        if self.report_status != 200:  # refused: not taken (the gateway sends it again)
            self.refused += 1
            return JSONResponse({"error": "nope"}, status_code=self.report_status)
        self.reports.append(body)
        return JSONResponse(
            {
                "acked_audit_seq": self.ack(body),
                "accepted_events": len(body.get("events", [])),
                "dropped": 0,
            }
        )

    def applied(self) -> list[dict[str, Any]]:
        return [r["applied"] for r in self.reports if r.get("applied")]

    def results(self) -> list[dict[str, Any]]:
        return [x for r in self.reports for x in r.get("results", [])]


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


async def until(pred: Callable[[], Any], timeout: float = 10.0) -> None:
    """Wait (polling for real) until ``pred()`` is true; AssertionError after ``timeout``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not pred():
        assert loop.time() < deadline, "condition not reached"
        await asyncio.sleep(0.005)


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        from a2agw.core.events import Done

        yield Done(text="ok")


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    async def fake(host: str) -> list[str]:
        return ["10.0.0.5"] if host == EVIL_HOST else ["93.184.216.34"]

    monkeypatch.setattr(netguard, "_resolve", fake)
    monkeypatch.setenv(TOKEN_ENV, TOKEN)


@pytest.fixture
def cp() -> FakeCP:
    return FakeCP()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def sleeps(clock) -> list[float]:
    return []


@pytest.fixture
def fake_sleep(clock, sleeps):
    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock.t += seconds
        await asyncio.sleep(0.002)

    return sleep


@pytest.fixture
async def gateway(tmp_path, cp, clock, fake_sleep):
    """``await gateway(**cfg)``: a started host with its connector (closed at teardown)."""
    made: list[tuple[AgentHost, httpx.AsyncClient]] = []
    transport = StreamingASGITransport({"cp.example": cp.app})

    async def make(
        db: str = "gw.db",
        start: bool = True,
        partner_http: httpx.AsyncClient | None = None,
        **cfg: Any,
    ) -> tuple[AgentHost, ControlPlaneConnector]:
        host = AgentHost(
            "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / db}", partner_http=partner_http
        )
        host.add(
            AgentSpec(
                id="alpha",
                name="Alpha",
                description="d",
                skills=[SkillSpec(id="s", name="S", description="d")],
                adapter=Echo(),
            )
        )
        http = httpx.AsyncClient(transport=transport)
        settings = ControlPlaneConfig(
            **{"url": CP, "token_env": TOKEN_ENV, "manage": ["partners", "policy"], **cfg}
        )
        conn = ControlPlaneConnector(host, settings, http=http, clock=clock, sleep=fake_sleep)
        made.append((host, http))
        if start:
            await host.startup()
        return host, conn

    yield make
    await transport.stop_serving()
    for host, http in made:
        await host.shutdown()
        await http.aclose()


async def audit_rows(host: AgentHost, action: str) -> list[dict[str, Any]]:
    assert host.audit is not None
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": action}, limit=100, ascending=True)
    return rows


# -- state ---------------------------------------------------------------------------------


async def test_applies_state_and_reports_applied(gateway, cp):
    s1 = state(1, [partner("p1")])
    cp.script(("state", s1))
    host, conn = await gateway()
    await until(lambda: cp.applied())
    assert cp.applied()[0] == {
        "epoch": "e1",
        "version": 1,
        "hash": s1["hash"],
        "status": "applied",
    }
    rec = host.partners.get("p1")
    assert rec.status == "active" and rec.card_hash == s1["partners"][0]["card_hash"]
    assert host.policy is not None
    assert policy_hash(host.policy.policy) == policy_hash(parse_policy(POLICY))
    assert host.policy_source == "control_plane" and host.policy_managed
    status = conn.status()
    assert status["connected"] is True and status["applied_version"] == 1
    assert set(status) == {"connected", "applied_version", "last_error_kind", "queue", "dropped"}
    [applied] = await audit_rows(host, "cp.apply")
    assert applied["detail"] == {"version": 1, "hash": s1["hash"]}
    assert host.engine is not None
    saved = await CpStateStore(host.engine).get("applied_state")
    assert saved is not None and saved["version"] == 1 and saved["epoch"] == "e1"
    # the first stream asks for everything; the token goes in the header only
    assert cp.queries[0] == {"applied": "0"}
    assert cp.stream_headers[0]["authorization"] == f"Bearer {TOKEN}"
    assert all(TOKEN not in u for u in cp.urls)
    info = next(r["info"] for r in cp.reports if r.get("info"))
    assert info == {
        "version": info["version"],
        "agents": [
            {
                "id": "alpha",
                "name": "Alpha",
                "version": "0.1.0",
                "skills": ["s"],
                "card_url": "http://t/agents/alpha/.well-known/agent-card.json",
            }
        ],
        "base_url": "http://t",
    }
    assert set(info) == {"version", "agents", "base_url"}


async def test_ignores_older_or_equal_version(gateway, cp):
    cp.script(
        ("state", state(2, [partner("p1")])),
        ("state", state(1, [partner("p2")])),  # older: ignored
        ("state", state(2, [partner("p2")])),  # equal: ignored
        ("state", state(1, [partner("p3")], epoch="e2")),  # another epoch (a reset): applied
        end=True,
    )
    host, conn = await gateway()
    await until(lambda: len(cp.queries) >= 2 and len(cp.applied()) >= 2)
    assert [r.id for r in host.partners.all()] == ["p3"]
    assert [(a["epoch"], a["version"]) for a in cp.applied()] == [("e1", 2), ("e2", 1)]
    # the reconnect says what was applied, with its epoch
    assert cp.queries[1] == {"applied": "1", "epoch": "e2"}
    assert conn.status()["applied_version"] == 1


async def test_rejects_state_with_bad_card_hash_keeps_previous(gateway, cp):
    good = state(1, [partner("p1")])
    tampered = partner("p1")
    tampered["card"] = {**tampered["card"], "description": "now evil"}
    bad = state(2, [tampered], policy={"version": 1})
    cp.script(("state", good), ("state", bad))
    host, conn = await gateway()
    await until(lambda: len(cp.applied()) >= 2)
    rejected = cp.applied()[1]
    assert rejected == {
        "epoch": "e1",
        "version": 2,
        "hash": bad["hash"],
        "status": "rejected",
        "reason": "partners.0.card_hash",
    }
    assert host.partners.get("p1").card == good["partners"][0]["card"]
    assert host.policy is not None and host.policy.policy.authz  # the first policy stays
    assert conn.status()["applied_version"] == 1
    [row] = await audit_rows(host, "cp.reject")
    assert row["detail"]["version"] == 2 and row["detail"]["reason"] == "partners.0.card_hash"


async def test_rejects_state_with_unsafe_endpoint_keeps_previous(gateway, cp):
    good = state(1, [partner("p1")])
    bad = state(2, [partner("p1"), partner("p2", host=EVIL_HOST)], policy={"version": 1})
    cp.script(("state", good), ("state", bad))
    host, _conn = await gateway()
    await until(lambda: len(cp.applied()) >= 2)
    assert cp.applied()[1]["status"] == "rejected"
    assert cp.applied()[1]["reason"] == "p2: UnsafeURL"  # the partner, never the URL
    assert [r.id for r in host.partners.all()] == ["p1"]
    assert host.policy is not None and host.policy.policy.authz


async def test_rejects_invalid_policy_keeps_previous(gateway, cp):
    good = state(1, [partner("p1")])
    bad_policy = {
        "version": 1,
        "authz": [{"principal": "not a principal", "agents": "*", "effect": "deny"}],
    }
    bad = state(2, [partner("p1"), partner("p2")], policy=bad_policy)
    cp.script(("state", good), ("state", bad))
    host, _conn = await gateway()
    await until(lambda: len(cp.applied()) >= 2)
    assert cp.applied()[1]["status"] == "rejected"
    assert cp.applied()[1]["reason"] == "policy.authz.0.principal"
    assert [r.id for r in host.partners.all()] == ["p1"]  # nothing from the state applied
    assert host.policy is not None
    assert policy_hash(host.policy.policy) == policy_hash(parse_policy(POLICY))


async def test_rejects_state_whose_hash_does_not_match(gateway, cp):
    bad = state(1, [partner("p1")])
    bad["hash"] = "0" * 64
    cp.script(("state", bad))
    host, _conn = await gateway()
    await until(lambda: cp.applied())
    assert cp.applied()[0]["status"] == "rejected" and cp.applied()[0]["reason"] == "hash"
    assert host.partners.all() == []


async def test_remote_record_cannot_set_local_fields(gateway, cp):
    """The control plane sends the approved card and settings; status, pending cards and
    verified key ids are the gateway's own."""
    bad = state(1, [partner("p1", signed_key_id="pinned#kid#x")])
    cp.script(("state", bad))
    host, _conn = await gateway()
    await until(lambda: cp.applied())
    assert cp.applied()[0]["reason"] == "partners.0.signed_key_id"
    assert host.partners.all() == []


async def test_same_card_keeps_local_quarantine(gateway, cp):
    """A partner quarantined here (its card changed at a refresh) stays quarantined when the
    control plane sends the same approved card again with new settings."""
    cp.script(("state", state(1, [partner("p1")])))
    host, _conn = await gateway()
    await until(lambda: cp.applied())
    rec = host.partners.get("p1")
    rec.pending_card = copy.deepcopy(rec.card) | {"description": "changed"}
    rec.status = "quarantined"
    cp.push("state", state(2, [partner("p1", tags=["red"])]))
    await until(lambda: len(cp.applied()) >= 2)
    rec = host.partners.get("p1")
    assert rec.status == "quarantined" and rec.pending_card is not None
    assert rec.tags == ["red"]


# -- commands ------------------------------------------------------------------------------


async def test_runs_command_and_reports_result(gateway, cp):
    cp.script(
        ("command", command("cmd-1", "tasks.reap", {"agent_id": "ghost"})),
        ("command", command("cmd-2", "no.such.kind", {})),
        ("command", command("cmd-3", "task.cancel", {"agent_id": "alpha", "task_id": "t-x"})),
    )
    host, _conn = await gateway()
    await until(lambda: len(cp.results()) >= 3)
    by_id = {r["id"]: r for r in cp.results()}
    assert by_id["cmd-1"]["status"] == "done"
    assert by_id["cmd-1"]["result"] == {"dry_run": True, "tasks": 0, "handles": 0, "recent": 0}
    assert by_id["cmd-2"] == {
        "id": "cmd-2",
        "status": "failed",
        "result": {"error": "unknown_command"},
    }
    assert by_id["cmd-3"]["status"] == "failed"
    assert by_id["cmd-3"]["result"] == {"error": "not_found"}
    [reaped] = await audit_rows(host, "task.reap")
    assert reaped["actor"] == "cp:oidc:op"
    [cancel] = await audit_rows(host, "task.cancel")
    assert cancel["actor"] == "cp:oidc:op" and cancel["outcome"] == "not_found"


async def test_expired_command_not_run(gateway, cp):
    cp.script(("command", command("cmd-old", "tasks.reap", {"agent_id": "ghost"}, ttl=-1)))
    host, _conn = await gateway()
    await until(lambda: cp.results())
    assert cp.results() == [{"id": "cmd-old", "status": "failed", "result": {"error": "expired"}}]
    assert await audit_rows(host, "task.reap") == []


# -- connection ----------------------------------------------------------------------------


async def test_backoff_capped_and_jittered(gateway, cp, sleeps):
    cp.stream_status = 503
    _host, conn = await gateway(report_interval_s=1000.0)
    await until(lambda: len([s for s in sleeps if s != 1000.0]) >= 12)
    backoff = [s for s in sleeps if s != 1000.0]
    assert all(0 < s <= 30.0 for s in backoff)
    assert 0.25 <= backoff[0] <= 0.5
    assert backoff[3] > backoff[0]  # it grows
    capped = backoff[8:12]
    assert all(15.0 <= s <= 30.0 for s in capped)  # at the cap, within its jitter
    assert len(set(capped)) > 1  # jittered, not a fixed delay
    status = conn.status()
    assert status["connected"] is False and status["last_error_kind"] == "http_503"


async def test_401_stops_and_names_env_not_token(gateway, cp, sleeps, caplog):
    cp.stream_status = 401
    caplog.set_level(logging.DEBUG)
    _host, conn = await gateway()
    await until(lambda: conn.status()["last_error_kind"] == "unauthorized")
    await until(lambda: conn.stopped)
    reports = len(cp.reports)
    for _ in range(20):  # time passes: nothing reconnects, nothing reports
        await asyncio.sleep(0.005)
    assert len(cp.queries) == 1 and len(cp.reports) == reports
    assert conn.status()["connected"] is False
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1 and TOKEN_ENV in errors[0].getMessage()
    assert all(TOKEN not in r.getMessage() for r in caplog.records)


async def test_audit_resent_until_acked_no_duplicates(gateway, cp):
    acks = iter([0, 0])
    first_batch: list[int] = []

    def ack(body: dict[str, Any]) -> int:
        seqs = [r["seq"] for r in body.get("audit", [])]
        try:
            return next(acks)  # the first two reports: nothing acknowledged
        except StopIteration:
            if not first_batch:
                first_batch.extend(seqs)
            cp.acked = max([cp.acked, *seqs])
            return cp.acked

    cp.ack = ack
    host, _conn = await gateway()
    await until(lambda: cp.acked > 0)
    sent = [[r["seq"] for r in rep.get("audit", [])] for rep in cp.reports]
    with_audit = [s for s in sent if s]
    assert with_audit[0] == sorted(with_audit[0])  # ascending
    assert with_audit[0][0] == with_audit[1][0]  # not acknowledged: sent again
    # more audit rows, then: each is sent once after the acknowledgement
    acked = cp.acked
    assert host.audit is not None
    for i in range(3):
        await host.audit.emit(AuditEvent(actor="t", action="admin.read", outcome=f"ok{i}"))
    await until(lambda: cp.acked > acked)
    later = [s for rep in cp.reports[len(sent) :] for s in [r["seq"] for r in rep.get("audit", [])]]
    assert later == sorted(set(later)) and min(later) > acked
    assert host.engine is not None
    stored = await CpStateStore(host.engine).get("audit_acked_seq")
    assert isinstance(stored, int) and stored >= acked


async def test_event_queue_bounded_counts_dropped(gateway, cp):
    from a2agw.ops.bus import GatewayEvent

    cp.report_status = 503  # nothing is delivered (the batch is kept for a retry)
    host, conn = await gateway()
    for i in range(EVENT_QUEUE_MAX + 5):
        host.bus.publish(
            GatewayEvent(kind="task.state", agent_id="alpha", data={"task_id": f"t{i}"})
        )
    status = conn.status()
    assert status["queue"] == EVENT_QUEUE_MAX and status["dropped"] == 5
    await until(lambda: cp.refused >= 2)  # sent, refused, kept
    assert conn.status()["queue"] == EVENT_QUEUE_MAX
    cp.report_status = 200
    await until(lambda: conn.status()["queue"] == 0)
    events = [e for rep in cp.reports if rep.get("events") for e in rep["events"]]
    delivered = [e["data"]["task_id"] for e in events]
    assert all(len(rep.get("events", [])) <= 500 for rep in cp.reports)
    assert delivered[0] == "t5"  # the oldest were dropped
    assert delivered == list(dict.fromkeys(delivered))  # each once
    assert delivered[-1] == f"t{EVENT_QUEUE_MAX + 4}"


# -- configuration -------------------------------------------------------------------------


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "a2agw.yaml"
    p.write_text(text)
    (tmp_path / "policy.yaml").write_text("version: 1\n")
    return p


CP_SECTION = """
control_plane:
  url: https://cp.example.com
  token_env: A2AGW_CP_TOKEN
  manage: [{manage}]
"""


def test_config_conflicts_managed_and_local(tmp_path):
    base = "base_url: http://localhost:8000\n"
    ok = load_config(_write(tmp_path, base + CP_SECTION.format(manage="partners, policy")))
    assert ok.control_plane is not None
    assert ok.control_plane.manage == ["partners", "policy"]
    assert ok.control_plane.report_interval_s == 1.0
    assert ok.control_plane.health_interval_s == 15
    with pytest.raises(ConfigError, match="policy_file") as e:
        load_config(
            _write(
                tmp_path, base + "policy_file: policy.yaml\n" + CP_SECTION.format(manage="policy")
            )
        )
    assert "manage" in str(e.value)
    partners = "partners:\n  - {id: p1, url: 'https://p1.example.com', tier: partner}\n"
    with pytest.raises(ConfigError, match="partners"):
        load_config(_write(tmp_path, base + partners + CP_SECTION.format(manage="partners")))
    # each conflict is only one with its section managed
    load_config(_write(tmp_path, base + partners + CP_SECTION.format(manage="policy")))
    load_config(
        _write(tmp_path, base + "policy_file: policy.yaml\n" + CP_SECTION.format(manage="partners"))
    )
    with pytest.raises(ConfigError, match="token_env"):
        load_config(_write(tmp_path, base + "control_plane:\n  url: https://cp.example.com\n"))
    with pytest.raises(ConfigError, match="manage"):
        load_config(_write(tmp_path, base + CP_SECTION.format(manage="agents")))
    with pytest.raises(ConfigError, match="tls_ref"):
        load_config(
            _write(
                tmp_path,
                base + CP_SECTION.format(manage="policy") + "  tls_ref: missing\n",
            )
        )
    with pytest.raises(ConfigError, match="url"):
        load_config(
            _write(tmp_path, base + CP_SECTION.format(manage="policy").replace("https", "http"))
        )


async def test_state_store_round_trip(db_url):
    """``a2agw_cp_state`` on sqlite and Postgres: set inserts, then replaces."""
    from a2agw.serve.store import create_engine

    engine = await create_engine(db_url)
    try:
        store = CpStateStore(engine)
        await store.initialize()
        await store.initialize()  # idempotent
        assert await store.get("applied_state") is None
        await store.set("audit_acked_seq", 7)
        await store.set("applied_state", {"epoch": "e1", "version": 1, "name": "ü"})
        await store.set("audit_acked_seq", 9)
        assert await store.get("audit_acked_seq") == 9
        assert await store.get("applied_state") == {"epoch": "e1", "version": 1, "name": "ü"}
    finally:
        await engine.dispose()


async def test_stop_is_bounded_and_leaves_no_task(gateway, cp, monkeypatch):
    """A command stuck forever does not hold up shutdown: ``stop`` waits STOP_TIMEOUT_S,
    then cancels it; cancelling ``stop`` itself cancels everything it was waiting for."""
    from a2agw.ops import cp_client

    started = asyncio.Event()

    async def stuck(host, args, actor):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setitem(cp_client.COMMANDS, "task.get", stuck)
    monkeypatch.setattr(cp_client, "STOP_TIMEOUT_S", 0.05)
    cp.script(("command", command("cmd-s", "task.get", {"agent_id": "a", "task_id": "t"})))
    _host, conn = await gateway()
    await asyncio.wait_for(started.wait(), 10)
    [work] = [t for t in conn._work if t.get_name() == "a2agw:cp-cmd-s"]
    await asyncio.wait_for(conn.stop(), 5)
    assert work.cancelled() and conn.stopped and not conn._work

    # cancelled while it waits: nothing it was waiting for keeps running
    started.clear()
    cp.script(("command", command("cmd-t", "task.get", {"agent_id": "a", "task_id": "t"})))
    monkeypatch.setattr(cp_client, "STOP_TIMEOUT_S", 30.0)
    await conn.start()
    await asyncio.wait_for(started.wait(), 10)
    running = [*conn._loops, *conn._work]
    stopping = asyncio.create_task(conn.stop())
    await asyncio.sleep(0.01)
    stopping.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stopping
    await asyncio.wait(running, timeout=5)
    assert all(t.done() for t in running)


async def test_null_managed_policy_is_lockdown(gateway, cp):
    """A desired state that assigns no policy does not open the gateway: it is locked down,
    audited, and healthz says why."""
    from a2agw.ops.cp_client import LOCKDOWN_RULE_ID, NO_POLICY_WARNING

    cp.script(("state", state(1, [partner("p1")])), ("state", state(2, [partner("p1")], None)))
    host, conn = await gateway()
    await until(lambda: len(cp.applied()) >= 2)
    assert cp.applied()[1]["status"] == "applied"
    assert host.policy is not None
    [rule] = host.policy.policy.authz
    assert rule.id == LOCKDOWN_RULE_ID and rule.effect == "deny" and rule.principal == "*"
    assert conn.health()["warning"] == NO_POLICY_WARNING
    assert not conn.waiting_for_state
    updates = await audit_rows(host, "policy.update")
    assert updates[-1]["detail"]["hash"] == policy_hash(host.policy.policy)
    # a policy assigned again lifts it
    cp.push("state", state(3, [partner("p1")]))
    await until(lambda: len(cp.applied()) >= 3)
    assert policy_hash(host.policy.policy) == policy_hash(parse_policy(POLICY))
    assert "warning" not in conn.health()


async def test_null_policy_in_cached_state_restores_lockdown(gateway, cp):
    cp.script(("state", state(1, [partner("p1")], None)))
    _host, conn = await gateway()
    await until(lambda: cp.applied())
    await conn.stop()
    host2, conn2 = await gateway(start=False)
    cp.stream_status = 503
    await host2.startup()
    assert host2.policy is not None and host2.policy.policy.authz[0].effect == "deny"
    assert conn2.no_policy_assigned and conn2.status()["applied_version"] == 1


async def test_stop_posts_a_final_report(gateway, cp):
    from a2agw.ops.bus import GatewayEvent

    host, conn = await gateway()
    await until(lambda: cp.reports)  # the loop is running
    host.bus.publish(GatewayEvent(kind="task.state", agent_id="alpha", data={"task_id": "last"}))
    await conn.stop()  # no await between the publish and the stop: only stop can send it
    sent = [e["data"]["task_id"] for r in cp.reports for e in r.get("events", [])]
    assert "last" in sent


async def test_final_report_is_bounded(gateway, cp, monkeypatch):
    from a2agw.ops import cp_client
    from a2agw.ops.bus import GatewayEvent

    monkeypatch.setattr(cp_client, "FINAL_REPORT_S", 0.05)
    monkeypatch.setattr(cp_client, "STOP_TIMEOUT_S", 0.5)  # a report in flight hangs too
    host, conn = await gateway()
    await until(lambda: cp.reports)
    cp.report_hang = asyncio.Event()  # the control plane stops answering
    host.bus.publish(GatewayEvent(kind="task.state", agent_id="alpha", data={"task_id": "x"}))
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await asyncio.wait_for(conn.stop(), 5)
    assert loop.time() - t0 < 3 and not conn._work and conn.stopped
    cp.report_hang.set()


CARD_URL = "https://partner.example.com/.well-known/agent-card.json"


@pytest.fixture
async def changed_card():
    """Partner card fetches answer a significantly changed card (a refresh quarantines)."""
    import respx

    changed = {**card("P1"), "description": "now does other things"}
    with respx.mock(assert_all_called=False) as router:
        router.get(CARD_URL).respond(200, json=changed)
        async with httpx.AsyncClient() as http:
            yield http


async def test_restart_keeps_local_quarantine_and_reject(gateway, cp, changed_card):
    """A quarantine found here, a partner.reject and the pending card survive a restart (a
    managed registry has no partners file: the local state is in a2agw_cp_state)."""
    from a2agw.ops import actions

    cp.script(("state", state(1, [partner("p1"), partner("p2")])))
    host, conn = await gateway(partner_http=changed_card)
    await until(lambda: conn.status()["applied_version"] == 1)
    assert (await actions.refresh_partner(host, "p1", actor="t"))["result"] == "quarantined"
    await actions.refresh_partner(host, "p2", actor="t")
    await actions.reject_partner(host, "p2", actor="t")
    fetched = host.partners.get("p1").fetched_at
    pending = host.partners.get("p1").pending_card
    await conn.stop()
    cp.stream_status = 503  # the control plane is down for the restart
    host2, _conn2 = await gateway(partner_http=changed_card)
    p1, p2 = host2.partners.get("p1"), host2.partners.get("p2")
    assert p1.status == "quarantined" and p1.pending_card == pending
    assert p1.fetched_at == fetched  # its refresh schedule is kept, not restarted
    assert p2.status == "disabled" and p2.pending_card is None


async def test_readded_after_draining_keeps_local_status(gateway, cp, changed_card):
    from a2agw.ops import actions

    cp.script(("state", state(1, [partner("p1")])))
    host, conn = await gateway(partner_http=changed_card)
    await until(lambda: conn.status()["applied_version"] == 1)
    await actions.refresh_partner(host, "p1", actor="t")
    assert host.partners.get("p1").status == "quarantined"
    assert host.handles is not None
    await host.handles.record("pt-1", "p1", "c1", None, None, "TASK_STATE_WORKING")
    cp.push("state", state(2, []))
    await until(lambda: conn.status()["applied_version"] == 2)
    assert host.partners.get("p1").status == "disabled" and "p1" in host.partners.draining
    cp.push("state", state(3, [partner("p1")]))
    await until(lambda: conn.status()["applied_version"] == 3)
    rec = host.partners.get("p1")
    assert rec.status == "quarantined" and rec.pending_card is not None
    assert "p1" not in host.partners.draining


async def test_backoff_resets_after_a_stream_that_reached_hello(gateway, cp, sleeps):
    """Streams that connect (hello) and then break keep reconnecting at the first back-off
    step, however many times they break."""
    cp.break_streams = True
    _host, _conn = await gateway(report_interval_s=1000.0)
    await until(lambda: len(cp.queries) >= 10)
    backoff = [s for s in sleeps if s != 1000.0]
    assert len(backoff) >= 9
    assert all(0.25 <= s <= 0.5 for s in backoff)


def test_result_cap_is_64k_for_task_get_only():
    from a2agw.ops import cp_client

    big = {"blob": "x" * 20_000}
    assert cp_client._clip(big, "task.get") == big
    assert cp_client._clip(big, "partner.refresh") == {"truncated": True}
    huge = {"blob": "x" * (cp_client.TASK_GET_RESULT_MAX_BYTES + 1)}
    assert cp_client._clip(huge, "task.get") == {"truncated": True}  # the last resort


async def test_task_get_command_answers_the_compact_detail(gateway, cp, monkeypatch):
    from a2agw.ops import actions as actions_mod

    seen: list[dict[str, Any]] = []

    async def detail(host, agent_id, task_id, *, actor, compact=False):
        seen.append({"agent_id": agent_id, "task_id": task_id, "actor": actor, "compact": compact})
        return {"task": {"id": task_id}, "clipped": False}

    monkeypatch.setattr(actions_mod, "task_detail", detail)
    cp.script(("command", command("cmd-g", "task.get", {"agent_id": "alpha", "task_id": "t1"})))
    await gateway()
    await until(lambda: cp.results())
    [result] = cp.results()
    assert result["status"] == "done" and result["result"]["task"] == {"id": "t1"}
    assert seen[0]["compact"] is True and seen[0]["actor"].startswith("cp:")


def test_info_agents_are_bounded(monkeypatch):
    from a2agw.ops import cp_client

    class Spec:
        def __init__(self, i: int) -> None:
            self.id = f"a{i:04d}"
            self.name = "N" * 1000
            self.version = "1"
            self.skills = [type("S", (), {"id": f"s{j}"})() for j in range(200)]

    class Host:
        def __init__(self) -> None:
            self.base_url = "http://t"
            self.specs = {f"a{i:04d}": Spec(i) for i in range(cp_client.INFO_AGENTS_MAX + 5)}

    agents = cp_client.agent_info(Host())  # type: ignore[arg-type]
    assert len(agents) == cp_client.INFO_AGENTS_MAX
    assert all(len(a["name"]) == cp_client.INFO_STRING_MAX for a in agents)
    assert all(len(a["skills"]) == cp_client.INFO_SKILLS_MAX for a in agents)


async def test_a_report_carries_at_most_8_task_get_results(gateway, cp):
    """Large task.get results are spread over reports (REPORT_TASK_GET_MAX each), so a
    burst of them cannot push one report past the control plane's body cap."""
    from a2agw.ops import cp_client

    _host, conn = await gateway(start=False)
    for i in range(12):
        conn._record_result(f"g{i}", "task.get", "done", {"n": i})
        conn._record_result(f"c{i}", "task.cancel", "done", {"n": i})
    first = conn._take_results()
    gets = [r for r in first if r["id"].startswith("g")]
    assert len(gets) == cp_client.REPORT_TASK_GET_MAX == 8
    assert [r["id"] for r in first if r["id"].startswith("c")] == [f"c{i}" for i in range(12)]
    conn._sent_results(first)
    second = conn._take_results()
    assert [r["id"] for r in second] == [f"g{i}" for i in range(8, 12)]
    assert set(second[0]) == {"id", "status", "result"}  # the kind is not reported
    conn._sent_results(second)
    assert conn._take_results() == []
