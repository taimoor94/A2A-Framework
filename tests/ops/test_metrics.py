"""Gateway metrics: rolling window, percentiles, the admin route and OTel instruments."""

from __future__ import annotations

import hashlib

import httpx
import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from a2agw.core.events import Done
from a2agw.ops.metrics import GatewayMetrics
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.store import TaskIndex, create_engine


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def make(**kw) -> tuple[GatewayMetrics, Clock]:
    clock = Clock()
    return GatewayMetrics(clock=clock, otel=False, **kw), clock


def test_metrics_window_expires_old_samples():
    m, clock = make(window_s=300)
    m.record_partner_call("a", "p", "completed", 10)
    m.record_hop(3)
    clock.t += 200
    m.record_partner_call("a", "p", "completed", 20)
    assert m.snapshot()["partners"]["p"]["calls"] == 2
    clock.t += 150  # the first sample is now 350s old
    snap = m.snapshot()
    assert snap["partners"]["p"]["calls"] == 1
    assert snap["hop_depth"] == {"p50": 0, "max": 0}
    clock.t += 400
    assert m.snapshot()["partners"] == {} and m.snapshot()["edges"] == []


def test_percentiles():
    m, _ = make()
    for ms in range(1, 101):
        m.record_partner_call("a", "p", "completed", float(ms))
    p = m.snapshot()["partners"]["p"]
    assert (p["p50_ms"], p["p95_ms"]) == (50.0, 95.0)
    for d in (1, 2, 3, 4, 9):
        m.record_hop(d)
    assert m.snapshot()["hop_depth"] == {"p50": 3, "max": 9}


def test_error_states_counted():
    m, _ = make()
    for state in ("completed", "failed", "unavailable", "rejected", "working", "input_required"):
        m.record_partner_call("a", "p", state, 1)
    p = m.snapshot()["partners"]["p"]
    assert (p["calls"], p["errors"]) == (6, 3)


def test_bounded_partners_lru():
    m, _ = make(max_partners_tracked=2)
    m.record_partner_call("a", "p1", "completed", 1)
    m.record_partner_call("a", "p2", "completed", 1)
    m.record_partner_call("a", "p1", "completed", 1)  # p1 is now most recent
    m.record_partner_call("a", "p3", "completed", 1)  # evicts p2
    snap = m.snapshot()
    assert set(snap["partners"]) == {"p1", "p3"}
    assert len(snap["edges"]) == 2


def test_ring_is_bounded():
    m, _ = make()
    for _ in range(3000):
        m.record_partner_call("a", "p", "completed", 1)
    assert m.snapshot()["partners"]["p"]["calls"] == 1024


def test_edges_aggregate_agent_to_partner():
    m, _ = make()
    m.record_partner_call("a", "p", "completed", 10)
    m.record_partner_call("a", "p", "failed", 30)
    m.record_partner_call("b", "p", "completed", 5)
    edges = {(e["from"], e["to"]): e for e in m.snapshot()["edges"]}
    assert edges[("a", "p")] == {
        "from": "a",
        "to": "p",
        "calls": 2,
        "errors": 1,
        "p95_ms": 30.0,
    }
    assert edges[("b", "p")]["calls"] == 1
    assert m.snapshot()["partners"]["p"]["calls"] == 3


def test_breaker_and_in_flight_from_partner_stats():
    m, _ = make()
    m.partner_stats = lambda pid: {"breaker_state": "open", "in_flight": 2}
    m.record_partner_call("a", "p", "unavailable", 1)
    p = m.snapshot()["partners"]["p"]
    assert (p["breaker"], p["in_flight"]) == ("open", 2)


def test_otel_instruments_receive_records():
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    m = GatewayMetrics(meter=provider.get_meter("t"))
    m.record_partner_call("a", "p", "failed", 12.5)
    m.record_task_state("a", "TASK_STATE_WORKING")
    found = {}
    for rm in reader.get_metrics_data().resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                found[metric.name] = metric.data.data_points[0]
    assert found["a2agw.partner.calls"].value == 1
    assert dict(found["a2agw.partner.calls"].attributes) == {"partner_id": "p", "state": "failed"}
    assert dict(found["a2agw.task.transitions"].attributes)["state"] == "WORKING"
    assert found["a2agw.partner.duration"].sum == 12.5
    assert found["a2agw.task.transitions"].value == 1


def test_no_principal_or_text_in_snapshot():
    m, _ = make()
    m.record_partner_call("agent-a", "partner-p", "completed", 1)
    m.record_task_state("agent-a", "TASK_STATE_WORKING")
    m.record_hop(1)
    assert set(m.snapshot()) == {"window_s", "partners", "tasks_by_state", "hop_depth", "edges"}
    assert set(m.snapshot()["partners"]["partner-p"]) == {
        "calls", "errors", "p50_ms", "p95_ms", "breaker", "in_flight",
    }  # fmt: skip


# -- index counts ----------------------------------------------------------------------


async def _count_by_state(url: str) -> None:
    engine = await create_engine(url)
    try:
        index = TaskIndex(engine)
        await index.initialize()
        assert await index.count_by_state() == {}
        for tid, agent, state in (
            ("t1", "a", "TASK_STATE_WORKING"),
            ("t2", "a", "TASK_STATE_WORKING"),
            ("t3", "a", "TASK_STATE_COMPLETED"),
            ("t4", "b", "TASK_STATE_FAILED"),
        ):
            await index.upsert(tid, agent, "o", f"c-{tid}", state, None)
        assert await index.count_by_state() == {
            "a": {"WORKING": 2, "COMPLETED": 1},
            "b": {"FAILED": 1},
        }
    finally:
        await engine.dispose()


async def test_count_by_state_sqlite(tmp_path):
    await _count_by_state(f"sqlite+aiosqlite:///{tmp_path / 'i.db'}")


@pytest.mark.postgres
async def test_count_by_state_postgres(pg_url):
    await _count_by_state(pg_url)


# -- admin route -----------------------------------------------------------------------


class Echo:
    durable_sessions = True

    async def run(self, ctx):
        yield Done(text="ok")


def _auth() -> AuthConfig:
    def h(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()

    return AuthConfig(
        api_keys={
            h("admin-secret"): ApiKeyEntry(principal_id="ops", scopes=["a2agw:admin"]),
            h("user-secret"): ApiKeyEntry(principal_id="user", scopes=["other"]),
        }
    )


ADMIN = {"X-API-Key": "admin-secret"}


def _spec() -> AgentSpec:
    return AgentSpec(
        id="alpha",
        name="Alpha",
        description="d",
        version="1",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=Echo(),
    )


async def test_admin_metrics_route_requires_admin(tmp_path):
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", auth=_auth())
    host.add(_spec())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()), base_url="http://t"
    ) as hc:
        url = "/a2agw/admin/metrics"
        assert (await hc.get(url)).status_code == 401
        assert (await hc.get(url, headers={"X-API-Key": "user-secret"})).status_code == 403
        r = await hc.get(url, headers=ADMIN)
        assert r.status_code == 503 and r.json() == {"error": "not started"}
        await host.startup()
        try:
            host.metrics.record_partner_call("alpha", "p", "completed", 5)
            host.metrics.record_hop(2)
            r = await hc.get(url, headers=ADMIN)
            assert r.status_code == 200
            body = r.json()
            assert body["window_s"] == 300
            assert body["partners"]["p"]["calls"] == 1
            assert body["edges"][0]["from"] == "alpha"
            assert body["hop_depth"]["max"] == 2
            assert body["tasks_by_state"] == {}
            audit = (await hc.get("/a2agw/admin/audit?action=admin.read", headers=ADMIN)).json()
            reasons = [e["detail"]["reason"] for e in audit["events"]]
            assert "metrics" in reasons
        finally:
            await host.shutdown()


async def test_executor_and_client_feed_the_metrics(tmp_path):
    from a2a.client import ClientConfig, ClientFactory
    from a2a.types import Message, Part, Role, SendMessageRequest

    from a2agw.consult.results import ToolResult

    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", auth=_auth())
    host.add(_spec())
    await host.startup()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=host.app()), base_url="http://t", headers=ADMIN
        ) as hc:
            c = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
                host.cards["alpha"]
            )
            req = SendMessageRequest(
                message=Message(message_id="m1", role=Role.ROLE_USER, parts=[Part(text="hi")])
            )
            _ = [ev async for ev in c.send_message(req)]
            assert host.client is not None
            host.client._publish(ToolResult(partner="p", state="failed"), 0.0, "alpha")
            body = (await hc.get("/a2agw/admin/metrics")).json()
        assert body["tasks_by_state"] == {"alpha": {"COMPLETED": 1}}
        assert len(host.metrics._hops) == 1
        assert body["edges"][0]["from"] == "alpha" and body["edges"][0]["errors"] == 1
    finally:
        await host.shutdown()


def test_telemetry_metrics_config_defaults_true_and_can_be_disabled():
    from a2agw.config import TelemetryConfig

    assert TelemetryConfig(service_name="x").metrics is True
    assert TelemetryConfig(service_name="x", metrics=False).metrics is False


@pytest.fixture
def fresh_global_meter():
    from opentelemetry import metrics
    from opentelemetry.metrics import _internal

    def reset() -> None:
        _internal._METER_PROVIDER_SET_ONCE._done = False
        _internal._METER_PROVIDER = None
        _internal._PROXY_METER_PROVIDER = _internal._ProxyMeterProvider()

    reset()
    yield metrics
    reset()


@pytest.mark.parametrize("before", [True, False])
def test_embedder_meter_provider_receives_records(fresh_global_meter, tmp_path, before):
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    if before:
        fresh_global_meter.set_meter_provider(provider)
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}")
    if not before:
        fresh_global_meter.set_meter_provider(provider)
    host.metrics.record_partner_call("a", "p", "completed", 3.0)
    names = {
        m.name
        for rm in reader.get_metrics_data().resource_metrics
        for sm in rm.scope_metrics
        for m in sm.metrics
    }
    assert "a2agw.partner.calls" in names
