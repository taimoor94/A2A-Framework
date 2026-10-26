import os
from typing import Any

import httpx
import pytest
from cascade_support import Env
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from postgres_support import _pg_server, pg_url, pg_url_factory  # noqa: F401 - fixtures
from streaming_asgi import StreamingASGITransport

from a2agw.consult import client as client_mod
from a2agw.serve.agent import AgentSpec
from a2agw.serve.host import AgentHost

# The OpenAI Agents SDK reads this once, on first tracing use: no trace export (and so no
# network) from any test.
os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")

# The OTel global provider can be set once per process; ``_span_exporter`` registers its
# in-memory exporter here so spans never pile up across the session.
INSTALLED_EXPORTERS: list = []


@pytest.fixture(
    params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)],
)
def db_factory(request, tmp_path):
    """Calls return a fresh database URL on each backend: a tmp sqlite file, or a throwaway
    Postgres database (the test is skipped when no PostgreSQL binaries are available)."""
    if request.param == "postgres":
        return request.getfixturevalue("pg_url_factory")
    count = 0

    def make() -> str:
        nonlocal count
        count += 1
        return f"sqlite+aiosqlite:///{tmp_path / f'db{count}.sqlite'}"

    return make


@pytest.fixture
def db_url(db_factory) -> str:
    """One fresh database URL, on sqlite and on Postgres (see ``db_factory``)."""
    return db_factory()


@pytest.fixture(autouse=True)
def _clear_span_exporters():
    for exporter in INSTALLED_EXPORTERS:
        exporter.clear()
    yield


@pytest.fixture(scope="session")
def _span_exporter():
    """One global provider per process: installed once for the whole session."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    INSTALLED_EXPORTERS.append(exporter)
    return exporter


@pytest.fixture
def spans(_span_exporter):
    _span_exporter.clear()
    yield _span_exporter
    _span_exporter.clear()


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setenv("A2AGW_DEV", "1")
    monkeypatch.setattr(client_mod, "POLL_MIN_S", 0.02)
    monkeypatch.setattr(client_mod, "POLL_MAX_S", 0.05)
    monkeypatch.setattr(client_mod, "WAIT_ANY_INTERVAL_S", 0.05)


@pytest.fixture
async def env(tmp_path, fast):
    made: list[Env] = []

    async def _make(
        *specs: AgentSpec,
        db: str = "host.db",
        apps: dict[str, Any] | None = None,
        **host_kwargs: Any,
    ) -> Env:
        transport = StreamingASGITransport(dict(apps or {}))
        partner_hc = httpx.AsyncClient(transport=transport, base_url="http://t")
        host = AgentHost(
            "http://t",
            db_url=f"sqlite+aiosqlite:///{tmp_path / db}",
            partner_http=partner_hc,
            **host_kwargs,
        )
        for s in specs:
            host.add(s)
        # Unless told otherwise, partners are the host's own agents.
        transport.apps.setdefault("t", host.app())
        e = Env(host, partner_hc)
        made.append(e)
        await host.startup()
        return e

    yield _make
    for e in made:
        await e.host.shutdown()
        await e.hc.aclose()
        await e.partner_hc.aclose()
