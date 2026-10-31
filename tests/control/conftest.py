"""Control-plane test helpers: settings on a fresh database, the app run through its lifespan."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from a2agw.control.settings import ControlSettings

# oidc_fake (the fake OIDC provider and sign-in helpers) lives next to this file
sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture
def cp_settings(db_url) -> ControlSettings:
    """Settings on a fresh database (sqlite and Postgres, see ``db_url``)."""
    return ControlSettings(base_url="https://cp.example", db_url=db_url)


@pytest.fixture
def sqlite_settings(tmp_path) -> ControlSettings:
    return ControlSettings(
        base_url="https://cp.example", db_url=f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"
    )


@asynccontextmanager
async def running(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    """``app`` with its lifespan started (engine, store, maintenance) and a client for it;
    the lifespan's shutdown (engine disposed) runs on exit."""
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="https://cp.example") as c:
            yield c


@pytest.fixture
def run_app():
    """``async with run_app(app) as client``: see ``running``."""
    return running


# -- sign-in: a fake clock, the fake OIDC provider, settings and apps that use them ----------


class Clock:
    """A fake epoch clock: ``clock()`` reads it, ``clock.advance(s)`` moves it."""

    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def idp(clock, monkeypatch):
    """The fake provider at https://idp.example, mocked with respx; its host resolves to a
    public address (netguard vets it for the ``partner`` tier) and the client secret is in
    the environment."""
    from oidc_fake import CLIENT_SECRET, CLIENT_SECRET_ENV, PUBLIC_IP, FakeIdP

    from a2agw.consult import netguard

    async def resolve(_host: str) -> list[str]:
        return [PUBLIC_IP]

    monkeypatch.setattr(netguard, "_resolve", resolve)
    monkeypatch.setenv(CLIENT_SECRET_ENV, CLIENT_SECRET)
    fake = FakeIdP(clock=clock)
    with respx.mock(assert_all_called=False) as rx:
        fake.routes = fake.install(rx)
        yield fake


@pytest.fixture
async def cp_http():
    """The app's injected outbound client (respx answers for the fake provider)."""
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def make_app(clock, cp_http):
    """``make_app(settings)``: the app with the fake clock and the injected client."""
    from a2agw.control.app import create_app

    def make(settings: ControlSettings) -> Any:
        return create_app(settings, http=cp_http, clock=clock, maintenance_interval_s=3600)

    return make
