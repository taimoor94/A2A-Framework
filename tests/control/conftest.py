"""Control-plane test helpers: settings on a fresh database, the app run through its lifespan."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest

from a2agw.control.settings import ControlSettings


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
