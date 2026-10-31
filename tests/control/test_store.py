"""Control-plane store: every cp_* table, idempotent concurrent initialize, tokens as digests."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest
from sqlalchemy import inspect, select, text

from a2agw.control.store import (
    API_KEYS,
    COMMANDS,
    EVENTS,
    GATEWAY_TOKENS,
    GATEWAYS,
    ControlStore,
    token_digest,
)
from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine

TABLES = {
    "cp_gateways",
    "cp_gateway_tokens",
    "cp_users",
    "cp_sessions",
    "cp_login_states",
    "cp_api_keys",
    "cp_partners",
    "cp_partner_versions",
    "cp_policies",
    "cp_policy_versions",
    "cp_assignments",
    "cp_desired",
    "cp_commands",
    "cp_events",
    "cp_gateway_audit",
    "cp_health",
}


@pytest.fixture
async def engine(db_url):
    eng = await create_engine(db_url)
    yield eng
    await eng.dispose()


@pytest.fixture
async def audit(engine):
    a = AuditLog(engine, table_name="cp_audit")
    await a.initialize()
    return a


@pytest.fixture
async def store(engine, audit):
    s = ControlStore(engine, audit=audit, clock=lambda: 1000.0)
    await s.initialize()
    return s


async def _tables(engine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda c: inspect(c).get_table_names()))


async def test_tables_exist(store, engine):
    assert TABLES <= await _tables(engine)

    def columns(c, table):
        return {col["name"] for col in inspect(c).get_columns(table)}

    async with engine.connect() as conn:
        gw = await conn.run_sync(columns, "cp_gateways")
        ev = await conn.run_sync(columns, "cp_events")
        cmd = await conn.run_sync(columns, "cp_commands")
        pk = await conn.run_sync(lambda c: inspect(c).get_pk_constraint("cp_partner_versions"))
    assert {"id", "name", "last_seen_at", "last_version_applied", "status", "info_json"} <= gw
    assert {"seq", "gateway_id", "ts", "kind", "agent_id", "trace_id", "data_json"} <= ev
    assert {"status", "result_json", "expires_at", "delivered_at", "finished_at"} <= cmd
    assert pk["constrained_columns"] == ["partner_id", "version"]


async def test_initialize_idempotent_concurrent(db_url):
    engines = [await create_engine(db_url) for _ in range(4)]
    try:
        await asyncio.gather(*(ControlStore(e).initialize() for e in engines))
        await ControlStore(engines[0]).initialize()  # and once more on a ready schema
        assert TABLES <= await _tables(engines[0])
    finally:
        for e in engines:
            await e.dispose()


async def test_create_gateway_stores_only_the_digest(store, engine, audit):
    gw_id, token = await store.create_gateway("east", actor="cli:ops")
    assert len(token) >= 40 and gw_id
    async with engine.connect() as conn:
        gw = (await conn.execute(select(GATEWAYS))).one()._mapping
        tok = (await conn.execute(select(GATEWAY_TOKENS))).one()._mapping
        dump = json.dumps(
            [
                dict(r._mapping)
                for t in (GATEWAYS, GATEWAY_TOKENS)
                for r in (await conn.execute(select(t))).all()
            ]
        )
    assert gw["id"] == gw_id and gw["name"] == "east" and gw["status"] == "active"
    assert gw["created_by"] == "cli:ops" and gw["created_at"] == 1000.0
    assert tok["digest"] == hashlib.sha256(token.encode()).hexdigest() == token_digest(token)
    assert tok["gateway_id"] == gw_id and tok["revoked_at"] is None
    assert token not in dump
    rows, _ = await audit.query({"action": "cp.gateway.create"})
    assert len(rows) == 1 and rows[0]["actor"] == "cli:ops"
    assert rows[0]["detail"]["gateway"] == gw_id and token not in json.dumps(rows)
    with pytest.raises(ValueError, match="already exists"):
        await store.create_gateway("east", actor="cli:ops")


async def test_rotate_gateway_token_revokes_the_old_one(store, engine, audit):
    gw_id, old = await store.create_gateway("west", actor="a")
    new = await store.rotate_gateway_token(gw_id, actor="b")
    assert new != old
    async with engine.connect() as conn:
        rows = {r.digest: r.revoked_at for r in (await conn.execute(select(GATEWAY_TOKENS))).all()}
    assert rows == {token_digest(old): 1000.0, token_digest(new): None}
    audit_rows, _ = await audit.query({"action": "cp.gateway.create"})
    assert audit_rows[0]["detail"]["reason"] == "rotate" and audit_rows[0]["actor"] == "b"
    with pytest.raises(KeyError):
        await store.rotate_gateway_token("nope", actor="b")


async def test_create_api_key(store, engine, audit):
    key_id, key = await store.create_api_key("ci", "operator", actor="cli:ops")
    async with engine.connect() as conn:
        row = (await conn.execute(select(API_KEYS))).one()._mapping
    assert row["id"] == key_id and row["digest"] == token_digest(key) and row["role"] == "operator"
    assert key not in json.dumps(dict(row))
    rows, _ = await audit.query({"action": "cp.apikey.create"})
    assert rows[0]["detail"] == {"key_id": key_id, "role": "operator"}
    with pytest.raises(ValueError, match="role"):
        await store.create_api_key("x", "root", actor="cli:ops")


async def test_expire_and_purge(store, engine):
    day = 86400.0
    async with engine.begin() as conn:
        for cid, status, created, expires in [
            ("c-live", "pending", 990.0, 2000.0),
            ("c-due", "pending", 900.0, 999.0),
            ("c-sent", "delivered", 900.0, 999.0),
            ("c-done", "done", 900.0, 999.0),
            ("c-old", "done", 1000.0 - 8 * day, 0.0),
        ]:
            await conn.execute(
                COMMANDS.insert().values(
                    id=cid,
                    gateway_id="g",
                    kind="task.cancel",
                    args_json="{}",
                    status=status,
                    actor="a",
                    created_at=created,
                    expires_at=expires,
                )
            )
        for ts in (1000.0 - 8 * day, 1000.0 - 6 * day):
            await conn.execute(
                EVENTS.insert().values(gateway_id="g", ts=ts, kind="task.state", data_json="{}")
            )
    assert await store.expire_commands(now=1000.0) == 2
    purged = await store.purge(now=1000.0, events_days=7, commands_days=7)
    assert purged == {"events": 1, "commands": 1}
    async with engine.connect() as conn:
        status = dict((await conn.execute(select(COMMANDS.c.id, COMMANDS.c.status))).all())
        events = (await conn.execute(text("SELECT count(*) FROM cp_events"))).scalar_one()
    assert status == {
        "c-live": "pending",
        "c-due": "expired",
        "c-sent": "expired",
        "c-done": "done",
    }
    assert events == 1
