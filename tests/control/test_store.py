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


async def test_indexes_and_wide_event_seq(store, engine):
    def indexes(c, table):
        return [tuple(i["column_names"]) for i in inspect(c).get_indexes(table)]

    def seq_type(c):
        return next(
            col["type"] for col in inspect(c).get_columns("cp_events") if col["name"] == "seq"
        )

    async with engine.connect() as conn:
        commands = await conn.run_sync(indexes, "cp_commands")
        sessions = await conn.run_sync(indexes, "cp_sessions")
        states = await conn.run_sync(indexes, "cp_login_states")
        seq = await conn.run_sync(seq_type)
    assert ("status", "expires_at") in commands
    assert ("expires_at",) in sessions and ("expires_at",) in states
    # 64-bit on Postgres; sqlite keeps INTEGER (its rowid alias for AUTOINCREMENT)
    assert type(seq).__name__ == ("INTEGER" if engine.dialect.name == "sqlite" else "BIGINT")


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
            ("c-late", "done", 1000.0 - 8 * day, 0.0),  # finished a day ago: kept
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
                    finished_at=1000.0 - day if cid == "c-late" else None,
                )
            )
        for ts in (1000.0 - 8 * day, 1000.0 - 6 * day):
            await conn.execute(
                EVENTS.insert().values(gateway_id="g", ts=ts, kind="task.state", data_json="{}")
            )
    assert await store.expire_commands(now=1000.0) == 2
    purged = await store.purge(now=1000.0, events_days=7, commands_days=7)
    assert purged == {"events": 1, "commands": 1, "login_states": 0, "sessions": 0}
    async with engine.connect() as conn:
        status = dict((await conn.execute(select(COMMANDS.c.id, COMMANDS.c.status))).all())
        events = (await conn.execute(text("SELECT count(*) FROM cp_events"))).scalar_one()
    assert status == {
        "c-live": "pending",
        "c-due": "expired",
        "c-sent": "expired",
        "c-done": "done",
        "c-late": "done",
    }
    assert events == 1


async def test_expire_and_purge_are_batched(store, engine):
    day = 86400.0
    async with engine.begin() as conn:
        for i in range(23):
            await conn.execute(
                COMMANDS.insert().values(
                    id=f"due-{i}",
                    gateway_id="g",
                    kind="k",
                    args_json="{}",
                    status="pending",
                    actor="a",
                    created_at=900.0,
                    expires_at=999.0,
                )
            )
            await conn.execute(
                EVENTS.insert().values(
                    gateway_id="g", ts=1000.0 - 8 * day, kind="k", data_json="{}"
                )
            )
    assert await store.expire_commands(now=1000.0, batch=5) == 23
    purged = await store.purge(now=1000.0 + 9 * day, events_days=7, commands_days=7, batch=5)
    assert purged == {"events": 23, "commands": 23, "login_states": 0, "sessions": 0}
    async with engine.connect() as conn:
        left = [
            (await conn.execute(text(f"SELECT count(*) FROM {t}"))).scalar_one()
            for t in ("cp_commands", "cp_events")
        ]
    assert left == [0, 0]


async def test_purge_expired_login_states_and_sessions(store, engine):
    await store.create_login_state(
        state="s-old", nonce="n", code_verifier="v", next_path="/", now=0.0
    )
    await store.create_login_state(
        state="s-new", nonce="n", code_verifier="v", next_path="/", now=900.0
    )
    await store.upsert_user("oidc:u", email=None, name=None, roles=["viewer"], now=0.0)
    await store.create_session("oidc:u", now=0.0, absolute_s=100, idle_s=50)
    await store.create_session("oidc:u", now=990.0, absolute_s=100, idle_s=50)
    purged = await store.purge(now=1000.0, events_days=7, commands_days=7)
    assert purged == {"events": 0, "commands": 0, "login_states": 1, "sessions": 1}


async def test_login_state_is_single_use(store):
    await store.create_login_state(
        state="st", nonce="the-nonce", code_verifier="ver", next_path="/x", now=1000.0
    )
    assert await store.take_login_state("other", now=1000.0) is None
    got = await store.take_login_state("st", now=1001.0)
    assert got is not None and got.code_verifier == "ver" and got.next_path == "/x"
    assert got.nonce_digest == token_digest("the-nonce")
    assert await store.take_login_state("st", now=1001.0) is None  # deleted at first use
    await store.create_login_state(
        state="late", nonce="n", code_verifier="v", next_path="/", now=1000.0
    )
    assert await store.take_login_state("late", now=1000.0 + 600) is None  # 10 minutes


async def test_sessions_idle_absolute_and_disabled_users(store, engine, audit):
    user = await store.upsert_user("oidc:u", email="u@x", name="U", roles=["viewer"], now=1000.0)
    assert user.disabled is False
    again = await store.upsert_user(
        "oidc:u", email="u@y", name="U2", roles=["admin", "viewer"], now=1001.0
    )
    assert again.roles == ("admin", "viewer") and again.email == "u@y"
    sid, csrf = await store.create_session("oidc:u", now=1000.0, absolute_s=300, idle_s=100)
    s = await store.get_session(sid, now=1070.0, absolute_s=300, idle_s=100)
    assert s is not None and s.user_id == "oidc:u" and s.roles == ("admin", "viewer")
    assert s.csrf_digest == token_digest(csrf)
    # each use within the idle limit keeps it alive (a use touches it when a minute has
    # passed since the last touch), until the absolute limit (1300)
    for t in (1160.0, 1250.0):
        assert await store.get_session(sid, now=t, absolute_s=300, idle_s=100) is not None
    assert await store.get_session(sid, now=1300.0, absolute_s=300, idle_s=100) is None
    sid2, _ = await store.create_session("oidc:u", now=2000.0, absolute_s=300, idle_s=100)
    assert await store.get_session(sid2, now=2101.0, absolute_s=300, idle_s=100) is None  # idle
    sid3, _ = await store.create_session("oidc:u", now=3000.0, absolute_s=300, idle_s=100)
    sid4, _ = await store.create_session(
        "oidc:u", now=3000.0, absolute_s=300, idle_s=100, replace=sid3
    )
    assert await store.get_session(sid3, now=3001.0, absolute_s=300, idle_s=100) is None
    await store.set_user_disabled("oidc:u", True, actor="admin")
    assert await store.get_session(sid4, now=3001.0, absolute_s=300, idle_s=100) is None
    async with engine.connect() as conn:
        left = (await conn.execute(text("SELECT count(*) FROM cp_sessions"))).scalar_one()
    assert left == 0
    disabled = await store.upsert_user("oidc:u", email=None, name=None, roles=[], now=4000.0)
    assert disabled.disabled is True  # a login does not re-enable a disabled user
    rows, _ = await audit.query({"action": "cp.user.update"})
    assert rows[0]["outcome"] == "disabled" and rows[0]["actor"] == "admin"
    with pytest.raises(KeyError):
        await store.set_user_disabled("oidc:nobody", True, actor="admin")


async def test_api_key_lookup_and_revoke(store, audit):
    key_id, key = await store.create_api_key("ci", "security", actor="a")
    found = await store.get_api_key(key, now=1000.0)
    assert found is not None and found.id == key_id and found.role == "security"
    assert found.name == "ci"
    assert await store.get_api_key("nope", now=1000.0) is None
    await store.revoke_api_key(key_id, actor="b")
    assert await store.get_api_key(key, now=1000.0) is None
    rows, _ = await audit.query({"action": "cp.apikey.revoke"})
    assert rows[0]["detail"] == {"key_id": key_id} and rows[0]["actor"] == "b"
    with pytest.raises(KeyError):
        await store.revoke_api_key("ak-nope", actor="b")
