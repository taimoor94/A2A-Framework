"""Hash-chained audit log: append, query, verify, tamper detection, CLI export/verify."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from a2agw import cli
from a2agw.ops.audit import (
    DETAIL_MAX_CHARS,
    GENESIS_HASH,
    AuditEvent,
    AuditLog,
    canonical_json,
    parse_since,
)
from a2agw.serve.store import create_engine


@pytest.fixture
async def engine(tmp_path):
    eng = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
    yield eng
    await eng.dispose()


@pytest.fixture
async def log(engine):
    a = AuditLog(engine)
    await a.initialize()
    return a


def ev(action="inbound.admit", **kw) -> AuditEvent:
    kw.setdefault("actor", "key:alice")
    kw.setdefault("outcome", "ok")
    return AuditEvent(action=action, **kw)


async def test_append_chains_from_genesis_and_verifies(log, engine):
    s1 = await log.append(ev(agent_id="a", task_id="t1"))
    s2 = await log.append(ev("partner.call", agent_id="a", partner_id="p", outcome="completed"))
    assert s2 > s1
    async with engine.connect() as conn:
        rows = [dict(r._mapping) for r in await conn.execute(text("SELECT * FROM a2agw_audit"))]
    assert rows[0]["prev_hash"] == GENESIS_HASH == "0" * 64
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert all(len(r["hash"]) == 64 for r in rows)
    assert await log.verify_chain() is None


async def test_hash_is_sha256_of_prev_plus_canonical_row(log, engine):
    import hashlib

    await log.append(ev(detail={"reason": "x"}))
    async with engine.connect() as conn:
        row = dict((await conn.execute(text("SELECT * FROM a2agw_audit"))).one()._mapping)
    body = {k: v for k, v in row.items() if k not in ("seq", "hash")}
    expect = hashlib.sha256((row["prev_hash"] + canonical_json(body)).encode()).hexdigest()
    assert row["hash"] == expect
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'


async def test_raw_update_of_middle_row_is_reported(log, engine):
    seqs = [await log.append(ev(task_id=f"t{i}")) for i in range(5)]
    middle = seqs[2]
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE a2agw_audit SET outcome = 'tampered' WHERE seq = :s"), {"s": middle}
        )
    assert await log.verify_chain() == middle


async def test_tampered_hash_chain_link_and_deleted_row_detected(log, engine):
    seqs = [await log.append(ev(task_id=f"t{i}")) for i in range(4)]
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM a2agw_audit WHERE seq = :s"), {"s": seqs[1]})
    # The row after the gap no longer links to its predecessor.
    assert await log.verify_chain() == seqs[2]


async def test_concurrent_appends_keep_chain_consistent(log, engine):
    seqs = await asyncio.gather(*(log.append(ev(task_id=f"t{i}")) for i in range(50)))
    assert len(set(seqs)) == 50
    assert await log.verify_chain() is None
    async with engine.connect() as conn:
        n = (await conn.execute(text("SELECT COUNT(*) FROM a2agw_audit"))).scalar_one()
    assert n == 50


async def test_detail_is_allowlisted_and_truncated(log):
    await log.append(
        ev(
            detail={
                "reason": "r" * 1000,
                "rule": "authz[0]",
                "message": "SECRET-TEXT",
                "text": "SECRET-TEXT",
                "count": 3,
                "state": {"nested": "SECRET-TEXT"},
            }
        )
    )
    rows, _ = await log.query({}, 10, None)
    detail = rows[0]["detail"]
    assert set(detail) == {"reason", "rule", "count"}
    assert len(detail["reason"]) == DETAIL_MAX_CHARS == 256
    assert "SECRET-TEXT" not in json.dumps(rows)


async def test_query_filters_and_cursor(log):
    for i in range(5):
        await log.append(ev("inbound.admit", agent_id="a", task_id=f"t{i}"))
    await log.append(ev("partner.call", agent_id="b", partner_id="p"))
    await log.append(ev("egress.deny", agent_id="a", partner_id="q"))
    rows, cur = await log.query({"action": "inbound.admit"}, 2, None)
    assert [r["task_id"] for r in rows] == ["t4", "t3"]  # newest first
    rows2, cur2 = await log.query({"action": "inbound.admit"}, 2, cur)
    assert [r["task_id"] for r in rows2] == ["t2", "t1"]
    rows3, cur3 = await log.query({"action": "inbound.admit"}, 2, cur2)
    assert [r["task_id"] for r in rows3] == ["t0"] and cur3 is None
    assert [r["action"] for r in (await log.query({"agent": "b"}, 10, None))[0]] == ["partner.call"]
    assert [r["partner_id"] for r in (await log.query({"partner": "q"}, 10, None))[0]] == ["q"]
    with pytest.raises(ValueError):
        await log.query({}, 10, "not-a-cursor")


async def test_query_since(log, engine):
    await log.append(ev(task_id="old", ts=1000.0))
    await log.append(ev(task_id="new", ts=2000.0))
    rows, _ = await log.query({"since": 1500.0}, 10, None)
    assert [r["task_id"] for r in rows] == ["new"]


def test_parse_since():
    assert parse_since("1970-01-01T00:00:10Z") == 10.0
    assert parse_since("1970-01-01T00:00:10") == 10.0  # naive means UTC
    assert parse_since("1970-01-01T01:00:10+01:00") == 10.0
    with pytest.raises(ValueError):
        parse_since("yesterday")


async def test_emit_never_raises_and_counts_errors(log, monkeypatch, caplog):
    async def boom(_ev):
        raise RuntimeError("db down with SECRET")

    monkeypatch.setattr(log, "append", boom)
    with caplog.at_level(logging.WARNING):
        await log.emit(ev())
    assert log.audit_errors == 1
    assert "SECRET" not in caplog.text


async def test_submit_runs_in_background_and_drain_waits(log):
    log.submit(ev(task_id="bg"))
    await log.drain()
    rows, _ = await log.query({}, 10, None)
    assert rows[0]["task_id"] == "bg"


async def test_initialize_is_idempotent(engine):
    a = AuditLog(engine)
    await a.initialize()
    await a.append(ev())
    b = AuditLog(engine)
    await b.initialize()
    await b.append(ev())  # continues the existing chain
    assert await b.verify_chain() is None


# -- CLI ---------------------------------------------------------------------------------


runner = CliRunner()


def _config(tmp_path, db) -> str:
    cfg = tmp_path / "a2agw.yaml"
    cfg.write_text(f"base_url: http://localhost\ndb_url: sqlite+aiosqlite:///{db}\nagents: []\n")
    return str(cfg)


async def _seed(db, n=3, tamper: int | None = None) -> list[int]:
    eng = await create_engine(f"sqlite+aiosqlite:///{db}")
    try:
        a = AuditLog(eng)
        await a.initialize()
        seqs = [
            await a.append(ev("inbound.admit" if i % 2 == 0 else "partner.call", ts=1000.0 + i))
            for i in range(n)
        ]
        if tamper is not None:
            async with eng.begin() as conn:
                await conn.execute(
                    text("UPDATE a2agw_audit SET actor = 'mallory' WHERE seq = :s"),
                    {"s": seqs[tamper]},
                )
        return seqs
    finally:
        await eng.dispose()


def test_cli_export_writes_jsonl(tmp_path):
    db = tmp_path / "gw.db"
    asyncio.run(_seed(db, 4))
    cfg = _config(tmp_path, db)
    r = runner.invoke(cli.app, ["audit", "export", "-c", cfg])
    assert r.exit_code == 0, r.output
    lines = [json.loads(line) for line in r.output.splitlines()]
    assert [x["seq"] for x in lines] == sorted(x["seq"] for x in lines) and len(lines) == 4
    assert {"hash", "prev_hash", "action", "detail"} <= set(lines[0])
    r = runner.invoke(cli.app, ["audit", "export", "-c", cfg, "--action", "partner.call"])
    assert {json.loads(x)["action"] for x in r.output.splitlines()} == {"partner.call"}
    r = runner.invoke(cli.app, ["audit", "export", "-c", cfg, "--since", "1970-01-01T00:16:42Z"])
    assert len(r.output.splitlines()) == 2  # ts 1002 and 1003
    r = runner.invoke(cli.app, ["audit", "export", "-c", cfg, "--since", "soon"])
    assert r.exit_code == 1 and "since" in r.output


def test_cli_verify_ok_and_broken(tmp_path):
    db = tmp_path / "gw.db"
    asyncio.run(_seed(db, 3))
    cfg = _config(tmp_path, db)
    r = runner.invoke(cli.app, ["audit", "verify", "-c", cfg])
    assert r.exit_code == 0 and "ok" in r.output
    db2 = tmp_path / "gw2.db"
    seqs = asyncio.run(_seed(db2, 3, tamper=1))
    r = runner.invoke(cli.app, ["audit", "verify", "-c", _config(tmp_path, db2)])
    assert r.exit_code == 1 and f"seq {seqs[1]}" in r.output


def test_cli_missing_database_is_an_error_and_not_created(tmp_path):
    db = tmp_path / "missing.db"
    r = runner.invoke(cli.app, ["audit", "verify", "-c", _config(tmp_path, db)])
    assert r.exit_code == 1 and "error" in r.output
    assert not db.exists()


@pytest.mark.postgres
async def test_chain_and_tamper_detection_on_postgres(pg_url):
    eng = await create_engine(pg_url)
    try:
        a = AuditLog(eng)
        await a.initialize()
        seqs = await asyncio.gather(*(a.append(ev(task_id=f"t{i}")) for i in range(20)))
        assert await a.verify_chain() is None
        rows, cur = await a.query({"action": "inbound.admit"}, 5, None)
        assert len(rows) == 5 and cur is not None
        middle = sorted(seqs)[10]
        async with eng.begin() as conn:
            await conn.execute(
                text("UPDATE a2agw_audit SET outcome = 'x' WHERE seq = :s"), {"s": middle}
            )
        assert await a.verify_chain() == middle
    finally:
        await eng.dispose()


# -- fix round 1 -------------------------------------------------------------------------


async def test_lone_surrogate_in_principal_id_still_audited():
    """Reviewer probe (surr.py): a lone surrogate must not make the append fail."""
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        a = AuditLog(eng)
        await a.initialize()
        await a.emit(
            AuditEvent(
                actor="jwt:\ud800x",
                action="inbound.admit",
                outcome="admitted",
                detail={"reason": "r\udfffr"},
            )
        )
        assert a.audit_errors == 0
        rows, _ = await a.query({}, 10)
        assert rows[0]["actor"] == "jwt:�x"
        assert rows[0]["detail"]["reason"] == "r�r"
        assert await a.verify_chain() is None
    finally:
        await eng.dispose()


async def test_lock_wait_is_bounded_and_counted(log, monkeypatch):
    from a2agw.ops import audit as audit_mod

    monkeypatch.setattr(audit_mod, "LOCK_TIMEOUT_S", 0.05)
    await log._lock.acquire()  # a stalled writer holds the lock
    try:
        await log.emit(ev())
    finally:
        log._lock.release()
    assert log.audit_errors == 1
    await log.emit(ev())  # recovers once the lock is free
    assert log.audit_errors == 1
    assert len((await log.query({}, 10, None))[0]) == 1


async def test_emit_coalesced_one_row_per_window_with_count(log, monkeypatch):
    from a2agw.ops import audit as audit_mod

    clock = [1000.0]
    monkeypatch.setattr(audit_mod.time, "monotonic", lambda: clock[0])
    deny = ev("authz.deny", actor="anonymous", outcome="forbidden")
    for _ in range(5):
        await log.emit_coalesced(deny, "agent:a")
    await log.emit_coalesced(deny, "agent:b")  # another category has its own window
    rows, _ = await log.query({}, 10, None, ascending=True)
    assert len(rows) == 2 and [r["detail"]["count"] for r in rows] == [0, 0]
    clock[0] += 61  # next window: the row carries the 4 suppressed before it
    await log.emit_coalesced(deny, "agent:a")
    await log.emit_coalesced(deny, "agent:a")  # suppressed again
    await log.flush_coalesced()
    rows, _ = await log.query({}, 10, None, ascending=True)
    counts = [r["detail"]["count"] for r in rows if r["action"] == "authz.deny"]
    assert counts == [0, 0, 4, 0]
    assert len(rows) + sum(counts) == 8  # every event is accounted for
    assert await log.verify_chain() is None
