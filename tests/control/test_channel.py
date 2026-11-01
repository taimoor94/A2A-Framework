"""The gateway channel (control-plane side): gateway tokens, the /cp/v1/stream SSE stream,
/cp/v1/report ingestion, desired state and its versions, the commands queue."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from oidc_fake import audit_rows
from sqlalchemy import func, select
from streaming_asgi import StreamingASGITransport

pytest.importorskip("fastapi")

from a2agw.control import channel
from a2agw.control.settings import ControlSettings
from a2agw.control.store import (
    ASSIGNMENTS,
    COMMANDS,
    DESIRED,
    EVENTS,
    GATEWAY_AUDIT,
    GATEWAYS,
    HEALTH,
    PARTNER_VERSIONS,
    PARTNERS,
    POLICIES,
    POLICY_VERSIONS,
)

KEEPALIVE_S = 2.0
BASE = "https://cp.example"


def settings_for(db_url: str, **limits: Any) -> ControlSettings:
    return ControlSettings(
        base_url=BASE,
        db_url=db_url,
        limits={"stream_keepalive_s": KEEPALIVE_S, **limits},
    )


@pytest.fixture
def fake_sleep(clock):
    """Each sleep moves the fake clock by its duration and yields briefly for real."""

    async def sleep(seconds: float) -> None:
        clock.advance(seconds)
        await asyncio.sleep(0.002)

    return sleep


@pytest.fixture
def make_cp(clock, cp_http, fake_sleep):
    from a2agw.control.app import create_app

    def make(settings: ControlSettings) -> Any:
        return create_app(
            settings, http=cp_http, clock=clock, sleep=fake_sleep, maintenance_interval_s=3600
        )

    return make


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


class Frames:
    """Reads an SSE response in the background; ``next()`` returns the next frame (a dict
    of fields; ``comment`` for a comment line), or None once the stream has ended."""

    def __init__(self, response: httpx.Response) -> None:
        self.queue: asyncio.Queue[dict[str, str] | None] = asyncio.Queue()
        self.task = asyncio.create_task(self._read(response))

    async def _read(self, response: httpx.Response) -> None:
        frame: dict[str, str] = {}
        try:
            async for line in response.aiter_lines():
                if line == "":
                    if frame:
                        await self.queue.put(frame)
                        frame = {}
                elif line.startswith(":"):
                    frame["comment"] = line[1:].strip()
                else:
                    name, _, value = line.partition(":")
                    frame[name] = value.lstrip()
        except httpx.HTTPError:
            pass
        finally:
            await self.queue.put(None)

    async def next(self, timeout: float = 10.0) -> dict[str, str] | None:
        return await asyncio.wait_for(self.queue.get(), timeout)

    async def until(self, pred: Any, timeout: float = 10.0) -> list[dict[str, str]]:
        """Frames up to and including the first matching one (AssertionError at the end)."""
        out: list[dict[str, str]] = []
        while True:
            frame = await self.next(timeout)
            assert frame is not None, f"stream ended before the frame: {out}"
            out.append(frame)
            if pred(frame):
                return out

    async def until_keepalive(self) -> list[dict[str, str]]:
        return await self.until(lambda f: f.get("comment") == "keepalive")


def data(frame: dict[str, str]) -> Any:
    return json.loads(frame["data"])


@asynccontextmanager
async def started(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    """The app's lifespan and a streaming client for it (closed before the shutdown)."""
    async with app.router.lifespan_context(app):
        transport = StreamingASGITransport({"cp.example": app})
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as c:
            yield c


@asynccontextmanager
async def stream(c: httpx.AsyncClient, token: str, query: str = "applied=0"):
    async with c.stream("GET", f"/cp/v1/stream?{query}", headers=bearer(token)) as r:
        assert r.status_code == 200, r.status_code
        frames = Frames(r)
        try:
            yield frames
        finally:
            frames.task.cancel()


async def report(c: httpx.AsyncClient, token: str, **body: Any) -> httpx.Response:
    return await c.post("/cp/v1/report", json=body, headers=bearer(token))


async def rows(app: Any, table: Any, *where: Any) -> list[Any]:
    async with app.state.engine.connect() as conn:
        return list((await conn.execute(select(table).where(*where))).all())


async def seed_partner(
    app: Any,
    gateway_id: str | None,
    pid: str,
    *,
    status: str = "approved",
    versions: int = 1,
    approved: int | None = 1,
    pin: int | None = None,
) -> None:
    """A partner with ``versions`` card versions, versions 1..``approved`` approved, and
    (when ``gateway_id`` is given) assigned to that gateway (``pin``: ref_version)."""
    now = app.state.clock()
    async with app.state.engine.begin() as conn:
        await conn.execute(
            PARTNERS.insert().values(
                id=pid,
                card_url=f"https://{pid}.example/.well-known/agent-card.json",
                tier="partner",
                credential_ref=f"cred-{pid}",
                tls_ref=None,
                tags_json=json.dumps(["blue"]),
                status=status,
                current_version=versions,
                created_at=now,
                updated_at=now,
            )
        )
        for v in range(1, versions + 1):
            ok = approved is not None and v <= approved
            await conn.execute(
                PARTNER_VERSIONS.insert().values(
                    partner_id=pid,
                    version=v,
                    card_json=json.dumps({"name": pid, "v": v}),
                    card_hash=f"h-{pid}-{v}",
                    fetched_at=now,
                    approved_by="oidc:sec" if ok else None,
                    approved_at=now if ok else None,
                )
            )
        if gateway_id is not None:
            await conn.execute(
                ASSIGNMENTS.insert().values(
                    gateway_id=gateway_id, kind="partner", ref_id=pid, ref_version=pin
                )
            )


async def seed_policy(
    app: Any, gateway_id: str | None, pid: str, versions: int, pin: int | None = None
) -> None:
    now = app.state.clock()
    async with app.state.engine.begin() as conn:
        await conn.execute(POLICIES.insert().values(id=pid, name=pid, created_at=now))
        for v in range(1, versions + 1):
            await conn.execute(
                POLICY_VERSIONS.insert().values(
                    policy_id=pid,
                    version=v,
                    doc_json=json.dumps({"rules": [f"r{v}"]}),
                    doc_hash=f"p{v}",
                    created_by="oidc:sec",
                    created_at=now,
                    comment="",
                )
            )
        if gateway_id is not None:
            await conn.execute(
                ASSIGNMENTS.insert().values(
                    gateway_id=gateway_id, kind="policy", ref_id=pid, ref_version=pin
                )
            )


# -- authentication ------------------------------------------------------------------------


async def test_stream_requires_gateway_token(db_url, make_cp, run_app):
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        store = app.state.store
        _gw, token = await store.create_gateway("gw-a", actor="t")
        revoked_gw, revoked = await store.create_gateway("gw-r", actor="t")
        await store.revoke_gateway(revoked_gw, actor="t")
        _key_id, api_key = await store.create_api_key("k", "admin", actor="t")
        for headers in (
            {},
            bearer("not-a-token"),
            bearer(revoked),
            bearer(api_key),
            {"authorization": f"Basic {token}"},
            {"authorization": "Bearer "},
        ):
            r = await c.get("/cp/v1/stream", headers=headers)
            assert r.status_code == 401, headers
            assert r.json()["error"] == "unauthorized"
            r = await c.post("/cp/v1/report", json={}, headers=headers)
            assert r.status_code == 401, headers
        ok = await c.post("/cp/v1/report", json={}, headers=bearer(token))
        assert ok.status_code == 200, ok.text
        assert token not in ok.text


# -- the stream ----------------------------------------------------------------------------


async def test_hello_then_state_when_behind(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        await seed_partner(app, gw, "p-ok")
        await seed_partner(app, gw, "p-pending", status="pending")
        await seed_partner(app, None, "p-unassigned")
        await seed_policy(app, gw, "pol", versions=2)
        async with stream(c, token) as frames:
            hello = await frames.next()
            assert hello is not None and hello["event"] == "hello"
            assert data(hello) == {"gateway_id": gw, "server_time": pytest.approx(clock.t, abs=5)}
            [*_, state] = await frames.until(lambda f: f.get("event") == "state")
            body = data(state)
            assert set(body) == {"epoch", "version", "hash", "partners", "policy"}
            assert body["epoch"] == app.state.store.epoch
            assert body["version"] == 1 and len(body["hash"]) == 64
            assert body["policy"] == {"rules": ["r2"]}  # not pinned: the latest version
            assert body["partners"] == [
                {
                    "id": "p-ok",
                    "card": {"name": "p-ok", "v": 1},
                    "card_hash": "h-p-ok-1",
                    "tier": "partner",
                    "credential_ref": "cred-p-ok",
                    "tls_ref": None,
                    "tags": ["blue"],
                    "card_url": "https://p-ok.example/.well-known/agent-card.json",
                }
            ]
            # sent once: the next frames are keepalives, not the same state again
            more = await frames.until_keepalive()
            more += await frames.until_keepalive()
            assert all(f.get("event") != "state" for f in more)


async def test_no_state_when_up_to_date(db_url, make_cp):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        await seed_partner(app, gw, "p1")
        desired = await channel.compute_desired(app.state.store, gw)
        query = f"applied={desired.version}&epoch={desired.epoch}"
        async with stream(c, token, query) as frames:
            got = await frames.until_keepalive()
            got += await frames.until_keepalive()
        assert [f.get("event") for f in got if "event" in f] == ["hello"]


@pytest.mark.parametrize(
    "query",
    ["applied=7&epoch=0123456789abcdef0123456789abcdef", "applied=7", "applied=1&epoch="],
    ids=["other epoch, higher version", "no epoch", "empty epoch"],
)
async def test_state_resent_after_store_reset(query, db_url, make_cp):
    """A gateway that applied a version of another store (the control-plane database was
    reset or replaced) is behind whatever its version: the state is sent."""
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        await seed_partner(app, gw, "p1")
        desired = await channel.compute_desired(app.state.store, gw)
        assert desired.version == 1
        async with stream(c, token, query) as frames:
            [*_, state] = await frames.until(lambda f: f.get("event") == "state")
        assert data(state)["version"] == 1 and data(state)["epoch"] == desired.epoch
        assert [p["id"] for p in data(state)["partners"]] == ["p1"]


async def test_state_follows_a_change_while_connected(db_url, make_cp):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        async with stream(c, token) as frames:
            [*_, first] = await frames.until(lambda f: f.get("event") == "state")
            assert data(first)["version"] == 1 and data(first)["partners"] == []
            await seed_partner(app, gw, "p1")
            await channel.mark_dirty(app.state.store, [gw])
            [*_, second] = await frames.until(lambda f: f.get("event") == "state")
            assert data(second)["version"] == 2
            assert [p["id"] for p in data(second)["partners"]] == ["p1"]


async def test_commands_delivered_once_and_marked(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw, token = await store.create_gateway("gw-a", actor="t")
        first = await channel.enqueue_command(
            store, gw, "partner.reload", {"partner_id": "p1"}, "oidc:op"
        )
        async with stream(c, token) as frames:
            [*_, cmd] = await frames.until(lambda f: f.get("event") == "command")
            assert data(cmd) == {
                "id": first,
                "kind": "partner.reload",
                "args": {"partner_id": "p1"},
                "expires_at": pytest.approx(clock.t, abs=60),
                "actor": "oidc:op",
            }
            # one enqueued while the stream is open arrives on it too
            second = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:op")
            [*_, cmd2] = await frames.until(lambda f: f.get("event") == "command")
            assert data(cmd2)["id"] == second
            later = await frames.until_keepalive()
            assert all(f.get("event") != "command" for f in later)
        [r1] = await rows(app, COMMANDS, COMMANDS.c.id == first)
        assert r1.status == "delivered" and r1.delivered_at is not None
        # a new stream does not deliver them again
        async with stream(c, token) as frames:
            got = await frames.until_keepalive()
            got += await frames.until_keepalive()
        assert all(f.get("event") != "command" for f in got)
        assert {r.status for r in await rows(app, COMMANDS)} == {"delivered"}
        queued = await audit_rows(app, "cp.command")
        assert [r["outcome"] for r in queued] == ["queued", "queued"]
        assert queued[0]["detail"] == {"gateway": gw, "command": "partner.reload"}


async def test_expired_command_never_delivered(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw, token = await store.create_gateway("gw-a", actor="t")
        cid = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:op", ttl_s=1)
        clock.advance(2)
        async with stream(c, token) as frames:
            got = await frames.until_keepalive()
            got += await frames.until_keepalive()
        assert all(f.get("event") != "command" for f in got)
        [row] = await rows(app, COMMANDS, COMMANDS.c.id == cid)
        assert row.status == "pending" and row.delivered_at is None
        await app.state.maintenance.run_once()
        [row] = await rows(app, COMMANDS, COMMANDS.c.id == cid)
        assert row.status == "expired"
        done = await channel.wait_command(store, cid, timeout_s=1)
        assert done.status == "expired"


@pytest.mark.parametrize("how", ["rotate", "revoke"])
async def test_revoked_token_closes_stream_within_keepalive(how, db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw, token = await store.create_gateway("gw-a", actor="t")
        async with stream(c, token) as frames:
            await frames.until_keepalive()
            revoked_at = clock.t
            if how == "rotate":
                await store.rotate_gateway_token(gw, actor="t")
            else:
                await store.revoke_gateway(gw, actor="t")
            while (frame := await frames.next()) is not None:
                assert frame.get("event") != "state", frame
            assert clock.t - revoked_at <= KEEPALIVE_S


async def test_token_cannot_read_other_gateway(db_url, make_cp):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw_a, token_a = await store.create_gateway("gw-a", actor="t")
        gw_b, _token_b = await store.create_gateway("gw-b", actor="t")
        await seed_partner(app, gw_b, "p-b")
        await seed_policy(app, gw_b, "pol-b", versions=1)
        cmd_a = await channel.enqueue_command(store, gw_a, "task.cancel", {"n": "a"}, "t")
        cmd_b = await channel.enqueue_command(store, gw_b, "task.cancel", {"n": "b"}, "t")
        # a gateway id in the query is ignored: the token decides
        async with stream(c, token_a, f"applied=0&gateway_id={gw_b}") as frames:
            got = await frames.until_keepalive()
            got += await frames.until_keepalive()
        hello = next(f for f in got if f.get("event") == "hello")
        assert data(hello)["gateway_id"] == gw_a
        [state] = [data(f) for f in got if f.get("event") == "state"]
        assert state["partners"] == [] and state["policy"] is None
        assert [data(f)["id"] for f in got if f.get("event") == "command"] == [cmd_a]
        [b] = await rows(app, COMMANDS, COMMANDS.c.id == cmd_b)
        assert b.status == "pending"
        # and in a report body
        r = await report(
            c,
            token_a,
            gateway_id=gw_b,
            events=[{"kind": "task.state", "agent_id": "x", "data": {}, "ts": 1.0}],
            audit=[{"seq": 1, "action": "inbound.admit"}],
            health={"status": "ok"},
        )
        assert r.status_code == 200, r.text
        assert {e.gateway_id for e in await rows(app, EVENTS)} == {gw_a}
        assert {e.gateway_id for e in await rows(app, GATEWAY_AUDIT)} == {gw_a}
        assert {e.gateway_id for e in await rows(app, HEALTH)} == {gw_a}


async def test_gateway_cannot_post_events_as_other_gateway(db_url, make_cp):
    """Whatever a report names (a gateway id at the top, in events, in audit rows, an
    applied state, the other gateway's command), it lands under the token's gateway only:
    the other gateway's events, audit copies, health, partner states, applied version and
    commands are untouched."""
    from a2agw.control.store import PARTNER_STATES

    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw_a, token_a = await store.create_gateway("gw-a", actor="t")
        gw_b, token_b = await store.create_gateway("gw-b", actor="t")
        cmd_b = await channel.enqueue_command(store, gw_b, "task.cancel", {}, "oidc:op")
        async with stream(c, token_b) as frames:  # delivered to gw-b
            await frames.until(lambda f: f.get("event") == "command")
        desired_b = await channel.compute_desired(store, gw_b)
        [b_before] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw_b)
        r = await report(
            c,
            token_a,
            gateway_id=gw_b,
            events=[
                {
                    "kind": "task.state",
                    "agent_id": "x",
                    "ts": 1.0,
                    "gateway_id": gw_b,
                    "data": {"task_id": "t1", "state": "TASK_STATE_WORKING", "gateway_id": gw_b},
                },
                {
                    "kind": "partner.state",
                    "agent_id": "x",
                    "ts": 1.0,
                    "data": {
                        "partner_id": "p",
                        "status": "quarantined",
                        "event": "quarantined",
                        "pending_hash": "h",
                        "gateway_id": gw_b,
                    },
                },
            ],
            audit=[{"seq": 1, "action": "inbound.admit", "gateway_id": gw_b}],
            health={"status": "ok", "gateway_id": gw_b},
            applied={
                "epoch": store.epoch,
                "version": desired_b.version,
                "hash": desired_b.hash,
                "status": "applied",
            },
            results=[{"id": cmd_b, "status": "done", "result": {"forged": True}}],
        )
        assert r.status_code == 200, r.text
        assert r.json()["dropped"] == 1  # the other gateway's command result
        assert {e.gateway_id for e in await rows(app, EVENTS)} == {gw_a}
        assert {e.gateway_id for e in await rows(app, GATEWAY_AUDIT)} == {gw_a}
        assert {e.gateway_id for e in await rows(app, HEALTH)} == {gw_a}
        assert {s.gateway_id for s in await rows(app, PARTNER_STATES)} == {gw_a}
        [b_after] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw_b)
        assert b_after == b_before  # applied version, epoch, info, last seen
        [cmd] = await rows(app, COMMANDS, COMMANDS.c.id == cmd_b)
        assert cmd.status == "delivered" and cmd.result_json is None
        # gw-b's own token still finishes its command
        r = await report(c, token_b, results=[{"id": cmd_b, "status": "done", "result": {}}])
        assert r.json()["dropped"] == 0


# -- reports -------------------------------------------------------------------------------


async def test_report_idempotent_audit_rows(db_url, make_cp, run_app, clock):
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        audit = [
            {"seq": s, "action": "inbound.admit", "ts": clock.t - 100 + s, "detail": {"n": s}}
            for s in (1, 2, 3)
        ]
        bad = [
            {"action": "no seq"},
            {"seq": "4", "action": "string seq"},
            {"seq": True, "action": "bool seq"},
            {"seq": 4.0, "action": "float seq"},
            "not a row",
        ]
        big = {"seq": 9, "action": "inbound.admit", "detail": {"x": "y" * 9000}}
        for _ in range(2):
            r = await report(c, token, audit=[*audit, *bad, big])
            assert r.status_code == 200, r.text
            assert r.json() == {"acked_audit_seq": 9, "accepted_events": 0, "dropped": 6}
        stored = await rows(app, GATEWAY_AUDIT)
        assert sorted(r.seq for r in stored) == [1, 2, 3]
        for row in stored:
            assert json.loads(row.row_json) == audit[row.seq - 1]  # verbatim
            assert row.ts == clock.t - 100 + row.seq
        # an empty report acks what is stored
        r = await report(c, token)
        assert r.json() == {"acked_audit_seq": 3, "accepted_events": 0, "dropped": 0}


async def test_report_body_cap_413(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url, report_max_bytes=2000))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        body = json.dumps({"health": {"pad": "x" * 3000}}).encode()
        r = await c.post(
            "/cp/v1/report",
            content=body,
            headers={**bearer(token), "content-type": "application/json"},
        )
        assert r.status_code == 413 and r.json()["error"] == "too_large"

        async def chunks():  # no Content-Length: counted while read
            for i in range(0, len(body), 500):
                yield body[i : i + 500]

        r = await c.post(
            "/cp/v1/report",
            content=chunks(),
            headers={**bearer(token), "content-type": "application/json"},
        )
        assert r.status_code == 413 and r.json()["error"] == "too_large"
        assert await rows(app, HEALTH) == []
        small = await report(c, token, health={"pad": "x" * 100})
        assert small.status_code == 200
        bad = await c.post(
            "/cp/v1/report",
            content=b"{not json",
            headers={**bearer(token), "content-type": "application/json"},
        )
        assert bad.status_code == 422
        unknown = await report(c, token, surprise=1)
        assert unknown.status_code == 422 and unknown.json()["fields"] == ["body.surprise"]


async def test_report_item_cap_counts_dropped(db_url, make_cp, run_app):
    app = make_cp(settings_for(db_url, report_max_items=3))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        events = [{"kind": "task.state", "agent_id": "a", "data": {}, "ts": 1.0}] * 5
        audit = [{"seq": s, "action": "inbound.admit"} for s in range(1, 6)]
        r = await report(c, token, events=events, audit=audit)
        assert r.json() == {"acked_audit_seq": 3, "accepted_events": 3, "dropped": 4}
        assert len(await rows(app, EVENTS)) == 3
        assert sorted(r.seq for r in await rows(app, GATEWAY_AUDIT)) == [1, 2, 3]


async def test_unknown_event_kind_dropped(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        events = [
            {"kind": "task.state", "agent_id": "a", "data": {"state": "working"}, "ts": 1.0},
            {"kind": "evil.kind", "agent_id": "a", "data": {}, "ts": 1.0},
            {"kind": 7, "agent_id": "a", "data": {}},
            {"kind": "partner.call", "agent_id": 5, "data": {}},  # agent_id not a string
            {"kind": "partner.call", "agent_id": "a", "data": "not a dict"},
            "not an event",
        ]
        r = await report(c, token, events=events)
        assert r.json() == {"acked_audit_seq": 0, "accepted_events": 1, "dropped": 5}
        assert [e.kind for e in await rows(app, EVENTS)] == ["task.state"]


async def test_report_strings_truncated_and_keys_allowlisted(db_url, make_cp, run_app, clock):
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        now = clock.t
        events = [
            {
                "kind": "task.state",
                "agent_id": "a" * 1000,
                "ts": now + 10 * 86400,  # far future: clamped to now + 5 minutes
                "data": {
                    "task_id": "t" * 1000,
                    "context_id": "c1",
                    "state": "working",
                    "trace_id": "f" * 32,
                    "message": "user text must not be kept",
                    "nested": {"task_id": "x"},
                },
            },
            {
                "kind": "partner.call",
                "agent_id": "a",
                "ts": 5.0,  # far past: clamped to now - 1 day
                "data": {
                    "partner_id": "p1",
                    "task_id": "t1",
                    "state": "completed",
                    "duration_ms": 12.5,
                    "token": "secret",
                    "list": [1, 2],
                },
            },
            {
                "kind": "partner.state",
                "agent_id": "a",
                "ts": "soon",  # not a number: now
                "data": {"partner_id": "p1", "status": "active", "event": "added", "x": 1},
            },
            {
                "kind": "security.denied",
                "agent_id": "a",
                "ts": now,
                "data": {
                    "reason": "r" * 300,
                    "rule": "authz",
                    "principal_kind": "anonymous",
                    "principal": "alice",
                },
                "extra": "top-level keys other than kind, agent_id, data, ts are not kept",
            },
        ]
        r = await report(c, token, events=events)
        assert r.json()["accepted_events"] == 4 and r.json()["dropped"] == 0
        stored = {e.kind: e for e in await rows(app, EVENTS)}
        ts = stored["task.state"]
        assert ts.gateway_id == gw
        assert ts.agent_id == "a" * 256 and ts.ts == now + 300
        assert ts.task_id == "t" * 256 and ts.trace_id == "f" * 32
        assert json.loads(ts.data_json) == {
            "task_id": "t" * 256,
            "context_id": "c1",
            "state": "working",
            "trace_id": "f" * 32,
        }
        call = stored["partner.call"]
        assert call.ts == now - 86400 and call.partner_id == "p1" and call.task_id == "t1"
        assert json.loads(call.data_json) == {
            "partner_id": "p1",
            "task_id": "t1",
            "state": "completed",
            "duration_ms": 12.5,
        }
        state = stored["partner.state"]
        assert state.ts == now
        assert json.loads(state.data_json) == {
            "partner_id": "p1",
            "status": "active",
            "event": "added",
        }
        denied = json.loads(stored["security.denied"].data_json)
        assert denied == {"reason": "r" * 256, "rule": "authz", "principal_kind": "anonymous"}
        dump = json.dumps([list(e) for e in await rows(app, EVENTS)])
        for leaked in ("user text", "secret", "alice", "top-level keys"):
            assert leaked not in dump


async def test_report_health_metrics_and_info(sqlite_settings, make_cp, run_app, clock):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        metrics = {"partners": {"p1": {"calls": 3}}, "edges": [], "window_s": 300}
        r = await report(
            c,
            token,
            health={"status": "ok"},
            metrics=metrics,
            info={"version": "1.4.0", "agents": ["alpha", "beta"], "base_url": "https://g"},
        )
        assert r.status_code == 200, r.text
        [h] = await rows(app, HEALTH)
        assert json.loads(h.health_json) == {"status": "ok"}
        assert json.loads(h.metrics_json) == metrics and h.ts == clock.t
        # a report without health keeps the stored health, a new metrics replaces
        await report(c, token, metrics={"window_s": 60})
        [h] = await rows(app, HEALTH)
        assert json.loads(h.health_json) == {"status": "ok"}
        assert json.loads(h.metrics_json) == {"window_s": 60}
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        # an id list (gateways before agent objects) is stored in the object form
        assert json.loads(g.info_json) == {
            "version": "1.4.0",
            "agents": [
                {"id": a, "name": None, "version": None, "skills": None, "card_url": None}
                for a in ("alpha", "beta")
            ],
            "base_url": "https://g",
        }
        assert g.last_seen_at == clock.t


async def test_report_info_keeps_the_known_numeric_limits(sqlite_settings, make_cp, run_app):
    """A gateway's effective limits (``info.limits``) are kept for the gateway list: known
    names with finite numbers only; anything else is dropped."""
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        limits = {
            "max_concurrent_tasks_per_caller": 32,
            "max_consults_per_task": 16,
            "max_open_sidecar_tasks_per_caller": 64,
            "max_body_bytes": 10485760,
            "max_parts": True,  # not a number
            "surprise": 1,  # not a known limit
        }
        info = {"version": "1", "agents": [], "base_url": "https://g", "limits": limits}
        assert (await report(c, token, info=info)).status_code == 200
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert json.loads(g.info_json)["limits"] == {
            "max_concurrent_tasks_per_caller": 32,
            "max_consults_per_task": 16,
            "max_open_sidecar_tasks_per_caller": 64,
            "max_body_bytes": 10485760,
        }
        r = await c.get("/api/v1/gateways", headers=await _admin(app))
        [shown] = r.json()["gateways"]
        assert shown["info"]["limits"]["max_consults_per_task"] == 16


async def _admin(app: Any) -> dict[str, str]:
    _kid, key = await app.state.store.create_api_key("t", "admin", actor="t")
    return bearer(key)


async def test_result_for_foreign_command_ignored(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        store = app.state.store
        gw_a, token_a = await store.create_gateway("gw-a", actor="t")
        _gw_b, token_b = await store.create_gateway("gw-b", actor="t")
        cid = await channel.enqueue_command(store, gw_a, "task.cancel", {}, "oidc:op")
        # not delivered yet: a result is ignored, even from its own gateway
        r = await report(c, token_a, results=[{"id": cid, "status": "done", "result": {}}])
        assert r.json()["dropped"] == 1
        async with stream(c, token_a) as frames:
            await frames.until(lambda f: f.get("event") == "command")
        # another gateway cannot finish it
        r = await report(c, token_b, results=[{"id": cid, "status": "failed", "result": {}}])
        assert r.json()["dropped"] == 1
        [row] = await rows(app, COMMANDS, COMMANDS.c.id == cid)
        assert row.status == "delivered"
        bad = [{"id": cid, "status": "maybe"}, {"status": "done"}, "x"]
        r = await report(c, token_a, results=bad)
        assert r.json()["dropped"] == 3
        r = await report(
            c, token_a, results=[{"id": cid, "status": "done", "result": {"cancelled": True}}]
        )
        assert r.json()["dropped"] == 0
        done = await channel.wait_command(store, cid, timeout_s=1)
        assert done.status == "done" and done.result == {"cancelled": True}
        assert done.finished_at == clock.t and done.gateway_id == gw_a
        # finished: a second result changes nothing
        r = await report(c, token_a, results=[{"id": cid, "status": "failed", "result": {}}])
        assert r.json()["dropped"] == 1
        assert (await channel.wait_command(store, cid, timeout_s=0)).status == "done"
        outcomes = [r["outcome"] for r in await audit_rows(app, "cp.command")]
        assert outcomes == ["queued", "done"]


async def test_wait_command_times_out_and_unknown(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app):
        store = app.state.store
        gw, _token = await store.create_gateway("gw-a", actor="t")
        cid = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:op")
        row = await channel.wait_command(store, cid, timeout_s=2, sleep=lambda s: asyncio.sleep(0))
        assert row.status == "pending"
        with pytest.raises(KeyError):
            await channel.wait_command(store, "cmd-nope", timeout_s=0)
        with pytest.raises(KeyError):
            await channel.enqueue_command(store, "gw-nope", "task.cancel", {}, "t")
        await store.revoke_gateway(gw, actor="t")
        with pytest.raises(ValueError):
            await channel.enqueue_command(store, gw, "task.cancel", {}, "t")


async def test_rejected_apply_recorded_and_audited(db_url, make_cp, run_app, clock):
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        desired = await channel.compute_desired(app.state.store, gw)
        applied = {
            "epoch": desired.epoch,
            "version": desired.version,
            "hash": desired.hash,
            "status": "applied",
        }
        r = await report(c, token, applied=applied)
        assert r.status_code == 200
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.last_version_applied == desired.version
        assert g.epoch_applied == desired.epoch
        rejected = {
            "epoch": desired.epoch,
            "version": 2,
            "hash": "a" * 64,
            "status": "rejected",
            "reason": "unknown credential_ref " + "x" * 400,
        }
        r = await report(c, token, applied=rejected)
        assert r.status_code == 200
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.last_version_applied == desired.version  # unchanged by a rejection
        info = json.loads(g.info_json)
        assert info["last_rejection"] == {
            "epoch": desired.epoch,
            "version": 2,
            "hash": "a" * 64,
            "reason": ("unknown credential_ref " + "x" * 400)[:256],
            "at": clock.t,
        }
        [applied_row, rejected_row] = await audit_rows(app, "cp.apply")
        assert applied_row["outcome"] == "applied"
        assert applied_row["actor"] == gw
        assert rejected_row["outcome"] == "rejected"
        assert rejected_row["detail"]["gateway"] == gw
        assert rejected_row["detail"]["version"] == 2
        assert rejected_row["detail"]["hash"] == "a" * 64
        assert rejected_row["detail"]["reason"].startswith("unknown credential_ref")
        # a later info report keeps the last rejection
        await report(c, token, info={"version": "1", "agents": [], "base_url": "https://g"})
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert json.loads(g.info_json)["last_rejection"]["version"] == 2
        bad = await report(
            c, token, applied={"epoch": "e", "version": 1, "hash": "h", "status": "maybe"}
        )
        assert bad.status_code == 422
        no_epoch = await report(c, token, applied={"version": 1, "hash": "h", "status": "applied"})
        assert no_epoch.status_code == 422 and no_epoch.json()["fields"] == ["body.applied.epoch"]
        # a store reset: the same version number of another epoch is a change, and audited
        other = {**applied, "epoch": "f" * 32}
        assert (await report(c, token, applied=other)).status_code == 200
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.epoch_applied == "f" * 32 and g.last_version_applied == desired.version
        assert [r["outcome"] for r in await audit_rows(app, "cp.apply")] == [
            "applied",
            "rejected",
            "applied",
        ]


# -- desired state -------------------------------------------------------------------------


async def test_desired_version_bumps_only_on_hash_change(db_url, make_cp, run_app):
    app = make_cp(settings_for(db_url))
    async with run_app(app):
        store = app.state.store
        gw, _token = await store.create_gateway("gw-a", actor="t")
        first = await channel.compute_desired(store, gw)
        again = await channel.compute_desired(store, gw)
        assert first.version == again.version == 1 and first.hash == again.hash
        assert first.partners == [] and first.policy is None
        canonical = json.dumps(
            {"partners": [], "policy": None}, sort_keys=True, separators=(",", ":")
        )
        import hashlib

        assert first.hash == hashlib.sha256(canonical.encode()).hexdigest()

        # an assignment: dirty until the maintenance pass recomputes it
        await seed_partner(app, gw, "p1", versions=3, approved=2)
        await channel.mark_dirty(store, [gw])
        assert await channel.dirty_gateways(store) == [gw]
        await app.state.maintenance.run_once()
        assert await channel.dirty_gateways(store) == []
        [row] = await rows(app, DESIRED, DESIRED.c.gateway_id == gw)
        assert row.version == 2
        doc = json.loads(row.doc_json)
        # version 3 is not approved: the latest approved one is rendered
        assert doc["partners"][0]["card"] == {"name": "p1", "v": 2}

        # marked dirty, nothing changed: the version stays
        await channel.mark_dirty(store, [gw])
        await app.state.maintenance.run_once()
        same = await channel.compute_desired(store, gw)
        assert same.version == 2

        # a pinned policy version, then following the latest
        await seed_policy(app, gw, "pol", versions=3, pin=1)
        pinned = await channel.compute_desired(store, gw)
        assert pinned.version == 3 and pinned.policy == {"rules": ["r1"]}
        async with app.state.engine.begin() as conn:
            await conn.execute(
                ASSIGNMENTS.update()
                .where(ASSIGNMENTS.c.gateway_id == gw)
                .where(ASSIGNMENTS.c.kind == "policy")
                .values(ref_version=None)
            )
        latest = await channel.compute_desired(store, gw)
        assert latest.version == 4 and latest.policy == {"rules": ["r3"]}

        # a quarantined partner leaves the desired state
        async with app.state.engine.begin() as conn:
            await conn.execute(
                PARTNERS.update().where(PARTNERS.c.id == "p1").values(status="quarantined")
            )
        gone = await channel.compute_desired(store, gw)
        assert gone.version == 5 and gone.partners == []

        # a new gateway with no desired row yet is dirty
        gw2, _ = await store.create_gateway("gw-b", actor="t")
        assert await channel.dirty_gateways(store) == [gw2]
        async with app.state.engine.connect() as conn:
            count = (await conn.execute(select(func.count()).select_from(DESIRED))).scalar()
        assert count == 1


async def test_concurrent_compute_bumps_once(db_url, make_cp, run_app):
    app = make_cp(settings_for(db_url))
    async with run_app(app):
        store = app.state.store
        gw, _token = await store.create_gateway("gw-a", actor="t")
        results = await asyncio.gather(*(channel.compute_desired(store, gw) for _ in range(4)))
        assert {r.version for r in results} == {1}
        await seed_partner(app, gw, "p1")
        results = await asyncio.gather(*(channel.compute_desired(store, gw) for _ in range(4)))
        assert {r.version for r in results} == {2}


# -- last_seen_at writes are throttled -------------------------------------------------------


def count_seen_writes(app: Any) -> list[int]:
    """A counter of the UPDATEs that set cp_gateways.last_seen_at."""
    from sqlalchemy import event

    counter = [0]

    def before(_conn, _cursor, statement, *_args):
        normalized = " ".join(statement.split()).lower()
        if normalized.startswith("update cp_gateways set last_seen_at"):
            counter[0] += 1

    event.listen(app.state.engine.sync_engine, "before_cursor_execute", before)
    return counter


async def test_last_seen_written_at_most_every_5s(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        writes = count_seen_writes(app)
        t0 = clock.t
        # reports: the first one writes, the next ones within 5 s do not
        await report(c, token)
        clock.advance(2)
        await report(c, token)
        clock.advance(2.9)
        await report(c, token)
        assert writes[0] == 1
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.last_seen_at == t0
        clock.advance(0.2)  # 5.1 s after the write
        await report(c, token)
        assert writes[0] == 2
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.last_seen_at == clock.t  # 5.1 s after the first write
        # stream polls (every 0.5 s on the fake clock) share the same throttle
        writes[0] = 0
        start = clock.t
        async with stream(c, token) as frames:
            while clock.t - start < 4.5:  # 9 polls or so, all within 5 s of the report
                await frames.until_keepalive()
            assert writes[0] == 0
            while clock.t - start < 10.6:
                await frames.until_keepalive()
        polls = (clock.t - start) / channel.POLL_S
        assert polls >= 20 and 1 <= writes[0] <= 3
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
        assert g.last_seen_at > t0 + 5.2


# -- review fixes ------------------------------------------------------------------------------


async def test_huge_integers_do_not_break_a_report(db_url, make_cp, run_app, clock):
    """A 400-digit integer (valid JSON) is not a finite float: it is dropped from event
    data, and a timestamp made of one counts as missing; the report still succeeds."""
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        huge = 10**400
        events = [
            {"kind": "task.state", "agent_id": "a", "data": {"state": huge, "task_id": "t1"}},
            {"kind": "task.state", "agent_id": "a", "data": {"state": "working"}, "ts": huge},
            {"kind": "partner.call", "agent_id": "a", "data": {"duration_ms": -huge}},
        ]
        audit = [{"seq": 1, "action": "inbound.admit", "ts": huge}]
        r = await report(c, token, events=events, audit=audit, health={"n": huge})
        assert r.status_code == 200, r.text
        assert r.json() == {"acked_audit_seq": 1, "accepted_events": 3, "dropped": 0}
        stored = await rows(app, EVENTS)
        assert [json.loads(e.data_json) for e in stored] == [
            {"task_id": "t1"},
            {"state": "working"},
            {},
        ]
        assert {e.ts for e in stored} == {clock.t}
        [row] = await rows(app, GATEWAY_AUDIT)
        assert row.ts == clock.t and json.loads(row.row_json)["ts"] == huge
        assert channel._finite_number(2**53 - 1) and not channel._finite_number(2**53)


async def test_audit_rows_sorted_before_the_cap(db_url, make_cp, run_app):
    """Rows cut by the item cap are the highest seqs, never acked, whatever the order sent."""
    app = make_cp(settings_for(db_url, report_max_items=3))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        audit = [{"seq": s, "action": "inbound.admit"} for s in (5, 1, 4, 2, 3)]
        r = await report(c, token, audit=[{"action": "no seq"}, *audit])
        assert r.json() == {"acked_audit_seq": 3, "accepted_events": 0, "dropped": 3}
        assert sorted(r.seq for r in await rows(app, GATEWAY_AUDIT)) == [1, 2, 3]
        rest = [a for a in audit if a["seq"] > 3]  # a gateway resends what is not acked
        r = await report(c, token, audit=rest)
        assert r.json()["acked_audit_seq"] == 5
        assert sorted(r.seq for r in await rows(app, GATEWAY_AUDIT)) == [1, 2, 3, 4, 5]


async def test_audit_row_ts_clamped_but_row_kept_verbatim(db_url, make_cp, run_app, clock):
    app = make_cp(settings_for(db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        now = clock.t
        audit = [
            {"seq": 1, "action": "inbound.admit", "ts": now + 10 * 86400},
            {"seq": 2, "action": "inbound.admit", "ts": 5.0},
            {"seq": 3, "action": "inbound.admit", "ts": now - 60},
        ]
        await report(c, token, audit=audit)
        stored = {r.seq: r for r in await rows(app, GATEWAY_AUDIT)}
        assert stored[1].ts == now + 300 and stored[2].ts == now - 86400
        assert stored[3].ts == now - 60
        for seq, item in zip((1, 2, 3), audit, strict=True):
            assert json.loads(stored[seq].row_json) == item


async def test_revoke_between_liveness_and_delivery_delivers_nothing(db_url, make_cp, run_app):
    from a2agw.control.store import token_digest

    app = make_cp(settings_for(db_url))
    async with run_app(app):
        store = app.state.store
        gw, old = await store.create_gateway("gw-a", actor="t")
        cid = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:op")
        # the stream checked its (old) token, then the token is rotated away
        new = await store.rotate_gateway_token(gw, actor="t")
        now = store.now()
        assert await channel.take_commands(store, gw, now, digest=token_digest(old)) == []
        [row] = await rows(app, COMMANDS, COMMANDS.c.id == cid)
        assert row.status == "pending"
        # the new token takes it
        [taken] = await channel.take_commands(store, gw, now, digest=token_digest(new))
        assert taken.id == cid
        # a revoked gateway: nothing either, whatever the token
        cid2 = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:op")
        await store.revoke_gateway(gw, actor="t")
        assert await channel.take_commands(store, gw, now, digest=token_digest(new)) == []
        [row] = await rows(app, COMMANDS, COMMANDS.c.id == cid2)
        assert row.status == "pending"


async def test_rejected_apply_hash_is_cleaned_in_the_audit(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        applied = {"epoch": "e", "version": 1, "hash": "ab\x00cd", "status": "rejected"}
        assert (await report(c, token, applied=applied)).status_code == 200
        [row] = await audit_rows(app, "cp.apply")
        assert row["detail"]["hash"] == "ab�cd"


async def test_background_drain_is_bounded(caplog):
    background = channel.Background(drain_timeout_s=0.2)
    stuck = asyncio.Event()

    async def hangs() -> None:
        await stuck.wait()  # never set

    async def caller() -> None:
        await background.run(hangs())

    waiter = asyncio.create_task(caller())
    await asyncio.sleep(0.01)
    waiter.cancel()  # the client went away; the shielded poll goes on
    loop = asyncio.get_running_loop()
    started = loop.time()
    with caplog.at_level("WARNING", logger="a2agw.control.channel"):
        await asyncio.wait_for(background.drain(), 5)
    assert loop.time() - started < 2
    assert background.pending == 0
    assert any("hangs" in r.getMessage() for r in caplog.records), caplog.text


async def test_shutdown_finishes_with_a_stuck_poll(sqlite_settings, make_cp):
    app = make_cp(settings_for(sqlite_settings.db_url))
    never = asyncio.Event()
    async with app.router.lifespan_context(app):
        app.state.background.drain_timeout_s = 0.2
        poll = asyncio.create_task(app.state.background.run(never.wait()))
        await asyncio.sleep(0.01)
        poll.cancel()
        exit_started = asyncio.get_running_loop().time()
    assert asyncio.get_running_loop().time() - exit_started < 3


async def test_report_info_agent_objects_are_bounded(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        agent = {
            "id": "alpha",
            "name": "A" * 1000,
            "version": "2.0",
            "skills": [f"s{i}" for i in range(500)] + [7],
            "card_url": "https://g/agents/alpha/.well-known/agent-card.json",
        }
        info = {"version": "1", "agents": [agent, "beta"], "base_url": "https://g"}
        r = await report(c, token, info=info)
        assert r.status_code == 200, r.text
        bad = await report(c, token, info={**info, "agents": [{"id": "x", "secret": "y"}]})
        assert bad.status_code == 422
        [g] = await rows(app, GATEWAYS, GATEWAYS.c.id == gw)
    alpha, beta = json.loads(g.info_json)["agents"]
    assert alpha["id"] == "alpha" and len(alpha["name"]) == channel.STRING_MAX
    assert alpha["version"] == "2.0" and alpha["card_url"] == agent["card_url"]
    assert alpha["skills"] == [f"s{i}" for i in range(channel.SKILLS_MAX)]
    assert beta == {"id": "beta", "name": None, "version": None, "skills": None, "card_url": None}


async def test_task_get_results_keep_up_to_64k(db_url, make_cp, clock):
    app = make_cp(settings_for(db_url))
    async with started(app):
        store = app.state.store
        gw, _token = await store.create_gateway("gw-a", actor="t")
        get = await channel.enqueue_command(store, gw, "task.get", {}, "oidc:op")
        other = await channel.enqueue_command(store, gw, "partner.refresh", {}, "oidc:op")
        await channel.take_commands(store, gw, clock())
        big = {"task": {"history": "x" * 30_000}}
        assert await channel.finish_command(store, gw, get, "done", big, now=clock())
        assert await channel.finish_command(store, gw, other, "done", big, now=clock())
        assert (await channel.get_command(store, get)).result == big
        assert (await channel.get_command(store, other)).result == {"truncated": True}
    assert channel.TASK_GET_RESULT_MAX_BYTES == 65536 and channel.RESULT_MAX_BYTES == 8192
    # a report carrying such a result fits the default body cap many times over
    assert ControlSettings(base_url="https://x").limits.report_max_bytes >= 8 * 65536


async def test_partner_call_trace_id_is_kept(sqlite_settings, make_cp, run_app):
    app = make_cp(settings_for(sqlite_settings.db_url))
    async with run_app(app) as c:
        _gw, token = await app.state.store.create_gateway("gw-a", actor="t")
        data = {
            "partner_id": "p1",
            "task_id": "t1",
            "state": "completed",
            "duration_ms": 3,
            "trace_id": "a" * 32,
        }
        r = await report(c, token, events=[{"kind": "partner.call", "agent_id": "a", "data": data}])
        assert r.json()["dropped"] == 0
        [ev] = await rows(app, EVENTS)
    assert ev.trace_id == "a" * 32 and json.loads(ev.data_json)["trace_id"] == "a" * 32
