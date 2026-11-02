"""Operator actions: cancel, answer, reap and per-gateway partner refresh queue a command
for the gateway; the request waits for its result (200, 409 or 202); GET /commands/{id}."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from oidc_fake import audit_rows, signed_in
from sqlalchemy import select
from test_channel import data, started, stream

pytest.importorskip("fastapi")

from a2agw.control import channel
from a2agw.control import operations as ops_mod
from a2agw.control.app import create_app
from a2agw.control.settings import ControlSettings
from a2agw.control.store import COMMANDS, PARTNERS
from a2agw.ops.audit import DETAIL_KEYS


def settings_for(db_url: str) -> ControlSettings:
    return ControlSettings(base_url="https://cp.example", db_url=db_url)


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def key(app: Any, role: str) -> tuple[str, dict[str, str]]:
    key_id, secret = await app.state.store.create_api_key(role, role, actor="t")
    return key_id, bearer(secret)


async def gateway(app: Any, name: str = "east") -> tuple[str, str]:
    return await app.state.store.create_gateway(name, actor="t")


def make(db_url: str, clock, cp_http, sleep: Callable[[float], Awaitable[None]]) -> Any:
    return create_app(
        settings_for(db_url), http=cp_http, clock=clock, maintenance_interval_s=3600, sleep=sleep
    )


def gateway_sleep(
    holder: dict[str, Any], status: str, result: Any
) -> Callable[[float], Awaitable[None]]:
    """A fake sleep: the first time it runs, the "gateway" takes its commands and reports
    ``status`` and ``result`` for each; every call yields briefly."""

    async def sleep(seconds: float) -> None:
        holder.setdefault("slept", []).append(seconds)
        if not holder.get("answered"):
            holder["answered"] = True
            app, gw = holder["app"], holder["gw"]
            for cmd in await channel.take_commands(app.state.store, gw, app.state.clock()):
                holder.setdefault("taken", []).append(cmd)
                await channel.finish_command(
                    app.state.store, gw, cmd.id, status, result, now=app.state.clock()
                )
        await asyncio.sleep(0)

    return sleep


async def silent(_seconds: float) -> None:
    await asyncio.sleep(0)


async def command_rows(app: Any) -> list[Any]:
    async with app.state.engine.connect() as conn:
        return list((await conn.execute(select(COMMANDS).order_by(COMMANDS.c.created_at))).all())


CANCEL = "/api/v1/tasks/{gw}/billing/t1/cancel"


async def test_cancel_done_200_with_result(db_url, cp_http, run_app, clock):
    holder: dict[str, Any] = {}
    app = make(db_url, clock, cp_http, gateway_sleep(holder, "done", {"state": "CANCELED"}))
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        holder.update(app=app, gw=gw)
        r = await c.post(CANCEL.format(gw=gw), headers=op)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "done" and body["result"] == {"state": "CANCELED"}
        [cmd] = holder["taken"]
        assert (cmd.id, cmd.kind, cmd.args) == (
            body["command_id"],
            "task.cancel",
            {"agent_id": "billing", "task_id": "t1"},
        )
        assert cmd.expires_at - cmd.created_at == 60.0


async def test_each_action_is_its_own_command_with_gateway_args(db_url, cp_http, run_app, clock):
    holder: dict[str, Any] = {}
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        async with app.state.engine.begin() as conn:
            await conn.execute(
                PARTNERS.insert().values(
                    id="acme",
                    card_url="https://acme.example/.well-known/agent-card.json",
                    tier="partner",
                    status="approved",
                    current_version=1,
                    created_at=clock(),
                    updated_at=clock(),
                )
            )
        holder.update(app=app, gw=gw)
        first = await c.post(CANCEL.format(gw=gw), headers=op)
        again = await c.post(CANCEL.format(gw=gw), headers=op)
        assert first.json()["command_id"] != again.json()["command_id"]
        await c.post(f"/api/v1/tasks/{gw}/billing/t1/answer", json={"text": "blue"}, headers=op)
        await c.post(
            f"/api/v1/gateways/{gw}/reap",
            json={"agent_id": "billing", "confirm": True, "force": False},
            headers=op,
        )
        await c.post(f"/api/v1/partners/acme/gateways/{gw}/refresh", headers=op)
        rows = await command_rows(app)
    assert [(r.kind, json.loads(r.args_json)) for r in rows] == [
        ("task.cancel", {"agent_id": "billing", "task_id": "t1"}),
        ("task.cancel", {"agent_id": "billing", "task_id": "t1"}),
        ("task.answer", {"agent_id": "billing", "task_id": "t1", "text": "blue"}),
        ("tasks.reap", {"agent_id": "billing", "confirm": True, "force": False}),
        ("partner.refresh", {"id": "acme"}),
    ]


async def test_failed_command_409_with_reason(db_url, cp_http, run_app, clock):
    holder: dict[str, Any] = {}
    failure = {"error": "conflict", "detail": "task is already final"}
    app = make(db_url, clock, cp_http, gateway_sleep(holder, "failed", failure))
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        holder.update(app=app, gw=gw)
        r = await c.post(CANCEL.format(gw=gw), headers=op)
        assert r.status_code == 409
        assert r.json() == {
            "command_id": r.json()["command_id"],
            "status": "failed",
            "result": failure,
        }


async def test_offline_gateway_202_then_expired(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        r = await c.post(CANCEL.format(gw=gw), headers=op)
        assert r.status_code == 202
        assert r.json()["status"] == "pending"
        cid = r.json()["command_id"]
        shown = (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()
        assert shown["status"] == "pending" and shown["finished_at"] is None
        clock.advance(61)
        # expired as soon as its time is up, before the maintenance pass records it
        assert (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()["status"] == "expired"
        assert await channel.take_commands(app.state.store, gw, clock()) == []
        await app.state.maintenance.run_once()
        final = (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()
        assert final["status"] == "expired" and final["finished_at"] is not None


async def test_expired_never_delivered_after_reconnect(db_url, cp_http, run_app, clock):
    async def tick(seconds: float) -> None:  # a stream's sleep moves the fake clock
        clock.advance(seconds)
        await asyncio.sleep(0.002)

    app = make(db_url, clock, cp_http, tick)
    async with started(app) as c:
        _kid, op = await key(app, "operator")
        gw, token = await gateway(app)
        queued = await c.post(CANCEL.format(gw=gw), headers=op)  # nobody is connected
        assert queued.status_code == 202
        cid = queued.json()["command_id"]
        clock.advance(61)  # expired, though no maintenance pass has recorded it yet
        async with stream(c, token) as frames:
            got = await frames.until_keepalive()
            assert all(f.get("event") != "command" for f in got)
        async with stream(c, token, "applied=1") as frames:  # and again after a reconnect
            got = await frames.until_keepalive()
            assert all(f.get("event") != "command" for f in got)
        [row] = await command_rows(app)
        assert row.id == cid and row.status == "pending" and row.delivered_at is None
        # a command still unexpired is delivered once, and not again on a reconnect
        fresh = await c.post(CANCEL.format(gw=gw), headers=op)
        async with stream(c, token) as frames:
            [*_, cmd] = await frames.until(lambda f: f.get("event") == "command")
            assert data(cmd)["id"] == fresh.json()["command_id"]
            assert data(cmd)["expires_at"] - clock() <= 60
        async with stream(c, token, "applied=1") as frames:
            got = await frames.until_keepalive()
            assert all(f.get("event") != "command" for f in got)


async def test_expiry_is_checked_when_marking_delivered(db_url, cp_http, run_app, clock):
    """A poll that read the command as unexpired but marks it after its time is up
    delivers nothing."""
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        await c.post(CANCEL.format(gw=gw), headers=op)
        [row] = await command_rows(app)
        late = row.expires_at + 1
        assert await channel.take_commands(app.state.store, gw, late) == []
        [row] = await command_rows(app)
        assert row.status == "pending"


async def test_answer_size_cap(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    url = "/api/v1/tasks/{gw}/billing/t1/answer"
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)

        async def answer(text: Any) -> Any:
            return await c.post(url.format(gw=gw), json={"text": text}, headers=op)

        assert (await answer("a" * 32768)).status_code == 202  # exactly the cap
        over = await answer("a" * 32769)
        assert over.status_code == 413 and over.json()["error"] == "too_large"
        # bytes, not characters: 16385 two-byte characters are 32770 bytes
        assert (await answer("é" * 16385)).status_code == 413
        assert (await answer("é" * 16384)).status_code == 202
        for bad in ("", "   ", "a\x00b"):
            r = await answer(bad)
            assert r.status_code == 422 and r.json()["fields"] == ["body.text"], bad
        assert (await answer(5)).status_code == 422
        extra = await c.post(url.format(gw=gw), json={"text": "x", "who": "me"}, headers=op)
        assert extra.status_code == 422
        assert len(await command_rows(app)) == 2  # only the two accepted answers were queued


async def test_permissions_viewer_403(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _v, viewer = await key(app, "viewer")
        _s, security = await key(app, "security")
        gw, _tok = await gateway(app)
        posts = [
            (CANCEL.format(gw=gw), None),
            (f"/api/v1/tasks/{gw}/billing/t1/answer", {"text": "x"}),
            (f"/api/v1/gateways/{gw}/reap", {"agent_id": "billing"}),
            (f"/api/v1/partners/acme/gateways/{gw}/refresh", None),
        ]
        for who in (viewer, security):
            for path, body in posts:
                r = await c.post(path, json=body, headers=who)
                assert r.status_code == 403, path
        assert (await c.post(posts[0][0])).status_code == 401
        assert await command_rows(app) == []
        # a viewer reads a command
        _o, op = await key(app, "operator")
        cid = (await c.post(CANCEL.format(gw=gw), headers=op)).json()["command_id"]
        assert (await c.get(f"/api/v1/commands/{cid}", headers=viewer)).status_code == 200
        assert (await c.get(f"/api/v1/commands/{cid}")).status_code == 401


async def test_audited_with_actor(db_url, cp_http, run_app, clock):
    holder: dict[str, Any] = {}
    app = make(db_url, clock, cp_http, gateway_sleep(holder, "done", {"state": "WORKING"}))
    secret_text = "the-secret-answer-text"
    async with run_app(app) as c:
        key_id, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        holder.update(app=app, gw=gw)
        r = await c.post(
            f"/api/v1/tasks/{gw}/billing/t1/answer", json={"text": secret_text}, headers=op
        )
        assert r.status_code == 200, r.text
        await c.post(f"/api/v1/gateways/{gw}/reap", json={"agent_id": "billing"}, headers=op)
        rows = await audit_rows(app, "cp.command")
        everything = json.dumps(await audit_rows(app))
    queued = [x for x in rows if x["outcome"] == "queued"]
    assert [(x["actor"], x["detail"]) for x in queued] == [
        (key_id, {"gateway": gw, "command": "task.answer"}),
        (key_id, {"gateway": gw, "command": "tasks.reap"}),
    ]
    assert all(set(x["detail"]) <= DETAIL_KEYS for x in rows)
    assert secret_text not in everything


async def test_get_command_shows_actor_kind_and_no_principals(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        key_id, op = await key(app, "operator")
        _v, viewer = await key(app, "viewer")
        gw, _tok = await gateway(app)
        store = app.state.store
        cid = (await c.post(CANCEL.format(gw=gw), headers=op)).json()["command_id"]
        shown = (await c.get(f"/api/v1/commands/{cid}", headers=viewer)).json()
        assert shown == {
            "id": cid,
            "gateway_id": gw,
            "kind": "task.cancel",
            "status": "pending",
            "result": None,
            "actor": "key",
            "created_at": clock(),
            "finished_at": None,
        }
        assert key_id not in json.dumps(shown)
        user = await channel.enqueue_command(store, gw, "task.cancel", {}, "oidc:alice")
        assert (await c.get(f"/api/v1/commands/{user}", headers=viewer)).json()["actor"] == (
            "console"
        )
        get = await channel.enqueue_command(store, gw, "task.get", {}, "oidc:alice")
        await channel.take_commands(store, gw, clock())
        detail = {"task": {"id": "t1", "owner": "key:abc", "history": []}, "partner_tasks": []}
        await channel.finish_command(store, gw, get, "done", detail, now=clock())
        shown = (await c.get(f"/api/v1/commands/{get}", headers=viewer)).json()
        assert "owner" not in shown["result"]["task"]
        assert shown["result"]["task"]["owner_kind"] == "api_key"
        assert "key:abc" not in json.dumps(shown)
        assert (await c.get("/api/v1/commands/cmd-nope", headers=viewer)).status_code == 404


async def test_unknown_targets_and_bodies(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        assert (await c.post(CANCEL.format(gw="gw-nope"), headers=op)).status_code == 404
        r = await c.post(f"/api/v1/partners/nope/gateways/{gw}/refresh", headers=op)
        assert r.status_code == 404
        for body in ({}, {"agent_id": "a", "confirm": "yes"}, {"agent_id": "a", "x": 1}):
            r = await c.post(f"/api/v1/gateways/{gw}/reap", json=body, headers=op)
            assert r.status_code == 422, body
        await app.state.store.revoke_gateway(gw, actor="t")
        assert (await c.post(CANCEL.format(gw=gw), headers=op)).status_code == 409
        assert await command_rows(app) == []


async def test_waiters_are_bounded(db_url, cp_http, run_app, clock, monkeypatch):
    """With the waiters saturated a request answers 202 at once; no database connection
    is held while the others wait."""
    monkeypatch.setattr(ops_mod, "OPERATE_WAITERS_MAX", 2)
    release = asyncio.Event()
    sleeping: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeping.append(seconds)
        await release.wait()

    app = make(db_url, clock, cp_http, sleep)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        calls = [asyncio.create_task(c.post(CANCEL.format(gw=gw), headers=op)) for _ in range(5)]
        for _ in range(500):
            if sum(t.done() for t in calls) == 3 and len(sleeping) >= 2:
                break
            await asyncio.sleep(0.01)
        early = [t.result() for t in calls if t.done()]
        assert len(early) == 3 and all(r.status_code == 202 for r in early)
        assert app.state.operations.waiting == 2
        pool = app.state.engine.pool
        if hasattr(pool, "checkedout"):
            assert pool.checkedout() == 0
        release.set()
        responses = await asyncio.gather(*calls)
        assert all(r.status_code == 202 for r in responses)
        assert len({r.json()["command_id"] for r in responses}) == 5  # none shared
        assert app.state.operations.waiting == 0


async def test_delivered_past_expiry_is_never_shown_expired_before_it_finishes(
    db_url, cp_http, run_app, clock
):
    """A delivered command the gateway finishes after its expiry reads delivered, then
    done: a final status never flips."""
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        store = app.state.store
        r = await c.post(CANCEL.format(gw=gw), headers=op)
        cid = r.json()["command_id"]
        clock.advance(59)
        [cmd] = await channel.take_commands(store, gw, clock())
        clock.advance(1.5)  # past expires_at, still delivered
        shown = (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()
        assert shown["status"] == "delivered"
        # an action waiting on it ends 202 delivered, not 409 expired
        assert cmd.expires_at < clock()
        await channel.finish_command(store, gw, cmd.id, "done", {"state": "X"}, now=clock())
        shown = (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()
        assert shown["status"] == "done" and shown["result"] == {"state": "X"}


async def test_maintenance_spares_a_delivered_command_within_the_grace(
    db_url, cp_http, run_app, clock
):
    """The sweep expires a delivered command only ``DELIVERED_GRACE_S`` after its expiry:
    a gateway that ran it and reports done meanwhile is recorded done."""
    from a2agw.control.store import DELIVERED_GRACE_S

    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        store = app.state.store
        cid = (await c.post(CANCEL.format(gw=gw), headers=op)).json()["command_id"]
        [cmd] = await channel.take_commands(store, gw, clock())
        clock.advance(channel.COMMAND_TTL_S + 30)  # past expires_at, inside the grace
        await app.state.maintenance.run_once()
        assert await channel.finish_command(store, gw, cmd.id, "done", {"state": "X"}, now=clock())
        shown = (await c.get(f"/api/v1/commands/{cid}", headers=op)).json()
        assert shown["status"] == "done" and shown["result"] == {"state": "X"}
        # never answered: expired once the grace is over
        cid2 = (await c.post(CANCEL.format(gw=gw), headers=op)).json()["command_id"]
        await channel.take_commands(store, gw, clock())
        clock.advance(channel.COMMAND_TTL_S + DELIVERED_GRACE_S - 1)
        await app.state.maintenance.run_once()
        assert (await channel.get_command(store, cid2)).status == "delivered"
        clock.advance(2)
        await app.state.maintenance.run_once()
        assert (await channel.get_command(store, cid2)).status == "expired"


async def test_action_wait_ending_on_delivered_answers_202_delivered(
    db_url, cp_http, run_app, clock
):
    holder: dict[str, Any] = {}

    async def sleep(_s: float) -> None:
        if not holder.get("done"):
            holder["done"] = True
            app = holder["app"]
            await channel.take_commands(app.state.store, holder["gw"], clock())
            clock.advance(100)  # delivered, then past its expiry before the wait ends
        await asyncio.sleep(0)

    app = make(db_url, clock, cp_http, sleep)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        holder.update(app=app, gw=gw)
        r = await c.post(CANCEL.format(gw=gw), headers=op)
        assert r.status_code == 202 and r.json()["status"] == "delivered"


async def test_session_post_needs_csrf(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        session = await signed_in(app, ["operator"])
        cookie = {"cookie": session["cookie"]}
        gw, _tok = await gateway(app)
        for path, body in (
            (CANCEL.format(gw=gw), None),
            (f"/api/v1/tasks/{gw}/billing/t1/answer", {"text": "x"}),
            (f"/api/v1/gateways/{gw}/reap", {"agent_id": "billing"}),
        ):
            refused = await c.post(path, json=body, headers=cookie)
            assert refused.status_code == 403 and refused.json()["error"] == "csrf", path
        assert await command_rows(app) == []
        ok = await c.post(CANCEL.format(gw=gw), headers=session)
        assert ok.status_code == 202
        assert len(await command_rows(app)) == 1


async def test_ids_in_action_and_detail_paths_are_bounded(db_url, cp_http, run_app, clock):
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        long_id = "a" * 257
        for path in (
            f"/api/v1/tasks/{gw}/{long_id}/t1/cancel",
            f"/api/v1/tasks/{gw}/billing/{long_id}/cancel",
            f"/api/v1/tasks/{gw}/billing/t%01x/cancel",
            f"/api/v1/partners/{long_id}/gateways/{gw}/refresh",
        ):
            r = await c.post(path, headers=op)
            assert r.status_code == 422, (path, r.status_code)
        r = await c.post(f"/api/v1/tasks/{gw}/billing/t%7F/answer", json={"text": "x"}, headers=op)
        assert r.status_code == 422
        r = await c.post(f"/api/v1/gateways/{gw}/reap", json={"agent_id": long_id}, headers=op)
        assert r.status_code == 422
        for path in (f"/api/v1/tasks/{gw}/{long_id}/t1", f"/api/v1/tasks/{gw}/billing/t%0A"):
            assert (await c.get(path, headers=op)).status_code == 422, path
        async with app.state.engine.connect() as conn:
            assert (await conn.execute(select(COMMANDS))).all() == []
        assert (
            await c.post(f"/api/v1/tasks/{gw}/{'a' * 256}/t1/cancel", headers=op)
        ).status_code == 202


async def test_a_full_command_queue_answers_429(db_url, cp_http, run_app, clock, monkeypatch):
    monkeypatch.setattr(channel, "OPEN_COMMANDS_MAX", 2)
    app = make(db_url, clock, cp_http, silent)
    async with run_app(app) as c:
        _kid, op = await key(app, "operator")
        gw, _tok = await gateway(app)
        for task in ("t1", "t2"):
            r = await c.post(f"/api/v1/tasks/{gw}/billing/{task}/cancel", headers=op)
            assert r.status_code == 202
        r = await c.post(f"/api/v1/tasks/{gw}/billing/t3/cancel", headers=op)
        assert r.status_code == 429 and r.json()["error"] == "too_many_requests"
        r = await c.get(f"/api/v1/tasks/{gw}/billing/t4", headers=op)  # task.get too
        assert r.status_code == 429
