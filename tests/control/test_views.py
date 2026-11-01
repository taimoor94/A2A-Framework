"""Console read APIs: overview, agents, tasks (list and detail with the cross-gateway
timeline), topology with the policy overlay, audit (both sources, export, verify),
credential names, and keyset pagination."""

from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from oidc_fake import audit_rows, signed_in

pytest.importorskip("fastapi")

from a2agw.control import channel
from a2agw.control import views as views_mod
from a2agw.control.app import create_app
from a2agw.control.settings import ControlSettings
from a2agw.control.store import ASSIGNMENTS, PARTNER_VERSIONS, PARTNERS
from a2agw.ops.audit import DETAIL_KEYS

SUBMITTED = "TASK_STATE_SUBMITTED"
WORKING = "TASK_STATE_WORKING"
COMPLETED = "TASK_STATE_COMPLETED"
FAILED = "TASK_STATE_FAILED"
INPUT = "TASK_STATE_INPUT_REQUIRED"


def settings_for(db_url: str) -> ControlSettings:
    return ControlSettings(base_url="https://cp.example", db_url=db_url)


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def admin_key(app: Any) -> dict[str, str]:
    _id, key = await app.state.store.create_api_key("admin", "admin", actor="t")
    return bearer(key)


async def gateway(app: Any, name: str) -> tuple[str, str]:
    return await app.state.store.create_gateway(name, actor="t")


def task_ev(
    agent: str,
    task_id: str,
    state: str,
    ts: float,
    *,
    trace: str | None = None,
    context: str = "ctx-1",
) -> dict[str, Any]:
    data = {"task_id": task_id, "context_id": context, "state": state, "trace_id": trace}
    return {"kind": "task.state", "agent_id": agent, "ts": ts, "data": data}


def call_ev(
    agent: str,
    partner: str,
    state: str,
    duration: float,
    ts: float,
    task_id: str = "pt-1",
    *,
    trace: str | None = None,
) -> dict[str, Any]:
    data = {
        "partner_id": partner,
        "task_id": task_id,
        "state": state,
        "duration_ms": duration,
        "trace_id": trace,
    }
    return {"kind": "partner.call", "agent_id": agent, "ts": ts, "data": data}


async def report(c, token: str, **body: Any) -> dict[str, Any]:
    r = await c.post("/cp/v1/report", json=body, headers=bearer(token))
    assert r.status_code == 200, r.text
    assert r.json()["dropped"] == 0, r.json()
    return r.json()


async def add_partner(
    app: Any,
    pid: str,
    *,
    status: str = "approved",
    tier: str = "public",
    card: dict[str, Any] | None = None,
    credential_ref: str | None = None,
    tls_ref: str | None = None,
    tags: list[str] | None = None,
) -> None:
    now = app.state.clock()
    card = card or {"name": pid.title(), "version": "1.0", "skills": []}
    async with app.state.engine.begin() as conn:
        await conn.execute(
            PARTNERS.insert().values(
                id=pid,
                card_url=f"https://{pid}.example/card",
                tier=tier,
                credential_ref=credential_ref,
                tls_ref=tls_ref,
                tags_json=json.dumps(tags or []),
                status=status,
                current_version=1 if status == "approved" else 0,
                created_at=now,
                updated_at=now,
            )
        )
        await conn.execute(
            PARTNER_VERSIONS.insert().values(
                partner_id=pid,
                version=1,
                card_json=json.dumps(card),
                card_hash="a" * 64,
                fetched_at=now,
                approved_by="t" if status == "approved" else None,
                approved_at=now if status == "approved" else None,
            )
        )


async def assign_partner(app: Any, gid: str, pid: str) -> None:
    async with app.state.engine.begin() as conn:
        await conn.execute(
            ASSIGNMENTS.insert().values(
                gateway_id=gid, kind="partner", ref_id=pid, ref_version=None
            )
        )


async def pages(
    c, path: str, headers: dict[str, str], params: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Every item of a paginated list, following ``next_cursor``."""
    items: list[dict[str, Any]] = []
    cursor = None
    for _ in range(100):
        q = dict(params or {})
        if cursor is not None:
            q["cursor"] = cursor
        r = await c.get(path, params=q, headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == {"items", "next_cursor"}
        items += body["items"]
        cursor = body["next_cursor"]
        if cursor is None:
            return items
    raise AssertionError("pagination did not end")


# -- overview -------------------------------------------------------------------------------


async def test_overview_buckets_and_alerts(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, t1 = await gateway(app, "east")
        gw2, t2 = await gateway(app, "west")
        await report(c, t2, events=[])  # seen now, then silent
        clock.advance(120)
        now = clock()
        minute = (now // 60) * 60
        events = [
            # new tasks: two in the current minute (one submitted twice), one 5 minutes ago
            task_ev("billing", "a", SUBMITTED, now - 1),
            task_ev("billing", "a", SUBMITTED, now - 0.5),
            task_ev("billing", "b", SUBMITTED, minute + 0.1),
            task_ev("billing", "c", SUBMITTED, minute - 5 * 60 + 1),
            # ended in the last 15 minutes: 3 completed, 1 failed; an older failure is out
            task_ev("billing", "a", COMPLETED, now - 10),
            task_ev("billing", "b", COMPLETED, now - 60),
            task_ev("billing", "c", COMPLETED, now - 600),
            task_ev("billing", "d", FAILED, now - 700),
            task_ev("billing", "e", FAILED, now - 20 * 60),
            task_ev("billing", "f", WORKING, now - 5),  # not an end
            call_ev("billing", "p1", "completed", 10, now - 30),
            call_ev("billing", "p1", "completed", 20, now - 30),
            call_ev("billing", "p1", "failed", 40, now - 30),
            call_ev("billing", "p1", "completed", 30, now - 30),
            call_ev("billing", "p2", "completed", 5, now - 30),
            call_ev("billing", "p2", "completed", 5, now - 2 * 3600),  # out of the window
            {
                "kind": "partner.state",
                "agent_id": "host",
                "ts": now - 40,
                "data": {"partner_id": "p3", "status": "quarantined", "event": "quarantined"},
            },
        ]
        metrics = {
            "window_s": 300,
            "partners": {
                "p1": {"calls": 4, "errors": 1, "breaker": "open"},
                "p2": {"calls": 1, "errors": 0, "breaker": "closed"},
            },
        }
        applied = {
            "epoch": app.state.store.epoch,
            "version": 3,
            "hash": "f" * 64,
            "status": "rejected",
            "reason": "partner p9: bad card",
        }
        await report(
            c, t1, events=events, metrics=metrics, health={"status": "ok"}, applied=applied
        )
        r = await c.get("/api/v1/overview", headers=admin)
        assert r.status_code == 200, r.text
        body = r.json()

    assert body["gateways"] == {"total": 2, "connected": 1, "stale": 1}
    buckets = body["tasks_per_min"]
    assert len(buckets) == 60
    assert [b["ts"] for b in buckets] == [minute - 60 * (59 - i) for i in range(60)]
    assert buckets[-1]["count"] == 2  # tasks a and b (a counted once)
    assert buckets[-6]["count"] == 1
    assert sum(b["count"] for b in buckets) == 3
    assert body["error_rate"] == pytest.approx(0.25)
    p1, p2 = body["top_partners"]
    assert p1 == {"partner_id": "p1", "calls": 4, "errors": 1, "p95_ms": 40.0}
    assert p2 == {"partner_id": "p2", "calls": 1, "errors": 0, "p95_ms": 5.0}
    alerts = {(a["kind"], a.get("gateway_id"), a.get("partner_id")): a for a in body["alerts"]}
    assert set(alerts) == {
        ("gateway_disconnected", gw2, None),
        ("breaker_open", gw1, "p1"),
        ("partner_quarantined", gw1, "p3"),
        ("desired_rejected", gw1, None),
    }
    assert alerts[("gateway_disconnected", gw2, None)]["since"] == pytest.approx(now - 120)
    assert alerts[("partner_quarantined", gw1, "p3")]["since"] == pytest.approx(now - 40)
    assert alerts[("desired_rejected", gw1, None)]["since"] == pytest.approx(now)


async def test_overview_rejection_alert_clears_once_a_newer_version_applies(
    db_url, make_app, run_app
):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        _gw, token = await gateway(app, "east")
        epoch = app.state.store.epoch
        rejected = {"epoch": epoch, "version": 2, "hash": "f" * 64, "status": "rejected"}
        await report(c, token, applied=rejected)
        assert [
            a["kind"] for a in (await c.get("/api/v1/overview", headers=admin)).json()["alerts"]
        ] == ["desired_rejected"]
        ok = {"epoch": epoch, "version": 3, "hash": "e" * 64, "status": "applied"}
        await report(c, token, applied=ok)
        body = (await c.get("/api/v1/overview", headers=admin)).json()
    assert body["alerts"] == []
    assert body["error_rate"] == 0.0 and body["top_partners"] == []


# -- agents ---------------------------------------------------------------------------------


async def test_agents_merge_hosted_and_partners(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, t1 = await gateway(app, "east")
        info = {"version": "0.4.0", "agents": ["support", "billing"], "base_url": "https://e.x/"}
        metrics = {"partners": {"p1": {"calls": 3, "errors": 1, "breaker": "open"}}}
        await report(c, t1, info=info, health={"status": "ok"}, metrics=metrics)
        card = {
            "name": "Payments",
            "version": "2.1",
            "skills": [{"id": "pay", "name": "Pay"}, {"id": "refund", "name": "Refund"}],
        }
        gw2, t2 = await gateway(app, "west")
        objects = {
            "version": "0.5.0",
            "agents": [
                {
                    "id": "orders",
                    "name": "Orders",
                    "version": "3.1",
                    "skills": ["place", "track"],
                    "card_url": "https://w.x/agents/orders/.well-known/agent-card.json",
                }
            ],
            "base_url": "https://w.x",
        }
        await report(c, t2, info=objects, health={"status": "ok"})
        await add_partner(app, "p1", card=card, tier="partner")
        await add_partner(app, "p2", status="pending")
        everything = await pages(c, "/api/v1/agents", admin)
        hosted = await pages(c, "/api/v1/agents", admin, {"kind": "hosted"})
        partners = await pages(c, "/api/v1/agents", admin, {"kind": "partner"})
        bad = await c.get("/api/v1/agents", params={"kind": "robot"}, headers=admin)

    assert bad.status_code == 422 and bad.json()["fields"] == ["query.kind"]
    assert everything == hosted + partners
    assert sorted((a["gateway_id"], a["id"]) for a in hosted) == sorted(
        [(gw1, "billing"), (gw1, "support"), (gw2, "orders")]
    )
    billing = next(a for a in hosted if a["id"] == "billing")
    orders = next(a for a in hosted if a["id"] == "orders")
    assert orders == {
        "kind": "hosted",
        "id": "orders",
        "name": "Orders",
        "version": "3.1",
        "skills": ["place", "track"],
        "card_url": "https://w.x/agents/orders/.well-known/agent-card.json",
        "gateway_id": gw2,
        "health": "ok",
        "tier": None,
        "status": None,
    }
    assert billing == {
        "kind": "hosted",
        "id": "billing",
        "name": None,
        "version": None,
        "skills": None,
        "card_url": "https://e.x/agents/billing/.well-known/agent-card.json",
        "gateway_id": gw1,
        "health": "ok",
        "tier": None,
        "status": None,
    }
    p1, p2 = partners
    assert p1 == {
        "kind": "partner",
        "id": "p1",
        "name": "Payments",
        "version": "2.1",
        "skills": ["pay", "refund"],
        "card_url": "https://p1.example/card",
        "gateway_id": None,
        "health": "open",
        "tier": "partner",
        "status": "approved",
    }
    assert p2["status"] == "pending" and p2["health"] is None


# -- tasks ----------------------------------------------------------------------------------


async def test_tasks_latest_state_per_task_and_filters(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, t1 = await gateway(app, "east")
        gw2, t2 = await gateway(app, "west")
        now = clock()
        await report(
            c,
            t1,
            events=[
                task_ev("billing", "task-a1", SUBMITTED, now - 50),
                task_ev("billing", "task-a1", WORKING, now - 40, trace="tr1"),
                task_ev("billing", "task-a1", COMPLETED, now - 30, context="ctx-a"),
                task_ev("support", "task-b2", SUBMITTED, now - 45),
                task_ev("support", "task-b2", INPUT, now - 20, trace="tr2"),
            ],
        )
        await report(c, t2, events=[task_ev("billing", "x_3", FAILED, now - 10)])

        async def ids(**params: Any) -> list[str]:
            return [t["task_id"] for t in await pages(c, "/api/v1/tasks", admin, params)]

        items = await pages(c, "/api/v1/tasks", admin)
        by_gateway = await ids(gateway_id=gw2)
        by_agent = await ids(agent_id="support")
        by_state = await ids(state=COMPLETED)
        by_trace = await ids(trace_id="tr1")
        by_since = await ids(since=str(now - 25))
        by_iso_since = await ids(since="2023-11-14T22:12:00Z")  # 1699999920
        by_prefix = await ids(q="task-a")
        wildcard = await ids(q="x_")
        not_wildcard = await ids(q="task_")  # "_" is literal, not a LIKE wildcard
        bad = await c.get("/api/v1/tasks", params={"since": "yesterday"}, headers=admin)

    assert [(t["gateway_id"], t["task_id"], t["state"]) for t in items] == [
        (gw2, "x_3", FAILED),
        (gw1, "task-b2", INPUT),
        (gw1, "task-a1", COMPLETED),
    ]
    a1 = items[2]
    assert a1 == {
        "gateway_id": gw1,
        "agent_id": "billing",
        "task_id": "task-a1",
        "context_id": "ctx-a",
        "state": COMPLETED,
        "updated_at": pytest.approx(now - 30),
        "trace_id": "tr1",  # the latest trace the task reported
    }
    assert items[0]["trace_id"] is None
    assert by_gateway == ["x_3"]
    assert by_agent == ["task-b2"]
    assert by_state == ["task-a1"]
    assert by_trace == ["task-a1"]
    assert by_since == ["x_3", "task-b2"]
    assert by_iso_since == ["x_3", "task-b2", "task-a1"]
    assert by_prefix == ["task-a1"]
    assert wildcard == ["x_3"] and not_wildcard == []
    assert bad.status_code == 422 and bad.json()["fields"] == ["query.since"]


def answering_sleep(holder: dict[str, Any], answer: Callable[[Any], Awaitable[None]]):
    """A fake sleep: the first time it is called, the "gateway" takes its commands and
    answers them with ``answer``; every call is recorded and yields briefly."""

    async def sleep(seconds: float) -> None:
        holder.setdefault("slept", []).append(seconds)
        if not holder.get("answered"):
            holder["answered"] = True
            await answer(holder["app"])
        await asyncio.sleep(0)

    return sleep


def detail_app(db_url: str, clock, cp_http, sleep) -> Any:
    return create_app(
        settings_for(db_url), http=cp_http, clock=clock, maintenance_interval_s=3600, sleep=sleep
    )


async def test_task_detail_via_command_and_timeline_across_gateways(
    db_url, cp_http, run_app, clock
):
    holder: dict[str, Any] = {}
    detail = {
        "task": {
            "id": "t1",
            "context_id": "ctx-1",
            "state": WORKING,
            "owner": "key:alice",
            "updated_at": 5.0,
            "trace_id": "tr1",
            "status_message": None,
            "history": [{"role": "user", "parts": [{"text": "hi"}]}],
            "artifacts": [],
        },
        "partner_tasks": [
            {
                "partner_id": "p1",
                "task_id": "pt-1",
                "context_id": "pc-1",
                "inbound_task_id": "t1",
                "origin": "o-1",
                "state": "TASK_STATE_COMPLETED",
                "created_at": 4.0,
                "caller_id": "key:alice",
                "owner": "key:alice",
                "end_reason": None,
                "cancel_attempts": 0,
            }
        ],
        "pending_prompt": None,
    }

    async def answer(app: Any) -> None:
        store = app.state.store
        gid = holder["gw1"]
        for cmd in await channel.take_commands(store, gid, app.state.clock()):
            holder.setdefault("commands", []).append(cmd)
            if cmd.args.get("task_id") == "t1":
                await channel.finish_command(store, gid, cmd.id, "done", detail, now=clock())
            else:
                result = {"error": "not_found"}
                await channel.finish_command(store, gid, cmd.id, "failed", result, now=clock())

    app = detail_app(db_url, clock, cp_http, answering_sleep(holder, answer))
    holder["app"] = app
    async with run_app(app) as c:
        viewer_id, key = await app.state.store.create_api_key("ops", "viewer", actor="t")
        viewer = bearer(key)
        gw1, t1 = await gateway(app, "east")
        gw2, t2 = await gateway(app, "west")
        holder["gw1"] = gw1
        now = clock()
        await report(
            c,
            t1,
            events=[
                task_ev("billing", "t1", SUBMITTED, now - 50),  # before its span: no trace
                task_ev("billing", "t1", WORKING, now - 49, trace="tr1"),
                call_ev("billing", "p1", "completed", 12.5, now - 45, task_id="pt-1"),
                call_ev("billing", "p1", "completed", 99, now - 44, task_id="pt-other"),
                task_ev("billing", "t9", WORKING, now - 43, trace="tr9"),  # unrelated
            ],
        )
        # the partner's gateway: its task in the same trace
        await report(
            c, t2, events=[task_ev("payments", "remote-1", WORKING, now - 47, trace="tr1")]
        )
        r = await c.get(f"/api/v1/tasks/{gw1}/billing/t1", headers=viewer)
        holder["answered"] = False
        missing = await c.get(f"/api/v1/tasks/{gw1}/billing/nope", headers=viewer)
        unknown_gw = await c.get("/api/v1/tasks/gw-nope/billing/t1", headers=viewer)

    assert r.status_code == 200, r.text
    body = r.json()
    task = body["task"]
    assert "owner" not in task and task["owner_kind"] == "api_key"  # never a principal id
    assert task["history"] == detail["task"]["history"]
    [handle] = body["partner_tasks"]
    assert handle == {
        "partner_id": "p1",
        "task_id": "pt-1",
        "context_id": "pc-1",
        "state": "TASK_STATE_COMPLETED",
        "created_at": 4.0,
        "end_reason": None,
    }
    timeline = body["timeline"]
    assert [(e["gateway_id"], e["kind"], e["task_id"], e["state"]) for e in timeline] == [
        (gw1, "task.state", "t1", SUBMITTED),
        (gw1, "task.state", "t1", WORKING),
        (gw2, "task.state", "remote-1", WORKING),
        (gw1, "partner.call", "pt-1", "completed"),
    ]
    call = timeline[-1]
    assert call["partner_id"] == "p1" and call["duration_ms"] == 12.5
    assert call["agent_id"] == "billing" and call["ts"] == pytest.approx(now - 45)
    [cmd, _] = holder["commands"]
    assert cmd.kind == "task.get" and cmd.args == {"agent_id": "billing", "task_id": "t1"}
    assert cmd.actor == viewer_id
    assert missing.status_code == 404 and missing.json()["error"] == "not_found"
    assert unknown_gw.status_code == 404


async def test_task_detail_202_when_gateway_slow(db_url, cp_http, run_app, clock):
    holder: dict[str, Any] = {}

    async def silent(_app: Any) -> None:
        return None

    app = detail_app(db_url, clock, cp_http, answering_sleep(holder, silent))
    holder["app"] = app
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, t1 = await gateway(app, "east")
        now = clock()
        await report(
            c,
            t1,
            events=[
                task_ev("billing", "t1", WORKING, now - 5, trace="tr1"),
                call_ev("billing", "p1", "completed", 4, now - 4, task_id="pt-9", trace="tr1"),
            ],
        )
        r = await c.get(f"/api/v1/tasks/{gw1}/billing/t1", headers=admin)
        assert r.status_code == 202, r.text
        body = r.json()
        command = await channel.get_command(app.state.store, body["command_id"])

    assert set(body) == {"command_id", "timeline"}
    # the partner call carries the turn's trace: it is in the timeline without the detail
    assert [(e["kind"], e["task_id"], e["state"]) for e in body["timeline"]] == [
        ("task.state", "t1", WORKING),
        ("partner.call", "pt-9", "completed"),
    ]
    assert sum(holder["slept"]) == pytest.approx(views_mod.DETAIL_WAIT_S)
    assert command.status == "pending" and command.kind == "task.get"


# -- topology -------------------------------------------------------------------------------

ROUTING_POLICY = {
    "version": 1,
    "authz": [{"id": "all", "principal": "*", "agents": "*", "effect": "allow"}],
    "routing": [
        {"id": "no-p2", "agent": "billing", "partners": ["p2"], "mode": "forbid"},
        {"id": "p3-first", "agent": "billing", "partners": ["p3"], "mode": "force"},
        {
            "id": "p4-tagged",
            "agent": "billing",
            "partners": ["p4"],
            "mode": "prefer",
            "match": {"tags_any": ["fast"]},
        },
    ],
}


async def test_topology_edges_latency_and_policy_overlay(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, t1 = await gateway(app, "east")
        gw2, t2 = await gateway(app, "west")
        for pid, tags in (("p1", []), ("p2", []), ("p3", []), ("p4", ["fast"])):
            await add_partner(app, pid, tags=tags)
            await assign_partner(app, gw1, pid)
        r = await c.post(
            "/api/v1/policies", json={"name": "edge", "doc": ROUTING_POLICY}, headers=admin
        )
        assert r.status_code == 201, r.text
        r = await c.put(
            f"/api/v1/gateways/{gw1}/policy",
            json={"policy_id": r.json()["id"], "version": None},
            headers=admin,
        )
        assert r.status_code == 200, r.text
        await app.state.maintenance.run_once()  # the desired states are recomputed
        now = clock()
        await report(
            c,
            t1,
            events=[
                *(
                    call_ev("billing", "p1", "failed" if d == 50 else "completed", d, now - 600)
                    for d in (30, 10, 50, 20, 40)
                ),
                call_ev("billing", "p2", "rejected", 1, now - 600),
                call_ev("billing", "p3", "completed", 7, now - 600),
                call_ev("billing", "p4", "completed", 8, now - 600),
                call_ev("billing", "p1", "completed", 1000, now - 2 * 3600),  # outside 60 min
            ],
        )
        # the same agent name on another gateway, which has no policy: all allowed
        await report(c, t2, events=[call_ev("billing", "p2", "completed", 3, now - 600)])
        r = await c.get("/api/v1/topology", headers=admin)
        assert r.status_code == 200, r.text
        body = r.json()
        wide = (await c.get("/api/v1/topology", params={"window_m": 1440}, headers=admin)).json()
        narrow = (await c.get("/api/v1/topology", params={"window_m": 5}, headers=admin)).json()
        bad = await c.get("/api/v1/topology", params={"window_m": 4}, headers=admin)

    hosted1, hosted2 = f"{gw1}/billing", f"{gw2}/billing"
    assert sorted(body["nodes"], key=lambda n: n["id"]) == sorted(
        [
            {"id": hosted1, "kind": "hosted", "gateway_id": gw1, "agent_id": "billing"},
            {"id": hosted2, "kind": "hosted", "gateway_id": gw2, "agent_id": "billing"},
            *({"id": p, "kind": "partner"} for p in ("p1", "p2", "p3", "p4")),
        ],
        key=lambda n: n["id"],
    )
    edges = {(e["from"], e["to"]): e for e in body["edges"]}
    assert edges[(hosted1, "p1")] == {
        "from": hosted1,
        "to": "p1",
        "calls": 5,
        "errors": 1,
        "p50_ms": 30.0,
        "p95_ms": 50.0,
        "policy": "allowed",
    }
    assert edges[(hosted1, "p2")]["policy"] == "forbidden"
    assert edges[(hosted1, "p2")]["errors"] == 1
    assert edges[(hosted1, "p3")]["policy"] == "forced"
    assert edges[(hosted1, "p4")]["policy"] == "preferred"
    assert edges[(hosted2, "p2")]["policy"] == "allowed"
    assert len(edges) == 5
    wide_p1 = next(e for e in wide["edges"] if (e["from"], e["to"]) == (hosted1, "p1"))
    assert wide_p1["calls"] == 6 and wide_p1["p95_ms"] == 1000.0
    assert narrow == {"nodes": [], "edges": []}
    assert bad.status_code == 422 and bad.json()["fields"] == ["query.window_m"]


# -- audit ----------------------------------------------------------------------------------


def gw_row(seq: int, action: str, ts: float, **fields: Any) -> dict[str, Any]:
    """A gateway audit row as the gateway reports it (``AuditLog.query``'s shape)."""
    row = {
        "seq": seq,
        "ts": ts,
        "actor": "key:alice",
        "action": action,
        "agent_id": "billing",
        "partner_id": None,
        "task_id": None,
        "classification": None,
        "outcome": "ok",
        "detail": {},
        "prev_hash": "0" * 64,
        "hash": f"{seq:064x}",
    }
    row.update(fields)
    return row


async def test_audit_filters_both_sources(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        security = await signed_in(app, ["security"])
        gw1, t1 = await gateway(app, "east")
        gw2, t2 = await gateway(app, "west")
        now = clock()
        await report(
            c,
            t1,
            audit=[
                gw_row(1, "inbound.admit", now - 30),
                gw_row(2, "partner.call", now - 20, partner_id="p1", actor="key:bob"),
                gw_row(3, "authz.deny", now - 10, actor="anonymous", agent_id="support"),
            ],
        )
        await report(c, t2, audit=[gw_row(1, "inbound.admit", now - 25)])

        async def get(**params: Any) -> list[dict[str, Any]]:
            return await pages(c, "/api/v1/audit", security, params)

        everything = await get()
        gateway_rows = await get(source="gateway")
        control_rows = await get(source="control")
        on_gw1 = await get(source="gateway", gateway_id=gw1)
        about_gw2 = await get(gateway_id=gw2)
        admits = await get(action="inbound.admit")
        bob = await get(actor="key:bob")
        support = await get(agent="support")
        p1 = await get(partner="p1")
        window = await get(since=str(now - 22), until=str(now - 15))
        bad = await c.get("/api/v1/audit", params={"source": "elsewhere"}, headers=security)

    assert bad.status_code == 422
    assert {(r["source"], r["gateway_id"], r["seq"]) for r in gateway_rows} == {
        ("gateway", gw1, 1),
        ("gateway", gw1, 2),
        ("gateway", gw1, 3),
        ("gateway", gw2, 1),
    }
    assert {r["action"] for r in control_rows} == {"cp.gateway.create"}
    assert all(r["source"] == "control" and r["gateway_id"] is None for r in control_rows)
    assert len(everything) == len(gateway_rows) + len(control_rows)
    assert [r["ts"] for r in everything] == sorted((r["ts"] for r in everything), reverse=True)
    assert [r["seq"] for r in on_gw1] == [3, 2, 1]
    # a gateway's own rows and the control plane's rows about it
    assert {(r["source"], r["action"]) for r in about_gw2} == {
        ("gateway", "inbound.admit"),
        ("control", "cp.gateway.create"),
    }
    assert {(r["gateway_id"], r["seq"]) for r in admits} == {(gw1, 1), (gw2, 1)}
    [bob_row] = bob
    assert bob_row["actor"] == "key:bob" and bob_row["partner_id"] == "p1"
    assert bob_row["detail"] == {} and bob_row["hash"] == f"{2:064x}"
    assert [r["seq"] for r in support] == [3]
    assert [r["seq"] for r in p1] == [2]
    assert [r["seq"] for r in window] == [2]


async def test_export_csv_formula_guard_and_audited(db_url, make_app, run_app, clock, monkeypatch):
    monkeypatch.setattr(views_mod, "EXPORT_BATCH", 2)  # several batches, keyset between them
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        security = await signed_in(app, ["security"])
        _gw, t1 = await gateway(app, "east")
        now = clock()
        hostile = gw_row(
            1,
            "inbound.admit",
            now - 10,
            actor="=HYPERLINK(1)",
            agent_id="+billing",
            partner_id="-p1",
            task_id="@t",
            outcome="\tok",
            classification="\rx",
        )
        rows = [hostile, *(gw_row(i, "inbound.admit", now - 10 + i) for i in range(2, 6))]
        await report(c, t1, audit=rows)
        r = await c.get(
            "/api/v1/audit/export",
            params={"format": "csv", "source": "gateway"},
            headers=security,
        )
        jsonl = await c.get(
            "/api/v1/audit/export",
            params={"format": "jsonl", "source": "gateway"},
            headers=security,
        )
        monkeypatch.setattr(views_mod, "EXPORT_MAX", 3)
        capped = await c.get(
            "/api/v1/audit/export",
            params={"format": "jsonl", "source": "gateway"},
            headers=security,
        )
        exported = await audit_rows(app, "cp.audit.export")

    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    table = list(csv.DictReader(io.StringIO(r.text)))
    assert len(table) == 5
    [bad] = [row for row in table if row["seq"] == "1"]
    assert bad["actor"] == "'=HYPERLINK(1)"
    assert bad["agent_id"] == "'+billing" and bad["partner_id"] == "'-p1"
    assert bad["task_id"] == "'@t" and bad["outcome"] == "'\tok"
    assert bad["classification"] == "'\rx"
    assert bad["source"] == "gateway" and bad["action"] == "inbound.admit"
    lines = [json.loads(line) for line in jsonl.text.splitlines()]
    assert len(lines) == 5 and jsonl.headers["content-type"].startswith("application/x-ndjson")
    assert lines[-1]["actor"] == "=HYPERLINK(1)"  # JSON lines are data, not spreadsheet cells
    assert [x["seq"] for x in lines] == [5, 4, 3, 2, 1]
    assert len(capped.text.splitlines()) == 3
    assert [e["actor"] for e in exported] == ["oidc:u1"] * 3
    assert [e["detail"].get("format") for e in exported] == ["csv", "jsonl", "jsonl"]
    assert all(set(e["detail"]) <= DETAIL_KEYS for e in exported)
    assert exported[0]["detail"]["source"] == "gateway"


async def test_audit_verify_checks_the_control_chain(db_url, make_app, run_app):
    from sqlalchemy import text

    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        security = await signed_in(app, ["security"])
        await gateway(app, "east")
        ok = (await c.get("/api/v1/audit/verify", headers=security)).json()
        async with app.state.engine.begin() as conn:
            await conn.execute(text("UPDATE cp_audit SET outcome = 'forged' WHERE seq = 1"))
        broken = (await c.get("/api/v1/audit/verify", headers=security)).json()
    assert ok == {"ok": True, "first_bad_seq": None}
    assert broken == {"ok": False, "first_bad_seq": 1}


# -- credentials ----------------------------------------------------------------------------


async def test_credentials_names_only(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gw1, _t1 = await gateway(app, "east")
        await add_partner(app, "p1", credential_ref="billing-oauth", tls_ref="mtls-1")
        await add_partner(app, "p2", credential_ref="billing-oauth")
        await add_partner(app, "p3")
        await assign_partner(app, gw1, "p1")
        r = await c.get("/api/v1/credentials", headers=admin)
        assert r.status_code == 200, r.text
        items = await pages(c, "/api/v1/credentials", admin, {"limit": 1})

    assert r.json()["items"] == items
    assert items == [
        {
            "kind": "credential",
            "name": "billing-oauth",
            "partners": ["p1", "p2"],
            "gateways": [gw1],
        },
        {"kind": "tls", "name": "mtls-1", "partners": ["p1"], "gateways": [gw1]},
    ]


# -- pagination -----------------------------------------------------------------------------


async def test_pagination_cursor_stable(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        security = await signed_in(app, ["security"])
        _gw1, t1 = await gateway(app, "east")
        now = clock()
        # two tasks updated at the same instant: the keyset still orders them
        events = [task_ev("billing", f"t{i}", WORKING, now - 100 + (i // 2)) for i in range(7)]
        await report(c, t1, events=events)
        everything = await pages(c, "/api/v1/tasks", admin, {"limit": 200})
        paged = await pages(c, "/api/v1/tasks", admin, {"limit": 2})
        first = (await c.get("/api/v1/tasks", params={"limit": 2}, headers=admin)).json()
        cursor = first["next_cursor"]
        again = (
            await c.get("/api/v1/tasks", params={"limit": 2, "cursor": cursor}, headers=admin)
        ).json()
        # a newer task does not move the pages after a cursor
        await report(c, t1, events=[task_ev("billing", "t-new", WORKING, now - 1)])
        later = (
            await c.get("/api/v1/tasks", params={"limit": 2, "cursor": cursor}, headers=admin)
        ).json()
        other_filters = await c.get(
            "/api/v1/tasks", params={"limit": 2, "cursor": cursor, "agent_id": "x"}, headers=admin
        )
        garbage = await c.get("/api/v1/tasks", params={"cursor": "!!nope"}, headers=admin)
        position = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        forged = []
        for k in ([10**400, 1], [1.0, 10**30], ["x", 1], [1.0, True], [1.0]):
            raw = json.dumps({"q": position["q"], "k": k}).encode()
            forged.append(base64.urlsafe_b64encode(raw).decode())
        forged_responses = [
            await c.get("/api/v1/tasks", params={"cursor": f}, headers=admin) for f in forged
        ]
        too_big = await c.get("/api/v1/tasks", params={"limit": 201}, headers=admin)
        # the audit list's cursor runs across both sources
        await report(c, t1, audit=[gw_row(i, "inbound.admit", now - 50 + i) for i in range(1, 4)])
        audit_all = await pages(c, "/api/v1/audit", security, {"limit": 200})
        audit_paged = await pages(c, "/api/v1/audit", security, {"limit": 1})
        # a READ cursor cannot be replayed against the audit list
        audit_with_task_cursor = await c.get(
            "/api/v1/audit", params={"cursor": cursor}, headers=security
        )

    assert len(everything) == 7
    assert paged == everything
    assert len({(t["gateway_id"], t["task_id"]) for t in paged}) == 7
    assert again == later
    assert [t["task_id"] for t in again["items"]] == [t["task_id"] for t in everything[2:4]]
    for r in (other_filters, garbage, audit_with_task_cursor, *forged_responses):
        assert r.status_code == 400 and r.json()["error"] == "bad_request", r.text
    assert too_big.status_code == 422
    assert audit_paged == audit_all and len(audit_all) >= 4


def test_public_detail_hides_principals_and_reports_truncation():
    shown = views_mod.public_detail(
        {
            "task": {"id": "t1", "owner": "jwt:carol", "state": WORKING},
            "partner_tasks": [{"partner_id": "p1", "task_id": "pt", "caller_id": "key:x"}, "junk"],
            "pending_prompt": "which account?",
            "history_total": 40,
            "artifacts_total": 2,
            "partner_tasks_total": 1,
            "clipped": True,
        }
    )
    assert (shown["history_total"], shown["artifacts_total"]) == (40, 2)
    assert shown["partner_tasks_total"] == 1 and shown["clipped"] is True
    assert shown["task"] == {"id": "t1", "state": WORKING, "owner_kind": "jwt"}
    assert shown["partner_tasks"] == [
        {
            "partner_id": "p1",
            "task_id": "pt",
            "context_id": None,
            "state": None,
            "created_at": None,
            "end_reason": None,
        }
    ]
    assert shown["pending_prompt"] == "which account?"
    # a detail the gateway cut for size (over its 8 KiB result cap)
    assert views_mod.public_detail({"truncated": True}) == {
        "task": None,
        "partner_tasks": [],
        "pending_prompt": None,
        "truncated": True,
    }


@pytest.mark.parametrize(
    ("value", "cell"),
    [
        ("=1+1", "'=1+1"),
        ("+1", "'+1"),
        ("-1", "'-1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tx", "'\tx"),
        ("\rx", "'\rx"),
        ("plain", "plain"),
        (None, ""),
        (12, "12"),
        ({"b": 1, "a": "=x"}, '{"a":"=x","b":1}'),
    ],
)
def test_csv_cell_formula_guard(value, cell):
    assert views_mod.csv_cell(value) == cell
