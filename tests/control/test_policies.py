"""Policies on the control plane: versions, warnings, per-gateway assignment (pinned or
latest) feeding the desired state, and the dry-run over the gateways' audit rows."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from oidc_fake import audit_rows, signed_in

pytest.importorskip("fastapi")

from a2agw.control import channel
from a2agw.control import policies as policies_mod
from a2agw.control.settings import ControlSettings
from a2agw.control.store import PARTNERS
from a2agw.ops.audit import DETAIL_KEYS
from a2agw.security.policy import Policy, parse_policy, policy_hash

DAY = 86400.0

ALLOW_ALICE = {
    "version": 1,
    "authz": [{"id": "alice", "principal": "key:alice", "agents": ["billing"], "effect": "allow"}],
}
ALLOW_ALL = {
    "version": 1,
    "authz": [{"id": "all", "principal": "*", "agents": ["billing"], "effect": "allow"}],
}
LONE_DENY = {
    "version": 1,
    "authz": [{"id": "no-mallory", "principal": "key:mallory", "agents": "*", "effect": "deny"}],
}


def settings_for(db_url: str) -> ControlSettings:
    return ControlSettings(base_url="https://cp.example", db_url=db_url)


async def admin_key(app: Any) -> dict[str, str]:
    _id, key = await app.state.store.create_api_key("admin", "admin", actor="t")
    return {"authorization": f"Bearer {key}"}


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def create(c, headers, name: str, doc: dict[str, Any], **body: Any) -> httpx.Response:
    return await c.post(
        "/api/v1/policies", json={"name": name, "doc": doc, **body}, headers=headers
    )


async def add_version(c, headers, pid: str, doc: dict[str, Any], **body: Any) -> httpx.Response:
    return await c.post(
        f"/api/v1/policies/{pid}/versions", json={"doc": doc, **body}, headers=headers
    )


async def assign(c, headers, gid: str, pid: str, version: int | None) -> httpx.Response:
    return await c.put(
        f"/api/v1/gateways/{gid}/policy",
        json={"policy_id": pid, "version": version},
        headers=headers,
    )


async def dry_run(c, headers, doc: dict[str, Any], **body: Any) -> httpx.Response:
    return await c.post("/api/v1/policies/dry-run", json={"doc": doc, **body}, headers=headers)


async def add_partner(app: Any, pid: str, tier: str = "public", tags: list[str] | None = None):
    now = app.state.clock()
    async with app.state.engine.begin() as conn:
        await conn.execute(
            PARTNERS.insert().values(
                id=pid,
                card_url=None,
                tier=tier,
                tags_json=json.dumps(tags or []),
                status="approved",
                current_version=0,
                created_at=now,
                updated_at=now,
            )
        )


def row(
    seq: int,
    action: str,
    *,
    ts: float,
    actor: str = "key:alice",
    agent: str | None = "billing",
    partner: str | None = None,
    classification: str | None = None,
    outcome: str = "admitted",
    **detail: Any,
) -> dict[str, Any]:
    """A gateway audit row as the gateway reports it (``AuditLog.query``'s shape)."""
    return {
        "seq": seq,
        "ts": ts,
        "actor": actor,
        "action": action,
        "agent_id": agent,
        "partner_id": partner,
        "task_id": f"t-{seq}",
        "classification": classification,
        "outcome": outcome,
        "detail": detail,
        "prev_hash": "0" * 64,
        "hash": f"{seq:064x}",
    }


async def report(c, token: str, rows: list[dict[str, Any]]) -> None:
    r = await c.post("/cp/v1/report", json={"audit": rows}, headers=bearer(token))
    assert r.status_code == 200, r.text
    assert r.json()["dropped"] == 0


def strip(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (entry["seq"], entry["action"], entry["actor_kind"], entry["rule"])


# -- versions -------------------------------------------------------------------------------


async def test_create_and_version_policy(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        r = await create(c, admin, "edge", ALLOW_ALICE, comment="first")
        assert r.status_code == 201, r.text
        body = r.json()
        pid = body["id"]
        assert pid.startswith("pol-") and body["name"] == "edge"
        [v1] = body["versions"]
        normalized = parse_policy(ALLOW_ALICE).model_dump(mode="json")
        assert v1["version"] == 1 and v1["doc"] == normalized and v1["comment"] == "first"
        assert v1["doc_hash"] == policy_hash(parse_policy(ALLOW_ALICE))
        assert v1["created_by"].startswith("ak-") and v1["diff"] == ""
        assert body["warnings"] == []

        # a name is taken once
        assert (await create(c, admin, "edge", ALLOW_ALL)).status_code == 409

        r = await add_version(c, admin, pid, ALLOW_ALL, comment="everyone")
        assert r.status_code == 201, r.text
        body = r.json()
        assert [v["version"] for v in body["versions"]] == [1, 2]
        diff = body["versions"][1]["diff"]
        assert diff.startswith("--- v1\n+++ v2\n")
        assert "-  id: alice\n" in diff and "+  id: all\n" in diff
        assert "-  principal: key:alice\n" in diff and "+  principal: '*'\n" in diff
        assert (await add_version(c, admin, "pol-nope", ALLOW_ALL)).status_code == 404

        r = await c.get(f"/api/v1/policies/{pid}", headers=admin)
        assert r.status_code == 200 and r.json()["versions"][1]["diff"] == diff
        assert r.json()["latest_version"] == 2 and r.json()["gateways"] == []
        listed = (await c.get("/api/v1/policies", headers=admin)).json()["policies"]
        [item] = listed
        assert item["id"] == pid and item["latest_version"] == 2
        assert [v["version"] for v in item["versions"]] == [1, 2]
        assert "doc" not in item["versions"][0]  # summaries in the list
        assert (await c.get("/api/v1/policies/pol-nope", headers=admin)).status_code == 404

        rows = await audit_rows(app, "cp.policy.save")
        assert [(r["outcome"], r["detail"]) for r in rows] == [
            ("created", {"policy": pid, "version": 1, "hash": v1["doc_hash"]}),
            (
                "created",
                {"policy": pid, "version": 2, "hash": policy_hash(parse_policy(ALLOW_ALL))},
            ),
        ]
        for r in rows:
            assert r["actor"].startswith("ak-") and set(r["detail"]) <= DETAIL_KEYS
        assert "key:alice" not in json.dumps(rows)  # no document body in the audit


async def test_invalid_doc_422_fields_only(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        bad = {
            "version": 1,
            "authz": [
                {"principal": "SECRET-VALUE with spaces", "agents": ["b"], "effect": "allow"}
            ],
            "bogus": "SECRET-EXTRA",
        }
        r = await create(c, admin, "bad", bad)
        assert r.status_code == 422
        assert r.json()["fields"] == ["body.doc.authz.0.principal", "body.doc.bogus"]
        assert "SECRET" not in r.text
        r = await create(c, admin, "ok", ALLOW_ALL)
        pid = r.json()["id"]
        r = await add_version(c, admin, pid, {"version": 2})
        assert r.status_code == 422 and r.json()["fields"] == ["body.doc.version"]
        r = await dry_run(c, admin, {"version": 1, "egress": {"tier_ceilings": {"x": "public"}}})
        assert r.status_code == 422 and r.json()["fields"] == [
            "body.doc.egress.tier_ceilings.x.[key]"
        ]
        r = await dry_run(c, admin, ALLOW_ALL, days=31)
        assert r.status_code == 422 and r.json()["fields"] == ["body.days"]
        detail = (await c.get(f"/api/v1/policies/{pid}", headers=admin)).json()
        assert len(detail["versions"]) == 1  # nothing stored
        assert (await c.get("/api/v1/policies", headers=admin)).json()["policies"][0][
            "name"
        ] == "ok"


async def test_lone_deny_warning(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        await add_partner(app, "acme")
        pid = (await create(c, admin, "edge", ALLOW_ALL)).json()["id"]
        r = await add_version(c, admin, pid, LONE_DENY)
        assert r.status_code == 201
        assert r.json()["warnings"] == ["lone deny rule locks down every agent"]

        # a deny next to an allow for its agent is a blocklist: no warning
        both = {
            "version": 1,
            "authz": [*ALLOW_ALL["authz"], {**LONE_DENY["authz"][0], "agents": ["billing"]}],
            "routing": [
                {"id": "r1", "agent": "billing", "partners": ["acme", "ghost"], "mode": "forbid"}
            ],
        }
        r = await add_version(c, admin, pid, both)
        assert r.json()["warnings"] == ["routing rule r1 names unknown partner ghost"]
        # a deny for an agent no allow rule names locks that agent down
        partial = {
            "version": 1,
            "authz": [
                *ALLOW_ALL["authz"],
                {"principal": "key:mallory", "agents": ["hr"], "effect": "deny"},
            ],
        }
        r = await add_version(c, admin, pid, partial)
        assert r.json()["warnings"] == [
            "deny rule authz[1] locks down agent hr: no allow rule for it"
        ]
        r = await create(c, admin, "other", LONE_DENY)  # the create response warns too
        assert r.json()["warnings"] == ["lone deny rule locks down every agent"]


# -- assignment and desired state -----------------------------------------------------------


async def test_assign_pinned_and_latest(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        store = app.state.store
        gid, _ = await store.create_gateway("edge-1", actor="t")
        pid = (await create(c, admin, "edge", ALLOW_ALICE)).json()["id"]
        await add_version(c, admin, pid, ALLOW_ALL)

        r = await assign(c, admin, gid, pid, 1)
        assert r.status_code == 200, r.text
        assert r.json() == {"gateway_id": gid, "policy_id": pid, "version": 1}
        state = await channel.compute_desired(store, gid)
        assert state.policy == parse_policy(ALLOW_ALICE).model_dump(mode="json")
        await add_version(c, admin, pid, LONE_DENY)
        assert (await channel.compute_desired(store, gid)).policy == state.policy  # pinned

        assert (await assign(c, admin, gid, pid, None)).status_code == 200  # follow latest
        latest = await channel.compute_desired(store, gid)
        assert latest.policy == parse_policy(LONE_DENY).model_dump(mode="json")
        detail = (await c.get(f"/api/v1/policies/{pid}", headers=admin)).json()
        assert detail["gateways"] == [{"gateway_id": gid, "version": None}]

        # one policy per gateway: assigning another replaces it
        other = (await create(c, admin, "other", ALLOW_ALL)).json()["id"]
        assert (await assign(c, admin, gid, other, None)).status_code == 200
        assert (await channel.compute_desired(store, gid)).policy == parse_policy(
            ALLOW_ALL
        ).model_dump(mode="json")
        assert (await c.get(f"/api/v1/policies/{pid}", headers=admin)).json()["gateways"] == []

        r = await assign(c, admin, gid, "pol-nope", None)
        assert r.status_code == 422 and r.json()["fields"] == ["body.policy_id"]
        r = await assign(c, admin, gid, pid, 9)
        assert r.status_code == 422 and r.json()["fields"] == ["body.version"]
        assert (await assign(c, admin, "gw-nope", pid, None)).status_code == 404
        r = await c.put(f"/api/v1/gateways/{gid}/policy", json={"policy_id": pid}, headers=admin)
        assert r.status_code == 422 and r.json()["fields"] == ["body.version"]  # explicit null

        rows = await audit_rows(app, "cp.assign")
        assert rows[0]["detail"] == {"gateway": gid, "policy": pid, "version": 1}
        assert rows[1]["detail"] == {"gateway": gid, "policy": pid, "version": None}


async def test_assignment_updates_desired_state(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        store = app.state.store
        g1, _ = await store.create_gateway("edge-1", actor="t")
        g2, _ = await store.create_gateway("edge-2", actor="t")
        await channel.recompute_dirty(store)
        assert (await channel.load_desired(store, g1)).policy is None  # unassigned: lockdown
        pid = (await create(c, admin, "edge", ALLOW_ALICE)).json()["id"]
        assert await channel.dirty_gateways(store) == []  # nobody follows it yet

        await assign(c, admin, g1, pid, None)
        await assign(c, admin, g2, pid, 1)
        assert await channel.dirty_gateways(store) == sorted([g1, g2])
        await channel.recompute_dirty(store)
        state = await channel.load_desired(store, g1)
        # what the control plane sends passes the gateway's own validation, same hash
        assert policy_hash(Policy.model_validate(state.policy)) == policy_hash(
            parse_policy(ALLOW_ALICE)
        )
        assert parse_policy(state.policy) == parse_policy(ALLOW_ALICE)
        v_before = state.version

        # a new version marks the gateways that follow the latest, not the pinned ones
        await add_version(c, admin, pid, ALLOW_ALL)
        assert await channel.dirty_gateways(store) == [g1]
        await channel.recompute_dirty(store)
        state = await channel.load_desired(store, g1)
        assert state.version == v_before + 1
        assert parse_policy(state.policy) == parse_policy(ALLOW_ALL)
        assert parse_policy((await channel.load_desired(store, g2)).policy) == parse_policy(
            ALLOW_ALICE
        )


# -- dry-run --------------------------------------------------------------------------------


async def test_dry_run_finds_newly_blocked_admit(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, token = await app.state.store.create_gateway("edge-1", actor="t")
        now = clock()
        await report(
            c,
            token,
            [
                row(1, "inbound.admit", ts=now - 50, actor="key:alice", principal_kind="api_key"),
                row(2, "inbound.admit", ts=now - 40, actor="key:bob", principal_kind="api_key"),
                row(
                    3,
                    "authz.deny",
                    ts=now - 30,
                    actor="jwt:carol",
                    outcome="forbidden",
                    principal_kind="jwt",
                    reason="no matching allow rule",
                ),
                row(  # not a policy decision: not replayed
                    4,
                    "authz.deny",
                    ts=now - 20,
                    actor="key:dave",
                    outcome="forbidden",
                    principal_kind="api_key",
                    reason="agent access: not allowed",
                ),
                row(5, "cp.apply", ts=now - 10, actor=gid, agent=None, outcome="applied"),
                row(
                    6,
                    "inbound.reject",
                    ts=now - 5,
                    actor="key:erin",
                    outcome="rejected",
                    reason="policy: no matching allow rule",
                ),
            ],
        )
        r = await dry_run(c, admin, ALLOW_ALICE)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["evaluated"] == 4 and body["truncated"] is False
        [blocked] = body["newly_blocked"]
        assert blocked == {
            "gateway_id": gid,
            "seq": 2,
            "ts": now - 40,
            "actor_kind": "api_key",
            "agent_id": "billing",
            "partner_id": None,
            "action": "inbound.admit",
            "rule": "no matching allow rule",
        }
        assert body["newly_allowed"] == []
        assert body["counts"] == {"newly_blocked": 1, "newly_allowed": 0, "skipped": 1}

        body = (await dry_run(c, admin, ALLOW_ALL)).json()
        assert body["newly_blocked"] == []
        assert [strip(e) for e in body["newly_allowed"]] == [
            (6, "inbound.reject", "api_key", "all"),
            (3, "authz.deny", "jwt", "all"),
        ]

        # a lone deny is a lockdown, not a blocklist: alice and bob are blocked too
        body = (await dry_run(c, admin, LONE_DENY)).json()
        assert [strip(e) for e in body["newly_blocked"]] == [
            (2, "inbound.admit", "api_key", "no matching allow rule"),
            (1, "inbound.admit", "api_key", "no matching allow rule"),
        ]
        assert body["newly_allowed"] == []
        lock = {"version": 1, "authz": [{"principal": "*", "agents": "*", "effect": "deny"}]}
        body = (await dry_run(c, admin, lock)).json()
        assert [strip(e) for e in body["newly_blocked"]] == [
            (2, "inbound.admit", "api_key", "authz[0]"),
            (1, "inbound.admit", "api_key", "authz[0]"),
        ]  # newest first
        [audited] = (await audit_rows(app, "cp.policy.dryrun"))[-1:]
        assert audited["outcome"] == "complete"
        assert audited["detail"] == {"count": 4, "hash": policy_hash(parse_policy(lock))}


async def test_dry_run_finds_newly_forbidden_partner_call(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        await add_partner(app, "acme", tags=["eu"])
        gid, token = await app.state.store.create_gateway("edge-1", actor="t")
        now = clock()

        def call(seq: int, partner: str, **kw: Any) -> dict[str, Any]:
            return row(
                seq,
                "partner.call",
                ts=now - 100 + seq,
                partner=partner,
                classification="public",
                outcome="completed",
                state="completed",
                tier="public",
                **kw,
            )

        await report(
            c,
            token,
            [
                call(1, "acme"),
                call(2, "other"),
                # unavailable without a classification: maybe forbidden then, maybe not
                row(3, "partner.call", ts=now - 90, partner="acme", outcome="unavailable"),
            ],
        )
        forbid = {
            "version": 1,
            "routing": [
                {
                    "id": "no-acme",
                    "agent": "billing",
                    "match": {"tags_any": ["eu"]},
                    "partners": ["acme", "other"],
                    "mode": "forbid",
                }
            ],
        }
        body = (await dry_run(c, admin, forbid)).json()
        # acme has tag eu in the catalogue; "other" is unknown there, so a match rule
        # cannot be decided for it: skipped, not guessed
        assert [(e["seq"], e["partner_id"], e["rule"]) for e in body["newly_blocked"]] == [
            (1, "acme", "no-acme")
        ]
        assert body["newly_blocked"][0]["actor_kind"] == "api_key"
        assert body["newly_blocked"][0]["gateway_id"] == gid
        assert body["evaluated"] == 1 and body["counts"]["skipped"] == 2

        plain = {
            "version": 1,
            "routing": [{"agent": "billing", "partners": ["other"], "mode": "forbid"}],
        }
        body = (await dry_run(c, admin, plain)).json()
        assert [(e["seq"], e["rule"]) for e in body["newly_blocked"]] == [(2, "routing[0]")]
        # another agent's rule changes nothing
        elsewhere = {
            "version": 1,
            "routing": [{"agent": "hr", "partners": ["acme", "other"], "mode": "forbid"}],
        }
        assert (await dry_run(c, admin, elsewhere)).json()["newly_blocked"] == []


async def test_dry_run_classification_ceiling(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        await add_partner(app, "acme", tier="partner")
        _gid, token = await app.state.store.create_gateway("edge-1", actor="t")
        now = clock()
        await report(
            c,
            token,
            [
                row(
                    1,
                    "partner.call",
                    ts=now - 30,
                    partner="acme",
                    classification="confidential",
                    outcome="completed",
                    state="completed",
                    tier="partner",
                ),
                row(
                    2,
                    "egress.deny",
                    ts=now - 20,
                    partner="pubco",
                    classification="internal",
                    outcome="rejected",
                    tier="public",
                    principal_kind="api_key",
                    reason="classification internal exceeds public ceiling for partner pubco",
                    rule="egress.tier_ceilings[public]",
                ),
                row(  # no classification: the ceiling cannot be replayed
                    3,
                    "egress.deny",
                    ts=now - 10,
                    partner="pubco",
                    outcome="rejected",
                    tier="public",
                    principal_kind="api_key",
                    reason="policy evaluation error",
                ),
            ],
        )
        tight = {"version": 1, "egress": {"partner_ceilings": {"acme": "internal"}}}
        body = (await dry_run(c, admin, tight)).json()
        assert [(e["seq"], e["rule"]) for e in body["newly_blocked"]] == [
            (1, "egress.partner_ceilings[acme]")
        ]
        assert body["newly_allowed"] == [] and body["counts"]["skipped"] == 1

        loose = {"version": 1, "egress": {"tier_ceilings": {"public": "internal"}}}
        body = (await dry_run(c, admin, loose)).json()
        assert body["newly_blocked"] == []
        assert [(e["seq"], e["action"], e["rule"]) for e in body["newly_allowed"]] == [
            (2, "egress.deny", "egress.tier_ceilings[public]")
        ]
        # an agent default raises the level of every call of that agent
        floor = {
            "version": 1,
            "egress": {"tier_ceilings": {"public": "internal"}},
            "defaults": {"agent_classification": {"billing": "restricted"}},
        }
        body = (await dry_run(c, admin, floor)).json()
        assert [(e["seq"], e["rule"]) for e in body["newly_blocked"]] == [
            (1, "egress.tier_ceilings[partner]")
        ]
        assert body["newly_allowed"] == []


async def test_dry_run_truncates_at_cap(db_url, make_app, run_app, clock, monkeypatch):
    monkeypatch.setattr(policies_mod, "DRY_RUN_MAX_ROWS", 5)
    monkeypatch.setattr(policies_mod, "DRY_RUN_BATCH", 2)
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        g1, t1 = await app.state.store.create_gateway("edge-1", actor="t")
        g2, t2 = await app.state.store.create_gateway("edge-2", actor="t")
        now = clock()
        lock = {"version": 1, "authz": [{"principal": "*", "agents": "*", "effect": "deny"}]}
        await report(c, t1, [row(i, "inbound.admit", ts=now - 100 + i) for i in range(1, 4)])
        # same timestamps on two gateways: the order is still total
        await report(c, t2, [row(i, "inbound.admit", ts=now - 100 + i) for i in range(1, 3)])
        body = (await dry_run(c, admin, lock)).json()
        assert body["truncated"] is False and body["evaluated"] == 5

        await report(c, t1, [row(9, "inbound.admit", ts=now - 1)])
        body = (await dry_run(c, admin, lock)).json()
        assert body["truncated"] is True and body["evaluated"] == 5
        # newest first; rows with the same ts by gateway id, then seq, both descending:
        # the oldest row of the lower gateway id is the one left out
        hi, lo = sorted([g1, g2], reverse=True)
        got = [(e["gateway_id"], e["seq"]) for e in body["newly_blocked"]]
        assert got == [(g1, 9), (g1, 3), (hi, 2), (lo, 2), (hi, 1)]

        # the listed entries are capped; the counts are not
        monkeypatch.setattr(policies_mod, "DRY_RUN_LIST_MAX", 2)
        body = (await dry_run(c, admin, lock)).json()
        assert len(body["newly_blocked"]) == 2 and body["counts"]["newly_blocked"] == 5
        assert (await audit_rows(app, "cp.policy.dryrun"))[-1]["outcome"] == "truncated"


async def test_dry_run_reports_not_replayable(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        g1, t1 = await app.state.store.create_gateway("edge-1", actor="t")
        g2, t2 = await app.state.store.create_gateway("edge-2", actor="t")
        lock = {"version": 1, "authz": [{"principal": "*", "agents": "*", "effect": "deny"}]}
        await report(c, t1, [row(1, "inbound.admit", ts=clock() - 10)])
        clock.advance(2 * DAY)
        await report(c, t2, [row(1, "inbound.admit", ts=clock() - 10)])
        await report(c, t1, [row(2, "inbound.admit", ts=clock() - 5)])

        body = (await dry_run(c, admin, lock)).json()
        assert "egress content checks" in body["not_replayable"]
        assert body["evaluated"] == 3
        # the window: only the last day
        body = (await dry_run(c, admin, lock, days=1)).json()
        assert sorted((e["gateway_id"], e["seq"]) for e in body["newly_blocked"]) == sorted(
            [(g1, 2), (g2, 1)]
        )
        # only the gateways asked for
        body = (await dry_run(c, admin, lock, gateway_ids=[g2])).json()
        assert [(e["gateway_id"], e["seq"]) for e in body["newly_blocked"]] == [(g2, 1)]
        body = (await dry_run(c, admin, lock, gateway_ids=[])).json()
        assert body["evaluated"] == 0 and body["newly_blocked"] == []
        assert body["not_replayable"] == ["egress content checks"]


async def test_dry_run_no_principal_ids(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        _gid, token = await app.state.store.create_gateway("edge-1", actor="t")
        now = clock()
        await report(
            c,
            token,
            [
                row(
                    1, "inbound.admit", ts=now - 3, actor="key:alice-7f3a", principal_kind="api_key"
                ),
                row(2, "inbound.admit", ts=now - 2, actor="jwt:sub-91c2", principal_kind="jwt"),
                row(3, "inbound.admit", ts=now - 1, actor="anonymous", principal_kind="anonymous"),
                row(  # no principal_kind: derived from the id's prefix
                    4,
                    "partner.call",
                    ts=now,
                    actor="key:bob-55aa",
                    partner="acme",
                    classification="public",
                    outcome="completed",
                    tier="public",
                ),
            ],
        )
        doc = {
            "version": 1,
            "authz": [{"principal": "*", "agents": "*", "effect": "deny"}],
            "routing": [{"agent": "billing", "partners": ["acme"], "mode": "forbid"}],
        }
        r = await dry_run(c, admin, doc)
        body = r.json()
        assert [(e["seq"], e["actor_kind"]) for e in body["newly_blocked"]] == [
            (4, "api_key"),
            (3, "anonymous"),
            (2, "jwt"),
            (1, "api_key"),
        ]
        for entry in body["newly_blocked"]:
            assert "actor" not in entry and "principal" not in entry
        texts = r.text + json.dumps(await audit_rows(app, "cp.policy.dryrun"))
        for secret in ("alice-7f3a", "sub-91c2", "bob-55aa", "key:", "jwt:"):
            assert secret not in texts


# -- permissions ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        ("viewer", {"read"}),
        ("operator", {"read"}),
        ("security", {"read", "edit"}),
        ("admin", {"read", "edit", "assign"}),
    ],
)
async def test_permissions(role, allowed, sqlite_settings, make_app, run_app):
    app = make_app(sqlite_settings)
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, _ = await app.state.store.create_gateway("edge-1", actor="t")
        pid = (await create(c, admin, "edge", ALLOW_ALL)).json()["id"]
        headers = await signed_in(app, [role])
        calls = {
            "read": [("GET", "/api/v1/policies", None), ("GET", f"/api/v1/policies/{pid}", None)],
            "edit": [
                ("POST", "/api/v1/policies", {"name": f"n-{role}", "doc": ALLOW_ALL}),
                ("POST", f"/api/v1/policies/{pid}/versions", {"doc": ALLOW_ALICE}),
                ("POST", "/api/v1/policies/dry-run", {"doc": ALLOW_ALICE}),
            ],
            "assign": [
                ("PUT", f"/api/v1/gateways/{gid}/policy", {"policy_id": pid, "version": None})
            ],
        }
        for group, requests in calls.items():
            for method, path, body in requests:
                r = await c.request(method, path, json=body, headers=headers)
                if group in allowed:
                    assert r.status_code < 400, (role, path, r.text)
                else:
                    assert r.status_code == 403, (role, path, r.text)
                    assert r.json()["error"] == "forbidden"
        no_csrf = {"cookie": headers["cookie"]}
        r = await c.post("/api/v1/policies/dry-run", json={"doc": ALLOW_ALL}, headers=no_csrf)
        assert r.status_code == 403 and r.json()["error"] == "csrf"
        assert (await c.get("/api/v1/policies")).status_code == 401
