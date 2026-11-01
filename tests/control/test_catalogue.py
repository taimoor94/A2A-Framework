"""The partner catalogue: register, approve (hash-pinned), reject, quarantine, refresh,
settings, skill search, gateway assignment, and the partner.state ingest."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from oidc_fake import audit_rows, signed_in
from sqlalchemy import select

pytest.importorskip("fastapi")

from a2agw.consult import guarded_net, netguard
from a2agw.consult.cardfetch import normalize_card
from a2agw.consult.registry import REMOTE_FIELDS, PartnerRegistry, card_hash
from a2agw.control import channel
from a2agw.control.settings import ControlSettings
from a2agw.control.store import COMMANDS
from a2agw.ops.audit import DETAIL_KEYS

PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "10.0.0.5"
HOSTS = {"private.example.com": PRIVATE_IP}


def card(name: str, **over: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "name": name,
        "description": f"{name} does things",
        "version": "1.0",
        "supportedInterfaces": [
            {
                "url": f"https://{name.lower()}.example.com/rpc",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "s1", "name": "S1", "description": "d", "tags": ["a"]}],
    }
    raw.update(over)
    return raw


def normalized(raw: dict[str, Any]) -> dict[str, Any]:
    return normalize_card(copy.deepcopy(raw))[0]


def url_of(name: str) -> str:
    return f"https://{name.lower()}.example.com"


def card_url_of(name: str) -> str:
    return url_of(name) + "/.well-known/agent-card.json"


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    async def resolve(host: str) -> list[str]:
        return [HOSTS.get(host, PUBLIC_IP)]

    monkeypatch.setattr(netguard, "_resolve", resolve)


def settings_for(db_url: str, **kw: Any) -> ControlSettings:
    return ControlSettings(base_url="https://cp.example", db_url=db_url, **kw)


@pytest.fixture
def catalogue_app(clock, cp_http, tmp_path):
    """``catalogue_app(settings, guarded=False)``: the app on the fake clock; key files
    are read from ``tmp_path``. ``guarded=True``: no injected client (the app's own
    guarded clients fetch cards)."""
    from a2agw.control.app import create_app

    def make(settings: ControlSettings, *, guarded: bool = False) -> Any:
        return create_app(
            settings,
            http=None if guarded else cp_http,
            clock=clock,
            maintenance_interval_s=3600,
            config_dir=tmp_path,
        )

    return make


async def admin_key(app) -> dict[str, str]:
    _id, key = await app.state.store.create_api_key("admin", "admin", actor="t")
    return {"authorization": f"Bearer {key}"}


async def register(c, headers, pid: str, **body: Any) -> httpx.Response:
    payload: dict[str, Any] = {"id": pid, "tier": "public"}
    if "card" not in body:
        payload["card_url"] = url_of(pid)
    payload.update(body)
    return await c.post("/api/v1/partners", json=payload, headers=headers)


async def latest(c, headers, pid: str) -> dict[str, Any]:
    r = await c.get(f"/api/v1/partners/{pid}", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["versions"][-1]


async def approve(c, headers, pid: str) -> httpx.Response:
    v = await latest(c, headers, pid)
    return await c.post(
        f"/api/v1/partners/{pid}/approve",
        json={"version": v["version"], "expected_hash": v["card_hash"]},
        headers=headers,
    )


async def gateway(app, name: str) -> tuple[str, str]:
    return await app.state.store.create_gateway(name, actor="t")


async def assign(c, headers, gid: str, *pids: str) -> httpx.Response:
    return await c.put(
        f"/api/v1/gateways/{gid}/partners", json={"partner_ids": list(pids)}, headers=headers
    )


async def desired(app, gid: str) -> channel.DesiredState:
    return await channel.compute_desired(app.state.store, gid)


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


# -- registration ---------------------------------------------------------------------------


@respx.mock(assert_all_called=False)
async def test_register_fetches_via_guarded_client_and_rejects_private_for_public_tier(
    respx_mock, sqlite_settings, catalogue_app, run_app, monkeypatch
):
    tiers: list[str] = []
    real = guarded_net.guarded_async_client

    def spy(tier_for_host, **kw):
        tiers.append(tier_for_host("any.host"))
        return real(tier_for_host, **kw)

    monkeypatch.setattr(guarded_net, "guarded_async_client", spy)
    acme = respx_mock.get(card_url_of("acme")).respond(200, json=card("Acme"))
    evil = respx_mock.get("https://private.example.com/.well-known/agent-card.json").respond(
        200, json=card("Evil")
    )
    app = catalogue_app(sqlite_settings, guarded=True)
    async with run_app(app) as c:
        admin = await admin_key(app)
        tiers.clear()  # the app's own clients
        r = await register(c, admin, "acme", tags=["eu"])
        assert r.status_code == 201, r.text
        body = r.json()
        assert acme.called and tiers == ["public"]  # a guarded client for the tier
        assert body["id"] == "acme" and body["status"] == "pending"
        assert body["current_version"] == 0 and body["approved"] is None
        [v1] = body["versions"]
        assert v1["version"] == 1 and v1["card_hash"] == card_hash(normalized(card("Acme")))
        assert body["pending_version"]["card"] == normalized(card("Acme"))

        # a card URL resolving to a private address is refused for the public tier
        r = await c.post(
            "/api/v1/partners",
            json={"id": "evil", "tier": "public", "card_url": "https://private.example.com"},
            headers=admin,
        )
        assert r.status_code == 422 and r.json() == {"error": "card", "detail": "UnsafeCardURL"}
        assert not evil.called
        # so is a card whose interface is private, given inline
        inline = card(
            "Evil",
            supportedInterfaces=[
                {
                    "url": "https://private.example.com/rpc",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0",
                }
            ],
        )
        r = await register(c, admin, "evil", card=inline)
        assert r.status_code == 422 and r.json()["detail"] == "UnsafeInterfaceURL"
        r = await register(c, admin, "evil", card={"name": 1})
        assert r.status_code == 422 and r.json()["detail"] == "InvalidCard"
        assert (await c.get("/api/v1/partners/evil", headers=admin)).status_code == 404
        # the internal tier may use private addresses
        r = await c.post(
            "/api/v1/partners",
            json={"id": "evil", "tier": "internal", "card_url": "https://private.example.com"},
            headers=admin,
        )
        assert r.status_code == 201, r.text
        assert evil.called
        assert tiers[-1] == "internal"

        dup = await register(c, admin, "acme")
        assert dup.status_code == 409 and dup.json()["error"] == "conflict"
        for bad in (
            {"id": "x", "tier": "public"},  # neither card_url nor card
            {"id": "x", "tier": "public", "card_url": url_of("x"), "card": card("X")},
            {"id": "Bad_Id", "tier": "public", "card_url": url_of("x")},
            {"id": "x", "tier": "galaxy", "card_url": url_of("x")},
            {"id": "x", "tier": "public", "card_url": url_of("x"), "status": "approved"},
            {"id": "x", "tier": "public", "card_url": url_of("x"), "credential_ref": "a b"},
        ):
            r = await c.post("/api/v1/partners", json=bad, headers=admin)
            assert r.status_code == 422 and r.json()["error"] == "invalid", bad


def _signing_key(tmp_path: Path) -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    priv = tmp_path / "k1.key"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (tmp_path / "k1.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv


async def test_register_signed_required_tier_unsigned_422(db_url, catalogue_app, run_app, tmp_path):
    from a2a.client.card_resolver import parse_agent_card
    from google.protobuf.json_format import MessageToDict

    from a2agw.security.cardsign import CardSigner

    priv = _signing_key(tmp_path)
    signed = MessageToDict(CardSigner(priv, "k1", "ES256").sign(parse_agent_card(card("Sig"))))
    settings = settings_for(
        db_url, trust={"card_keys": {"k1": "k1.pem"}, "require_signed": ["public"]}
    )
    app = catalogue_app(settings)
    async with run_app(app) as c:
        admin = await admin_key(app)
        r = await register(c, admin, "plain", card=card("Plain"))
        assert r.status_code == 422 and r.json() == {
            "error": "card",
            "detail": "CardSignatureInvalid",
        }
        # the same card on a tier that does not require signatures
        r = await register(c, admin, "plain", card=card("Plain"), tier="partner")
        assert r.status_code == 201, r.text
        assert r.json()["versions"][0]["signed_key_id"] is None
        r = await register(c, admin, "sig", card=signed)
        assert r.status_code == 201, r.text
        assert r.json()["versions"][0]["signed_key_id"].startswith("trusted#k1#")
        # an unsigned partner cannot be moved onto a tier that requires signatures
        r = await c.put("/api/v1/partners/plain/settings", json={"tier": "public"}, headers=admin)
        assert r.status_code == 422 and r.json()["detail"] == "CardSignatureInvalid"
        assert (await c.get("/api/v1/partners/plain", headers=admin)).json()["tier"] == "partner"


# -- approval and desired state -------------------------------------------------------------


async def test_approve_requires_matching_hash(db_url, catalogue_app, run_app):
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        assert (await register(c, admin, "acme", card=card("Acme"))).status_code == 201
        v1 = await latest(c, admin, "acme")
        url = "/api/v1/partners/acme/approve"
        r = await c.post(url, json={"version": 1, "expected_hash": "0" * 64}, headers=admin)
        assert r.status_code == 409 and r.json()["error"] == "conflict"
        r = await c.post(url, json={"version": 2, "expected_hash": v1["card_hash"]}, headers=admin)
        assert r.status_code == 404
        r = await c.post(
            "/api/v1/partners/nope/approve",
            json={"version": 1, "expected_hash": v1["card_hash"]},
            headers=admin,
        )
        assert r.status_code == 404
        r = await c.post(url, json={"version": 1}, headers=admin)
        assert r.status_code == 422
        detail = (await c.get("/api/v1/partners/acme", headers=admin)).json()
        assert detail["status"] == "pending" and detail["current_version"] == 0
        assert await audit_rows(app, "cp.partner.approve") == []
        r = await c.post(url, json={"version": 1, "expected_hash": v1["card_hash"]}, headers=admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "approved" and body["current_version"] == 1
        assert body["approved"]["card_hash"] == v1["card_hash"] and body["pending"] is False
        assert body["approved"]["approved_by"].startswith("ak-")


async def test_approve_recomputes_desired_for_assigned_gateways(db_url, catalogue_app, run_app):
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        store = app.state.store
        g1, _ = await gateway(app, "edge-1")
        g2, _ = await gateway(app, "edge-2")
        assert (await register(c, admin, "acme", card=card("Acme"), tags=["eu"])).status_code == 201
        r = await assign(c, admin, g1, "acme")
        assert r.status_code == 200 and r.json() == {"gateway_id": g1, "partner_ids": ["acme"]}
        await channel.recompute_dirty(store)
        assert (await channel.load_desired(store, g1)).partners == []  # still pending
        assert await channel.dirty_gateways(store) == []

        assert (await approve(c, admin, "acme")).status_code == 200
        assert await channel.dirty_gateways(store) == [g1]  # only the assigned gateway
        await channel.recompute_dirty(store)
        state = await channel.load_desired(store, g1)
        [rec] = state.partners
        assert set(rec) == REMOTE_FIELDS
        assert rec["card"] == normalized(card("Acme")) and rec["card_hash"] == card_hash(
            rec["card"]
        )
        assert rec["tier"] == "public" and rec["tags"] == ["eu"] and rec["card_url"] is None
        assert (await channel.load_desired(store, g2)).partners == []

        # what the catalogue sends passes the gateway's own checks
        registry = PartnerRegistry()
        plan = await registry.prepare_remote(state.partners)
        assert plan.added == ["acme"] and plan.quarantined == {}
        await registry.apply_remote(state.partners)
        assert registry.get("acme").status == "active"

        # an assignment change marks the gateway too; unknown partners are refused
        r = await assign(c, admin, g2, "acme", "nope")
        assert r.status_code == 422 and r.json()["fields"] == ["body.partner_ids.1"]
        assert (await assign(c, admin, "gw-unknown", "acme")).status_code == 404
        assert (await assign(c, admin, g2, "acme")).status_code == 200
        assert await channel.dirty_gateways(store) == [g2]
        assert (await assign(c, admin, g1)).status_code == 200  # replaced by nothing
        assert (await desired(app, g1)).partners == []
        listed = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert [p["gateways"] for p in listed] == [[g2]]


async def test_reject_and_quarantine_remove_from_desired(db_url, catalogue_app, run_app):
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        store = app.state.store
        gid, _ = await gateway(app, "edge-1")
        await register(c, admin, "acme", card=card("Acme"))
        await assign(c, admin, gid, "acme")
        await approve(c, admin, "acme")
        assert [p["id"] for p in (await desired(app, gid)).partners] == ["acme"]

        r = await c.post("/api/v1/partners/acme/quarantine", headers=admin)
        assert r.status_code == 200 and r.json()["status"] == "quarantined"
        assert await channel.dirty_gateways(store) == [gid]
        assert (await desired(app, gid)).partners == []
        assert (await approve(c, admin, "acme")).status_code == 200  # approved again
        assert [p["id"] for p in (await desired(app, gid)).partners] == ["acme"]

        r = await c.post("/api/v1/partners/acme/reject", headers=admin)
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        assert await channel.dirty_gateways(store) == [gid]
        assert (await desired(app, gid)).partners == []
        assert (await c.post("/api/v1/partners/nope/reject", headers=admin)).status_code == 404
        assert (await c.post("/api/v1/partners/nope/quarantine", headers=admin)).status_code == 404


# -- refresh --------------------------------------------------------------------------------


@respx.mock(assert_all_called=False)
async def test_refresh_significant_change_creates_pending_with_diff(
    respx_mock, db_url, catalogue_app, run_app
):
    route = respx_mock.get(card_url_of("acme")).respond(200, json=card("Acme"))
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, _ = await gateway(app, "edge-1")
        await register(c, admin, "acme")
        await assign(c, admin, gid, "acme")
        await approve(c, admin, "acme")
        v1_hash = (await desired(app, gid)).partners[0]["card_hash"]

        changed = card("Acme")
        changed["skills"][0]["description"] = "now does other things"
        route.respond(200, json=changed)
        r = await c.post("/api/v1/partners/acme/refresh", headers=admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outcome"] == "pending"
        assert body["status"] == "approved" and body["pending"] is True
        assert body["current_version"] == 1 and body["pending_version"]["version"] == 2
        assert body["pending_version"]["card"] == normalized(changed)
        [change] = body["diff"]
        assert change == {
            "path": "skills[s1].description",
            "kind": "changed",
            "old": "d",
            "new": "now does other things",
            "significant": True,
        }
        assert [v["version"] for v in body["versions"]] == [1, 2]
        # the gateway keeps the approved card until the new one is approved
        assert await channel.dirty_gateways(app.state.store) == []
        assert (await desired(app, gid)).partners[0]["card_hash"] == v1_hash
        listed = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert listed[0]["card_hash"] == v1_hash and listed[0]["pending"] is True

        # the same card again: nothing new
        r = await c.post("/api/v1/partners/acme/refresh", headers=admin)
        assert r.json()["outcome"] == "unchanged" and len(r.json()["versions"]) == 2

        assert (await approve(c, admin, "acme")).status_code == 200
        assert (await desired(app, gid)).partners[0]["card_hash"] == card_hash(normalized(changed))

        # a partner registered from an inline card has nothing to refresh
        await register(c, admin, "inline", card=card("Inline"))
        r = await c.post("/api/v1/partners/inline/refresh", headers=admin)
        assert r.status_code == 409
        # a fetch failure is a card error and changes nothing
        route.respond(500)
        r = await c.post("/api/v1/partners/acme/refresh", headers=admin)
        assert r.status_code == 422 and r.json()["detail"] == "CardUnavailable"


@respx.mock(assert_all_called=False)
async def test_refresh_cosmetic_auto_applies(respx_mock, db_url, catalogue_app, run_app):
    route = respx_mock.get(card_url_of("acme")).respond(200, json=card("Acme"))
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, _ = await gateway(app, "edge-1")
        await register(c, admin, "acme")
        await assign(c, admin, gid, "acme")
        await approve(c, admin, "acme")
        await desired(app, gid)

        cosmetic = card("Acme", version="1.1", documentationUrl="https://acme.example.com/doc")
        route.respond(200, json=cosmetic)
        r = await c.post("/api/v1/partners/acme/refresh", headers=admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outcome"] == "applied" and body["status"] == "approved"
        assert body["current_version"] == 2 and body["pending"] is False
        assert body["pending_version"] is None and body["diff"] == []
        assert body["approved"]["card"] == normalized(cosmetic)
        assert await channel.dirty_gateways(app.state.store) == [gid]
        [rec] = (await desired(app, gid)).partners
        assert rec["card_hash"] == card_hash(normalized(cosmetic))

        # a cosmetic change of a partner not approved yet waits for approval
        await register(c, admin, "beta", card_url=url_of("acme"))
        route.respond(200, json=card("Acme", version="2.0"))
        r = await c.post("/api/v1/partners/beta/refresh", headers=admin)
        assert r.json()["outcome"] == "pending" and r.json()["current_version"] == 0


# -- gateway reports ------------------------------------------------------------------------


@respx.mock(assert_all_called=False)
async def test_gateway_quarantine_report_shown_and_approve_queues_command(
    respx_mock, db_url, catalogue_app, run_app
):
    route = respx_mock.get(card_url_of("acme")).respond(200, json=card("Acme"))
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        g1, t1 = await gateway(app, "edge-1")
        g2, t2 = await gateway(app, "edge-2")
        await register(c, admin, "acme")
        await assign(c, admin, g1, "acme")
        await assign(c, admin, g2, "acme")
        await approve(c, admin, "acme")
        changed = card("Acme", description="new words")
        route.respond(200, json=changed)
        await c.post("/api/v1/partners/acme/refresh", headers=admin)
        pending_hash = card_hash(normalized(changed))

        def state(status: str, pending: str | None, **extra: Any) -> dict[str, Any]:
            data: dict[str, Any] = {"partner_id": "acme", "status": status, "event": status}
            if pending is not None:
                data["pending_hash"] = pending
            data.update(extra)
            return {"kind": "partner.state", "agent_id": "host", "data": data}

        r = await c.post(
            "/cp/v1/report",
            json={"events": [state("quarantined", pending_hash, card={"name": "Forged"})]},
            headers=bearer(t1),
        )
        assert r.status_code == 200 and r.json()["accepted_events"] == 1
        r = await c.post(
            "/cp/v1/report",
            json={"events": [state("quarantined", "f" * 64)]},
            headers=bearer(t2),
        )
        assert r.status_code == 200
        [item] = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert item["quarantined_on"] == sorted([g1, g2])
        detail = (await c.get("/api/v1/partners/acme", headers=admin)).json()
        by_gw = {g["gateway_id"]: g for g in detail["gateways"]}
        assert by_gw[g1]["status"] == "quarantined" and by_gw[g1]["pending_hash"] == pending_hash
        assert by_gw[g1]["assigned"] is True
        assert "Forged" not in json.dumps(detail)  # a card sent by a gateway is never taken
        assert detail["pending_version"]["card"] == normalized(changed)  # fetched here

        r = await c.post(
            "/api/v1/partners/acme/approve",
            json={"version": 2, "expected_hash": pending_hash},
            headers=admin,
        )
        assert r.status_code == 200, r.text
        async with app.state.engine.connect() as conn:
            cmds = (await conn.execute(select(COMMANDS))).all()
        [cmd] = cmds  # for edge-1 only: edge-2 holds another pending card
        assert cmd.gateway_id == g1 and cmd.kind == "partner.approve"
        assert json.loads(cmd.args_json) == {"id": "acme", "expected_hash": pending_hash}
        assert cmd.actor.startswith("ak-") and cmd.status == "pending"
        assert r.json()["commands"] == [{"gateway_id": g1, "command_id": cmd.id}]

        # the gateway reports the partner active again: no longer shown as quarantined
        await c.post("/cp/v1/report", json={"events": [state("active", None)]}, headers=bearer(t1))
        [item] = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert item["quarantined_on"] == [g2]
        filtered = await c.get("/api/v1/partners", params={"gateway_id": g1}, headers=admin)
        assert [p["id"] for p in filtered.json()["partners"]] == ["acme"]
        # removed on the gateway: its state row goes
        await c.post(
            "/cp/v1/report",
            json={"events": [state("disabled", None, event="removed")]},
            headers=bearer(t2),
        )
        [item] = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert item["quarantined_on"] == []


# -- search ---------------------------------------------------------------------------------


async def test_skill_search_ranks_skill_name_matches_first(db_url, catalogue_app, run_app):
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        named = card(
            "Lingo",
            skills=[
                {"id": "tr", "name": "Translate text", "description": "any language", "tags": []},
                {"id": "sum", "name": "Summarize", "description": "short", "tags": []},
            ],
        )
        described = card(
            "Wordy",
            description="We translate documents",
            skills=[{"id": "w1", "name": "Edit", "description": "edits", "tags": ["pdf"]}],
        )
        tagged = card(
            "Tagger",
            skills=[{"id": "t1", "name": "Classify", "description": "x", "tags": ["translate"]}],
        )
        for pid, c_ in (("lingo", named), ("wordy", described), ("tagger", tagged)):
            assert (await register(c, admin, pid, card=c_, tier="partner")).status_code == 201
            assert (await approve(c, admin, pid)).status_code == 200
        # not approved: never found by default
        hidden = card("Hidden", skills=[{"id": "h", "name": "Translate", "description": "x"}])
        await register(c, admin, "hidden", card=hidden)
        # approved once, then rejected or quarantined: not found by default either
        for pid in ("gone", "held"):
            await register(c, admin, pid, card=card(pid.title(), skills=hidden["skills"]))
            await approve(c, admin, pid)
        await c.post("/api/v1/partners/gone/reject", headers=admin)
        await c.post("/api/v1/partners/held/quarantine", headers=admin)

        r = await c.get("/api/v1/partners", params={"q": "TRANSLATE"}, headers=admin)
        assert r.status_code == 200
        got = [(p["id"], p["matched_skills"]) for p in r.json()["partners"]]
        assert got[0] == ("lingo", ["tr"])  # a skill-name match counts double
        assert sorted(got[1:]) == [("tagger", ["t1"]), ("wordy", [])]

        r = await c.get("/api/v1/partners", params={"q": "translate pdf"}, headers=admin)
        got = [(p["id"], p["matched_skills"]) for p in r.json()["partners"]]
        # lingo: one skill-name match (2); wordy: two other matches (2); tagger: one (1)
        assert got == [("lingo", ["tr"]), ("wordy", ["w1"]), ("tagger", ["t1"])]

        r = await c.get("/api/v1/partners", params={"q": "nothing-like-it"}, headers=admin)
        assert r.json()["partners"] == []

        all_ = (await c.get("/api/v1/partners", headers=admin)).json()["partners"]
        assert [p["id"] for p in all_] == ["lingo", "tagger", "wordy"]  # approved only
        lingo = next(p for p in all_ if p["id"] == "lingo")
        assert lingo["name"] == "Lingo" and lingo["skills_count"] == 2
        assert lingo["status"] == "approved" and lingo["current_version"] == 1
        assert "matched_skills" not in lingo
        # an explicit status filter still lists (and searches) the others
        r = await c.get("/api/v1/partners", params={"status": "pending"}, headers=admin)
        assert [p["id"] for p in r.json()["partners"]] == ["hidden"]
        for status, pid in (("rejected", "gone"), ("quarantined", "held")):
            r = await c.get(
                "/api/v1/partners", params={"status": status, "q": "translate"}, headers=admin
            )
            assert [(p["id"], p["matched_skills"]) for p in r.json()["partners"]] == [(pid, ["h"])]
        r = await c.get("/api/v1/partners", params={"tier": "public"}, headers=admin)
        assert r.json()["partners"] == []  # hidden is public but pending
        r = await c.get(
            "/api/v1/partners", params={"tier": "public", "status": "pending"}, headers=admin
        )
        assert [p["id"] for p in r.json()["partners"]] == ["hidden"]
        r = await c.get("/api/v1/partners", params={"status": "bogus"}, headers=admin)
        assert r.status_code == 422


# -- secrets, permissions, audit ------------------------------------------------------------


async def test_detail_never_contains_secrets(db_url, catalogue_app, run_app):
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        _kid, key = await app.state.store.create_api_key("admin", "admin", actor="t")
        admin = {"authorization": f"Bearer {key}"}
        session = await signed_in(app, ["admin"])
        r = await register(
            c, session, "acme", card=card("Acme"), credential_ref="acme-oauth", tls_ref="acme-mtls"
        )
        assert r.status_code == 201, r.text
        await approve(c, admin, "acme")
        texts = [
            (await c.get("/api/v1/partners/acme", headers=session)).text,
            (await c.get("/api/v1/partners", headers=admin)).text,
            r.text,
        ]
        detail = json.loads(texts[0])
        assert detail["credential_ref"] == "acme-oauth" and detail["tls_ref"] == "acme-mtls"
        secrets = [key, session["x-a2agw-csrf"], session["cookie"].split("=", 1)[1]]
        rows = await audit_rows(app)
        for text in [*texts, json.dumps(rows)]:
            for secret in secrets:
                assert secret not in text
        for row in rows:
            assert set(row["detail"]) <= DETAIL_KEYS
        assert "Acme does things" not in json.dumps(rows)  # no card content in the audit


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        ("viewer", {"read"}),
        ("operator", {"read"}),
        ("security", {"read", "trust"}),
        ("admin", {"read", "trust", "register", "assign"}),
    ],
)
async def test_permissions(role, allowed, sqlite_settings, catalogue_app, run_app):
    app = catalogue_app(sqlite_settings)
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, _ = await gateway(app, "edge-1")
        await register(c, admin, "acme", card=card("Acme"))
        v = await latest(c, admin, "acme")
        headers = await signed_in(app, [role])
        calls = {
            "read": [("GET", "/api/v1/partners", None), ("GET", "/api/v1/partners/acme", None)],
            "register": [
                ("POST", "/api/v1/partners", {"id": "b", "tier": "public", "card": card("B")}),
                ("POST", "/api/v1/partners/acme/refresh", None),
            ],
            "trust": [
                (
                    "POST",
                    "/api/v1/partners/acme/approve",
                    {"version": 1, "expected_hash": v["card_hash"]},
                ),
                ("PUT", "/api/v1/partners/acme/settings", {"tags": ["x"]}),
                ("POST", "/api/v1/partners/acme/quarantine", None),
                ("POST", "/api/v1/partners/acme/reject", None),
            ],
            "assign": [("PUT", f"/api/v1/gateways/{gid}/partners", {"partner_ids": ["acme"]})],
        }
        for group, requests in calls.items():
            for method, path, body in requests:
                r = await c.request(method, path, json=body, headers=headers)
                if group in allowed:
                    assert r.status_code < 400 or r.status_code == 409, (role, path, r.text)
                else:
                    assert r.status_code == 403, (role, path, r.text)
                    assert r.json()["error"] == "forbidden"
        # a session write without the CSRF header is refused, whatever the role
        no_csrf = {"cookie": headers["cookie"]}
        r = await c.post("/api/v1/partners/acme/quarantine", headers=no_csrf)
        assert r.status_code == 403 and r.json()["error"] == "csrf"
        assert (await c.get("/api/v1/partners")).status_code == 401


@respx.mock(assert_all_called=False)
async def test_every_write_audited(respx_mock, db_url, catalogue_app, run_app):
    route = respx_mock.get(card_url_of("acme")).respond(200, json=card("Acme"))
    app = catalogue_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        gid, _token = await gateway(app, "edge-1")
        await register(c, admin, "acme", tier="partner")
        await assign(c, admin, gid, "acme")
        await approve(c, admin, "acme")
        route.respond(200, json=card("Acme", version="9"))
        await c.post("/api/v1/partners/acme/refresh", headers=admin)
        r = await c.put(
            "/api/v1/partners/acme/settings",
            json={"tier": "public", "tags": ["eu"], "credential_ref": "acme-oauth"},
            headers=admin,
        )
        assert r.status_code == 200, r.text
        assert r.json()["tier"] == "public" and r.json()["tags"] == ["eu"]
        r = await c.put(
            "/api/v1/partners/acme/settings", json={"credential_ref": None}, headers=admin
        )
        assert r.status_code == 200 and r.json()["credential_ref"] is None
        # settings that change nothing write nothing
        await c.put("/api/v1/partners/acme/settings", json={"tier": "public"}, headers=admin)
        await c.post("/api/v1/partners/acme/quarantine", headers=admin)
        await c.post("/api/v1/partners/acme/reject", headers=admin)

        rows = [
            r
            for r in await audit_rows(app)
            if r["action"].startswith("cp.partner") or r["action"] == "cp.assign"
        ]
        assert [(r["action"], r["outcome"]) for r in rows] == [
            ("cp.partner.register", "pending"),
            ("cp.assign", "assigned"),
            ("cp.partner.approve", "approved"),
            ("cp.partner.refresh", "applied"),
            ("cp.partner.update", "updated"),
            ("cp.partner.update", "updated"),
            ("cp.partner.quarantine", "quarantined"),
            ("cp.partner.reject", "rejected"),
        ]
        for row in rows:
            assert row["actor"].startswith("ak-")
        register_row, assign_row, approve_row, refresh_row, tier_row, clear_row = rows[:6]
        assert register_row["detail"] == {
            "tier": "partner",
            "version": 1,
            "hash": card_hash(normalized(card("Acme"))),
        }
        assert assign_row["detail"] == {"gateway": gid, "count": 1}
        assert approve_row["detail"]["version"] == 1 and approve_row["detail"]["count"] == 0
        assert refresh_row["detail"]["version"] == 2
        assert tier_row["detail"] == {
            "fields": "credential_ref,tags,tier",
            "tier": "public",
            "reason": "trust",  # a tier change is a trust change
        }
        assert clear_row["detail"] == {"fields": "credential_ref", "tier": "public"}
        async with app.state.engine.connect() as conn:
            from sqlalchemy import text

            partner_ids = (
                await conn.execute(
                    text("SELECT partner_id FROM cp_audit WHERE action LIKE 'cp.partner.%'")
                )
            ).scalars()
            assert set(partner_ids) == {"acme"}
