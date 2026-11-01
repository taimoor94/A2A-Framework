"""Gateway management routes: create (token shown once), list, rotate, revoke."""

from __future__ import annotations

import json

import pytest
from oidc_fake import audit_rows, signed_in
from sqlalchemy import select, text

pytest.importorskip("fastapi")

from a2agw.control import channel
from a2agw.control.settings import ControlSettings
from a2agw.control.store import GATEWAY_TOKENS, token_digest

KEEPALIVE_S = 5.0


def settings_for(db_url: str) -> ControlSettings:
    return ControlSettings(
        base_url="https://cp.example",
        db_url=db_url,
        limits={"stream_keepalive_s": KEEPALIVE_S},
    )


async def admin_key(app) -> dict[str, str]:
    _id, key = await app.state.store.create_api_key("admin", "admin", actor="t")
    return {"authorization": f"Bearer {key}"}


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def test_create_shows_token_once(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        r = await c.post("/api/v1/gateways", json={"name": "edge-1"}, headers=admin)
        assert r.status_code == 201, r.text
        body = r.json()
        assert set(body) == {"id", "name", "token"} and body["name"] == "edge-1"
        assert r.headers["cache-control"] == "no-store"
        token = body["token"]
        # the token works on the gateway channel
        ok = await c.post("/cp/v1/report", json={}, headers=bearer(token))
        assert ok.status_code == 200
        # and is never shown again, nor stored or audited
        listed = await c.get("/api/v1/gateways", headers=admin)
        assert listed.status_code == 200 and token not in listed.text
        [gw] = listed.json()["gateways"]
        assert gw["id"] == body["id"] and gw["name"] == "edge-1" and gw["status"] == "active"
        async with app.state.engine.connect() as conn:
            dump = []
            for table in ("cp_gateways", "cp_gateway_tokens", "cp_audit"):
                dump += [list(r) for r in (await conn.execute(text(f"SELECT * FROM {table}")))]
        assert token not in json.dumps(dump, default=str)
        assert token_digest(token) in json.dumps(dump, default=str)
        [row] = await audit_rows(app, "cp.gateway.create")
        assert row["detail"] == {"gateway": body["id"]} and row["actor"].startswith("ak-")
        dup = await c.post("/api/v1/gateways", json={"name": "edge-1"}, headers=admin)
        assert dup.status_code == 409 and dup.json()["error"] == "conflict"
        for bad in ({}, {"name": ""}, {"name": "x", "id": "gw-mine"}):
            r = await c.post("/api/v1/gateways", json=bad, headers=admin)
            assert r.status_code == 422, bad


async def test_rotate_revokes_old(db_url, make_app, run_app):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        created = (await c.post("/api/v1/gateways", json={"name": "edge-1"}, headers=admin)).json()
        gid, old = created["id"], created["token"]
        r = await c.post(f"/api/v1/gateways/{gid}/tokens", headers=admin)
        assert r.status_code == 200, r.text
        assert r.headers["cache-control"] == "no-store"
        new = r.json()["token"]
        assert r.json() == {"id": gid, "token": new} and new != old
        assert (await c.post("/cp/v1/report", json={}, headers=bearer(old))).status_code == 401
        assert (await c.post("/cp/v1/report", json={}, headers=bearer(new))).status_code == 200
        async with app.state.engine.connect() as conn:
            tokens = (await conn.execute(select(GATEWAY_TOKENS))).all()
        assert sorted(t.revoked_at is None for t in tokens) == [False, True]
        missing = await c.post("/api/v1/gateways/gw-nope/tokens", headers=admin)
        assert missing.status_code == 404
        # revoke: every token stops working; rotating afterwards is refused
        r = await c.post(f"/api/v1/gateways/{gid}/revoke", headers=admin)
        assert r.status_code == 200 and r.json() == {"id": gid, "status": "revoked"}
        assert (await c.post("/cp/v1/report", json={}, headers=bearer(new))).status_code == 401
        again = await c.post(f"/api/v1/gateways/{gid}/revoke", headers=admin)
        assert again.status_code == 200  # idempotent
        refused = await c.post(f"/api/v1/gateways/{gid}/tokens", headers=admin)
        assert refused.status_code == 409
        assert (await c.post("/api/v1/gateways/gw-nope/revoke", headers=admin)).status_code == 404
        [listed] = (await c.get("/api/v1/gateways", headers=admin)).json()["gateways"]
        assert listed["status"] == "revoked" and listed["connected"] is False
        revokes = await audit_rows(app, "cp.gateway.revoke")
        assert len(revokes) == 1 and revokes[0]["detail"] == {"gateway": gid}


async def test_list_connected_flag(db_url, make_app, run_app, clock):
    app = make_app(settings_for(db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        created = (await c.post("/api/v1/gateways", json={"name": "edge-1"}, headers=admin)).json()
        [gw] = (await c.get("/api/v1/gateways", headers=admin)).json()["gateways"]
        assert gw == {
            "id": created["id"],
            "name": "edge-1",
            "status": "active",
            "last_seen_at": None,
            "connected": False,
            "version_applied": 0,
            "version_desired": 0,
            "epoch_applied": None,
            "epoch_desired": None,
            "last_rejection": None,
            "info": {},
        }
        desired = await channel.compute_desired(app.state.store, created["id"])
        info = {"version": "1.4.0", "agents": ["alpha"], "base_url": "https://g"}
        applied = {
            "epoch": desired.epoch,
            "version": desired.version,
            "hash": desired.hash,
            "status": "applied",
        }
        r = await c.post(
            "/cp/v1/report",
            json={"info": info, "applied": applied},
            headers=bearer(created["token"]),
        )
        assert r.status_code == 200
        [gw] = (await c.get("/api/v1/gateways", headers=admin)).json()["gateways"]
        assert gw["connected"] is True and gw["last_seen_at"] == clock.t
        assert gw["version_applied"] == gw["version_desired"] == desired.version
        assert gw["epoch_applied"] == gw["epoch_desired"] == app.state.store.epoch
        assert gw["info"] == info
        clock.advance(2 * KEEPALIVE_S - 1)
        [gw] = (await c.get("/api/v1/gateways", headers=admin)).json()["gateways"]
        assert gw["connected"] is True
        clock.advance(2)
        [gw] = (await c.get("/api/v1/gateways", headers=admin)).json()["gateways"]
        assert gw["connected"] is False


ROUTES = [
    ("POST", "/api/v1/gateways"),
    ("GET", "/api/v1/gateways"),
    ("POST", "/api/v1/gateways/gw-x/tokens"),
    ("POST", "/api/v1/gateways/gw-x/revoke"),
]


async def test_permissions(sqlite_settings, make_app, run_app):
    app = make_app(sqlite_settings)
    async with run_app(app) as c:
        _gid, gateway_token = await app.state.store.create_gateway("edge-1", actor="t")
        for method, path in ROUTES:
            kw = {"json": {"name": "n"}} if path == "/api/v1/gateways" and method == "POST" else {}
            for role in ("viewer", "operator", "security"):
                headers = await signed_in(app, [role], user=f"oidc:{role}")
                r = await c.request(method, path, headers=headers, **kw)
                assert r.status_code == 403, (method, path, role)
            assert (await c.request(method, path, **kw)).status_code == 401
            # a gateway token is not a console credential
            r = await c.request(method, path, headers=bearer(gateway_token), **kw)
            assert r.status_code == 401, (method, path)
            admin = await signed_in(app, ["admin"], user="oidc:admin")
            r = await c.request(method, path, headers=admin, **kw)
            assert r.status_code not in (401, 403), (method, path, r.text)
