"""Console admin routes: users (disable ends sessions), API keys (shown once, role
ceiling), redacted settings, and who may call each read and admin route."""

from __future__ import annotations

from typing import Any

import pytest
from oidc_fake import CLIENT_SECRET, CLIENT_SECRET_ENV, audit_rows, oidc_settings, signed_in
from sqlalchemy import func, select

pytest.importorskip("fastapi")

from a2agw.control import admin as admin_mod
from a2agw.control import rbac
from a2agw.control.rbac import Permission
from a2agw.control.settings import ControlSettings
from a2agw.control.store import API_KEYS, SESSIONS
from a2agw.ops.audit import DETAIL_KEYS


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def admin_key(app: Any) -> dict[str, str]:
    _id, key = await app.state.store.create_api_key("admin", "admin", actor="t")
    return bearer(key)


async def sessions_of(app: Any, user: str) -> int:
    async with app.state.engine.connect() as conn:
        return int(
            (
                await conn.execute(
                    select(func.count()).select_from(SESSIONS).where(SESSIONS.c.user_id == user)
                )
            ).scalar_one()
        )


async def test_disable_user_ends_sessions(db_url, make_app, run_app):
    app = make_app(ControlSettings(base_url="https://cp.example", db_url=db_url))
    async with run_app(app) as c:
        admin = await signed_in(app, ["admin"], user="oidc:boss")
        victim = await signed_in(app, ["viewer"], user="oidc:u2")
        await signed_in(app, ["viewer"], user="oidc:u2")  # a second session
        assert (await c.get("/api/v1/overview", headers=victim)).status_code == 200
        listed = (await c.get("/api/v1/users", headers=admin)).json()
        no_csrf = await c.patch(
            "/api/v1/users/oidc:u2",
            json={"disabled": True},
            headers={"cookie": admin["cookie"]},
        )
        extra = await c.patch("/api/v1/users/oidc:u2", json={"roles": ["admin"]}, headers=admin)
        unknown = await c.patch("/api/v1/users/oidc:nobody", json={"disabled": True}, headers=admin)
        assert await sessions_of(app, "oidc:u2") == 2
        r = await c.patch("/api/v1/users/oidc:u2", json={"disabled": True}, headers=admin)
        left = await sessions_of(app, "oidc:u2")
        after = await c.get("/api/v1/overview", headers=victim)
        users = (await c.get("/api/v1/users", headers=admin)).json()
        enabled = await c.patch("/api/v1/users/oidc:u2", json={"disabled": False}, headers=admin)
        rows = await audit_rows(app, "cp.user.update")

    assert [u["id"] for u in listed["items"]] == ["oidc:boss", "oidc:u2"]
    assert listed["next_cursor"] is None
    assert set(listed["items"][1]) == {
        "id",
        "email",
        "name",
        "roles",
        "disabled",
        "created_at",
        "last_login_at",
    }
    assert no_csrf.status_code == 403 and no_csrf.json()["error"] == "csrf"
    assert extra.status_code == 422 and extra.json()["fields"] == ["body.roles"]
    assert unknown.status_code == 404
    assert r.status_code == 200 and r.json()["disabled"] is True and r.json()["id"] == "oidc:u2"
    assert left == 0
    assert after.status_code == 401
    assert [u["disabled"] for u in users["items"]] == [False, True]
    assert enabled.status_code == 200 and enabled.json()["disabled"] is False
    assert [(x["actor"], x["outcome"], x["detail"]) for x in rows] == [
        ("oidc:boss", "disabled", {"user": "oidc:u2"}),
        ("oidc:boss", "enabled", {"user": "oidc:u2"}),
    ]


async def test_api_key_shown_once_and_role_ceiling(db_url, make_app, run_app, monkeypatch):
    app = make_app(ControlSettings(base_url="https://cp.example", db_url=db_url))
    async with run_app(app) as c:
        admin = await admin_key(app)
        r = await c.post("/api/v1/api-keys", json={"name": "ci", "role": "viewer"}, headers=admin)
        assert r.status_code == 201, r.text
        created = r.json()
        assert set(created) == {"id", "name", "role", "key"}
        assert r.headers["cache-control"] == "no-store"
        key = created["key"]
        works = await c.get("/api/v1/overview", headers=bearer(key))
        listed = await c.get("/api/v1/api-keys", headers=admin)
        async with app.state.engine.connect() as conn:
            digests = list((await conn.execute(select(API_KEYS.c.digest))).scalars())
        revoked = await c.post(f"/api/v1/api-keys/{created['id']}/revoke", headers=admin)
        after = await c.get("/api/v1/overview", headers=bearer(key))
        again = await c.post(f"/api/v1/api-keys/{created['id']}/revoke", headers=admin)
        unknown = await c.post("/api/v1/api-keys/ak-nope/revoke", headers=admin)
        bad_role = await c.post(
            "/api/v1/api-keys", json={"name": "x", "role": "root"}, headers=admin
        )
        # a role that may manage keys without holding every permission: its ceiling bites
        widened = rbac.ROLE_PERMISSIONS["security"] | {Permission.APIKEYS_MANAGE}
        monkeypatch.setitem(rbac.ROLE_PERMISSIONS, "security", widened)
        sec = await signed_in(app, ["security"])
        above = await c.post("/api/v1/api-keys", json={"name": "y", "role": "admin"}, headers=sec)
        operator = await c.post(
            "/api/v1/api-keys", json={"name": "y", "role": "operator"}, headers=sec
        )
        below = await c.post("/api/v1/api-keys", json={"name": "z", "role": "viewer"}, headers=sec)
        own = await c.post("/api/v1/api-keys", json={"name": "s", "role": "security"}, headers=sec)
        creates = await audit_rows(app, "cp.apikey.create")

    assert works.status_code == 200
    assert listed.status_code == 200
    body = listed.text
    assert key not in body and not any(d in body for d in digests)
    items = {k["id"]: k for k in listed.json()["items"]}
    mine = items[created["id"]]
    assert set(mine) == {
        "id",
        "name",
        "role",
        "created_by",
        "created_at",
        "revoked_at",
        "last_used_at",
    }
    assert mine["role"] == "viewer" and mine["revoked_at"] is None
    assert revoked.status_code == 200 and revoked.json() == {
        "id": created["id"],
        "status": "revoked",
    }
    assert after.status_code == 401
    assert again.status_code == 200
    assert unknown.status_code == 404
    assert bad_role.status_code == 422 and bad_role.json()["fields"] == ["body.role"]
    assert above.status_code == 403 and above.json()["error"] == "forbidden"
    assert operator.status_code == 403  # tasks.operate is not the caller's
    assert below.status_code == 201 and own.status_code == 201
    assert all(set(r["detail"]) <= DETAIL_KEYS for r in creates)
    assert [r["detail"]["role"] for r in creates] == ["admin", "viewer", "viewer", "security"]


def test_settings_redaction_unit():
    settings = ControlSettings.model_validate(
        {
            "base_url": "https://cp.example",
            "db_url": "postgresql+asyncpg://cp:hunter2@db.internal:5432/cp",
            "oidc": {
                "issuer": "https://idp.example",
                "client_id": "cp",
                "client_secret_env": "CP_OIDC_SECRET",
            },
            "trust": {
                "card_keys": {"k1": "keys/k1.pem"},
                "context_issuers": {"iss": {"issuer": "https://iss.example", "key_file": "i.pem"}},
            },
        }
    )
    out = admin_mod.redacted_settings(settings)
    text = repr(out)
    assert "hunter2" not in text and "CP_OIDC_SECRET" not in text
    assert out["db_url"] == "postgresql+asyncpg://cp:***@db.internal:5432/cp"
    assert "client_secret_env" not in out["oidc"]
    assert out["oidc"]["client_id"] == "cp"
    assert out["trust"]["card_keys"] == {"k1": "keys/k1.pem"}
    assert out["session"]["idle_s"] == 3600


async def test_settings_redacted(db_url, make_app, run_app, idp):
    app = make_app(oidc_settings(db_url))
    async with run_app(app) as c:
        r = await c.get("/api/v1/settings", headers=await admin_key(app))
    assert r.status_code == 200, r.text
    body = r.json()
    assert CLIENT_SECRET not in r.text and CLIENT_SECRET_ENV not in r.text
    assert "client_secret_env" not in body["oidc"]
    assert body["oidc"]["role_map"]["cp-admins"] == "admin"
    assert body["base_url"] == "https://cp.example"
    assert body["limits"]["report_max_items"] == 1000


READS = [
    "/api/v1/overview",
    "/api/v1/agents",
    "/api/v1/tasks",
    "/api/v1/topology",
    "/api/v1/credentials",
]
AUDITS = ["/api/v1/audit", "/api/v1/audit/export", "/api/v1/audit/verify"]
ADMIN = ["/api/v1/users", "/api/v1/api-keys", "/api/v1/settings"]


@pytest.mark.parametrize("role", ["viewer", "operator", "security", "admin"])
async def test_permissions(role, tmp_path, make_app, run_app):
    db = f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"
    app = make_app(ControlSettings(base_url="https://cp.example", db_url=db))
    async with run_app(app) as c:
        headers = await signed_in(app, [role])
        status = {p: (await c.get(p, headers=headers)).status_code for p in READS + AUDITS + ADMIN}
        anonymous = {p: (await c.get(p)).status_code for p in READS + AUDITS + ADMIN}
        write = await c.post(
            "/api/v1/api-keys", json={"name": "k", "role": "viewer"}, headers=headers
        )
        patch = await c.patch("/api/v1/users/oidc:u1", json={}, headers=headers)
    assert set(anonymous.values()) == {401}
    assert all(status[p] == 200 for p in READS), status
    audit_ok = role in ("security", "admin")
    assert all((status[p] == 200) == audit_ok for p in AUDITS), status
    assert all((status[p] == 200) == (role == "admin") for p in ADMIN), status
    assert all(status[p] == 403 for p in ADMIN if role != "admin"), status
    assert write.status_code == (201 if role == "admin" else 403)
    assert patch.status_code == (200 if role == "admin" else 403)
    assert admin_mod.MANAGE is Permission.GATEWAYS_MANAGE  # the existing routes are kept
