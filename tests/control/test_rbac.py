"""Control-plane roles: every route declares its permission, the role matrix, CSRF."""

from __future__ import annotations

import pytest
from oidc_fake import COOKIE, audit_rows, oidc_settings, signed_in

pytest.importorskip("fastapi")

from a2agw.control import app as app_mod  # noqa: F401 - registers the app's routes
from a2agw.control.rbac import (
    ROLE_PERMISSIONS,
    ROUTE_PERMISSIONS,
    Permission,
    Routes,
    permissions_for,
    require,
    require_gateway,
)
from a2agw.control.settings import ROLES

WRITES = {"POST", "PUT", "PATCH", "DELETE"}

# One probe route per permission (writes for most, reads for the read permissions), so
# every permission is checked against every role even before the routes using it exist.
PROBES = Routes()
_READS = {Permission.READ, Permission.AUDIT_READ}
for _perm in Permission:
    _method = "GET" if _perm in _READS else "POST"

    @PROBES.route(_method, f"/api/v1/_probe/{_perm.value}", _perm)
    async def _probe() -> dict[str, str]:
        return {"ok": "yes"}


@PROBES.gateway_route("POST", "/cp/v1/_probe")
async def _gateway_probe() -> dict[str, str]:
    return {"ok": "yes"}


ALL_ROUTES = {**ROUTE_PERMISSIONS, **PROBES.permissions}
PERMISSION_ROUTES = sorted(
    (key for key, access in ALL_ROUTES.items() if isinstance(access, Permission)),
)
PUBLIC_ROUTES = sorted(key for key, access in ROUTE_PERMISSIONS.items() if access == "public")
GATEWAY_ROUTES = sorted(key for key, access in ALL_ROUTES.items() if access == "gateway")
ROLE_CASES = [*ROLES, "none"]  # "none": signed in, but no mapped role


def _app(make_app, tmp_path):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    PROBES.mount(app)
    return app


def _path(path: str) -> str:
    return path.replace("{", "").replace("}", "")  # a path parameter becomes its own name


async def _call(c, method: str, path: str, headers: dict[str, str]):
    kw = {"json": {}} if method in WRITES else {}
    return await c.request(method, _path(path), headers=headers, **kw)


def test_every_route_declares_permission(sqlite_settings):
    from a2agw.control.app import create_app

    app = create_app(sqlite_settings)
    seen = set()
    for r in app.routes:
        methods = sorted(getattr(r, "methods", None) or [])
        assert methods, f"{r.path}: not an API route"
        for method in methods:
            if method == "HEAD":
                continue
            key = (method, r.path)
            seen.add(key)
            assert key in ROUTE_PERMISSIONS, f"{key} declares no permission"
            access = ROUTE_PERMISSIONS[key]
            assert isinstance(access, Permission) or access in ("public", "gateway"), key
            # the declared permission is the one enforced
            calls = [d.call for d in r.dependant.dependencies]
            if isinstance(access, Permission):
                assert require(access) in calls, key
            elif access == "gateway":
                assert require_gateway in calls, key
            assert (access == "gateway") == r.path.startswith("/cp/v1/"), key
    assert seen == set(ROUTE_PERMISSIONS)
    assert ("GET", "/api/openapi.json") in seen and ROUTE_PERMISSIONS[
        ("GET", "/api/openapi.json")
    ] is Permission.READ
    assert {("GET", "/auth/login"), ("GET", "/auth/callback"), ("POST", "/auth/logout")} <= set(
        PUBLIC_ROUTES
    )


@pytest.mark.parametrize("role", ROLE_CASES)
@pytest.mark.parametrize("route", PERMISSION_ROUTES, ids=lambda r: f"{r[0]} {r[1]}")
async def test_role_matrix(route, role, tmp_path, make_app, run_app):
    method, path = route
    permission = ALL_ROUTES[route]
    allowed = role != "none" and permission in ROLE_PERMISSIONS[role]
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        headers = await signed_in(app, [] if role == "none" else [role])
        r = await _call(c, method, path, headers)
        denied = await audit_rows(app, "cp.denied")
    if allowed:
        assert r.status_code != 403, (route, role, r.text)
        assert denied == []
    else:
        assert r.status_code == 403 and r.json()["error"] == "forbidden", (route, role, r.text)
        [row] = denied
        assert row["actor"] == "oidc:u1" and row["outcome"] == "denied"
        assert row["detail"]["reason"] == "permission"
        assert row["detail"]["rule"] == permission.value


@pytest.mark.parametrize("route", PUBLIC_ROUTES, ids=lambda r: f"{r[0]} {r[1]}")
async def test_public_routes_never_403_for_any_role(route, tmp_path, idp, make_app, run_app):
    method, path = route
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        for role in ROLE_CASES:
            headers = await signed_in(app, [] if role == "none" else [role], user=f"oidc:{role}")
            r = await _call(c, method, path, headers)
            assert r.status_code != 403, (route, role, r.text)
        assert await audit_rows(app, "cp.denied") == []


@pytest.mark.parametrize("route", GATEWAY_ROUTES, ids=lambda r: f"{r[0]} {r[1]}")
async def test_gateway_routes_reject_user_sessions_and_api_keys(route, tmp_path, make_app, run_app):
    """Every /cp/v1 route (Task 6 adds them; a probe stands in until then) takes gateway
    tokens only: an admin's session or API key gets 401."""
    method, path = route
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        session = await signed_in(app, ["admin"])
        _key_id, key = await app.state.store.create_api_key("k", "admin", actor="t")
        for headers in (session, {"authorization": f"Bearer {key}"}, {}):
            r = await _call(c, method, path, headers)
            assert r.status_code == 401, (route, headers.keys(), r.text)


def test_role_permissions_table():
    viewer = {Permission.READ}
    assert ROLE_PERMISSIONS["viewer"] == viewer
    assert ROLE_PERMISSIONS["operator"] == viewer | {Permission.TASKS_OPERATE}
    assert ROLE_PERMISSIONS["security"] == viewer | {
        Permission.PARTNERS_TRUST,
        Permission.POLICY_EDIT,
        Permission.AUDIT_READ,
    }
    assert ROLE_PERMISSIONS["admin"] == frozenset(Permission)
    assert set(ROLE_PERMISSIONS) == set(ROLES)
    assert {p.value for p in Permission} == {
        "read",
        "tasks.operate",
        "partners.register",
        "partners.trust",
        "policy.edit",
        "assign",
        "audit.read",
        "gateways.manage",
        "users.manage",
        "apikeys.manage",
        "settings.manage",
    }


async def test_union_of_roles(tmp_path, make_app, run_app):
    both = permissions_for(frozenset({"operator", "security"}))
    assert both == ROLE_PERMISSIONS["operator"] | ROLE_PERMISSIONS["security"]
    assert permissions_for(frozenset()) == frozenset()
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        headers = await signed_in(app, ["operator", "security"])
        got = {
            p: (await _call(c, "POST", f"/api/v1/_probe/{p.value}", headers)).status_code
            for p in (Permission.TASKS_OPERATE, Permission.POLICY_EDIT, Permission.GATEWAYS_MANAGE)
        }
        me = (await c.get("/api/v1/me", headers=headers)).json()
    assert got == {
        Permission.TASKS_OPERATE: 200,
        Permission.POLICY_EDIT: 200,
        Permission.GATEWAYS_MANAGE: 403,
    }
    assert me["roles"] == ["operator", "security"]
    assert set(me["permissions"]) == {p.value for p in both}


async def test_csrf_needed_for_session_writes_not_api_keys(tmp_path, make_app, run_app):
    write = f"/api/v1/_probe/{Permission.SETTINGS_MANAGE.value}"
    read = f"/api/v1/_probe/{Permission.READ.value}"
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        session = await signed_in(app, ["admin"])
        cookie = {"cookie": session["cookie"]}
        no_csrf = await c.post(write, json={}, headers=cookie)
        bad_csrf = await c.post(write, json={}, headers={**cookie, "x-a2agw-csrf": "x" * 43})
        with_csrf = await c.post(write, json={}, headers=session)
        read_r = await c.get(read, headers=cookie)
        _key_id, key = await app.state.store.create_api_key("ci", "admin", actor="t")
        api_key = await c.post(write, json={}, headers={"authorization": f"Bearer {key}"})
        # a bearer header that is not a key is refused; it never falls back to the cookie
        mixed = await c.post(
            write, json={}, headers={**session, "authorization": "Bearer not-a-key"}
        )
        denied = await audit_rows(app, "cp.denied")
    for r in (no_csrf, bad_csrf):
        assert r.status_code == 403 and r.json()["error"] == "csrf", r.text
    assert with_csrf.status_code == 200 and read_r.status_code == 200
    assert api_key.status_code == 200
    assert mixed.status_code == 401
    assert denied == []  # a CSRF refusal is not a permission denial


async def test_unauthenticated_is_401(tmp_path, make_app, run_app):
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        r = await c.get(f"/api/v1/_probe/{Permission.READ.value}")
        expired_cookie = await c.get(
            f"/api/v1/_probe/{Permission.READ.value}", headers={"cookie": f"{COOKIE}=nope"}
        )
    for resp in (r, expired_cookie):
        assert resp.status_code == 401 and resp.json()["error"] == "unauthorized"


async def test_denials_are_coalesced(tmp_path, make_app, run_app):
    path = f"/api/v1/_probe/{Permission.GATEWAYS_MANAGE.value}"
    app = _app(make_app, tmp_path)
    async with run_app(app) as c:
        headers = await signed_in(app, ["viewer"])
        statuses = [(await c.post(path, json={}, headers=headers)).status_code for _ in range(5)]
        rows = await audit_rows(app, "cp.denied")
        await app.state.audit.flush_coalesced()
        flushed = await audit_rows(app, "cp.denied")
    assert statuses == [403] * 5
    assert len(rows) == 1
    assert len(flushed) + sum(r["detail"].get("count", 0) for r in flushed) == 5


def test_public_writes_must_say_they_check_csrf():
    """A public route that is not GET/HEAD/OPTIONS has no require() to check CSRF for it:
    registering one needs csrf_checked=True (the handler checks it, like /auth/logout)."""
    routes = Routes()
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(ValueError, match="csrf_checked"):
            routes.public(method, f"/api/v1/_open_{method.lower()}")

    async def handler() -> None:
        return None

    routes.public("GET", "/api/v1/_open_get")(handler)  # safe methods need no flag
    routes.public("POST", "/api/v1/_checked", csrf_checked=True)(handler)
    assert routes.permissions == {
        ("GET", "/api/v1/_open_get"): "public",
        ("POST", "/api/v1/_checked"): "public",
    }
