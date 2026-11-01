"""Control-plane sign-in: OIDC (authorization code + PKCE, server side), session cookies,
CSRF, API keys, disabled users, and secrets kept out of logs."""

from __future__ import annotations

import json
import logging
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import pytest
from oidc_fake import (
    CLIENT_ID,
    CLIENT_SECRET,
    COOKIE,
    ISSUER,
    audit_rows,
    login,
    oidc_settings,
    s256,
)

LOGIN_COOKIE = "a2agw_login"
from sqlalchemy import select

from a2agw.control.store import LOGIN_STATES, SESSIONS, USERS, csrf_token_for, token_digest

pytest.importorskip("fastapi")


def _cookie(response) -> SimpleCookie:
    jar = SimpleCookie()
    for header in response.headers.get_list("set-cookie"):
        jar.load(header)
    return jar


async def _rows(app, table) -> list[dict]:
    async with app.state.engine.connect() as conn:
        return [dict(r._mapping) for r in (await conn.execute(select(table))).all()]


async def test_login_redirect_has_state_nonce_pkce(tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        r = await c.get("/auth/login", params={"next": "/partners?tab=pending"})
        states = await _rows(app, LOGIN_STATES)
    assert r.status_code == 302
    assert r.headers["cache-control"] == "no-store"
    loc = urlsplit(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/authorize"
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert q["response_type"] == "code" and q["client_id"] == CLIENT_ID
    assert q["redirect_uri"] == "https://cp.example/auth/callback"
    assert q["scope"] == "openid profile email"
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    assert len(q["state"]) >= 43 and len(q["nonce"]) >= 43 and q["state"] != q["nonce"]
    # kept server side: the state and nonce only as digests, the verifier matching the challenge
    [row] = states
    assert row["state_digest"] == token_digest(q["state"])
    assert row["nonce"] == token_digest(q["nonce"])
    assert s256(row["code_verifier"]) == q["code_challenge"]
    assert row["next_path"] == "/partners?tab=pending"
    assert q["state"] not in json.dumps(states) and q["nonce"] not in json.dumps(states)


BAD_CASES = [
    "state",
    "state_reused",
    "state_expired",
    "nonce",
    "iss",
    "aud",
    "exp",
    "sig",
    "alg",
    "kty",
    "iat_future",
    "no_iat",
]


@pytest.mark.parametrize("case", BAD_CASES)
async def test_callback_rejects_bad_state_nonce_iss_aud_exp(
    case, tmp_path, idp, clock, make_app, run_app
):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        start = await c.get("/auth/login")
        code, state = idp.authorize(start.headers["location"])
        if case == "state":
            state = "not-a-state-we-issued"
        elif case == "state_reused":
            first = await c.get("/auth/callback", params={"code": code, "state": state})
            assert first.status_code == 302
            c.cookies.clear()
            code, _ = idp.authorize(start.headers["location"])  # a fresh code, the old state
        elif case == "state_expired":
            clock.advance(601)
        else:
            idp.bad = case
        r = await c.get("/auth/callback", params={"code": code, "state": state})
        sessions = await _rows(app, SESSIONS)
        refused = await audit_rows(app, "cp.login")
    assert r.status_code == 400, r.text
    assert r.json() == {"error": "login_failed", "detail": "sign-in failed"}
    assert COOKIE not in _cookie(r)
    assert len(sessions) == (1 if case == "state_reused" else 0)
    expected = {
        "state": "state",
        "state_reused": "state",
        "state_expired": "state",
        "nonce": "nonce",
        "iss": "issuer",
        "aud": "audience",
        "exp": "expired",
        "sig": "signature",
        "alg": "algorithm",
        "kty": "algorithm",
        "iat_future": "issued_at",
        "no_iat": "claims",
    }[case]
    assert refused[-1]["outcome"] == "refused" and refused[-1]["actor"] == "anonymous"
    assert refused[-1]["detail"] == {"reason": expected, "count": 0}  # coalesced per reason


@pytest.mark.parametrize("secure", [True, False])
async def test_login_cookie_binds_the_state_to_the_browser(
    secure, tmp_path, idp, make_app, run_app
):
    """The callback needs the a2agw_login cookie set by /auth/login in the same browser:
    otherwise someone could send a victim a callback link for their own sign-in."""
    app = make_app(
        oidc_settings(
            f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}", session={"cookie_secure": secure}
        )
    )
    async with run_app(app) as c:
        start = await c.get("/auth/login", params={"next": "/after"})
        bind = _cookie(start)[LOGIN_COOKIE]
        code, state = idp.authorize(start.headers["location"])
        # no cookie: refused, and the state is left for the browser that started it
        c.cookies.delete(LOGIN_COOKIE)
        missing = await c.get("/auth/callback", params={"code": code, "state": state})
        # another browser's cookie (the attacker's link opened in the victim's browser)
        other = await c.get("/auth/login")
        mallory_code, _mallory_state = idp.authorize(other.headers["location"])
        crossed = await c.get(
            "/auth/callback", params={"code": mallory_code, "state": state}
        )  # c now holds the cookie of the second login, not of `state`
        c.cookies.set(LOGIN_COOKIE, bind.value, domain="cp.example", path="/auth/callback")
        ok = await c.get("/auth/callback", params={"code": code, "state": state})
        sessions = await _rows(app, SESSIONS)
        refused = await audit_rows(app, "cp.login")
    assert bind["httponly"] is True and bind["path"] == "/auth/callback"
    assert bind["samesite"].lower() == "lax" and bind["max-age"] == "600"
    assert bool(bind["secure"]) is secure
    for r in (missing, crossed):
        assert r.status_code == 400 and r.json() == {
            "error": "login_failed",
            "detail": "sign-in failed",
        }
        assert COOKIE not in _cookie(r)
    reasons = [row["detail"]["reason"] for row in refused if row["outcome"] == "refused"]
    assert reasons and set(reasons) == {"state"}  # the second refusal may be coalesced
    assert ok.status_code == 302 and ok.headers["location"] == "/after"
    cleared = _cookie(ok)[LOGIN_COOKIE]
    assert cleared.value == "" and cleared["max-age"] == "0" and cleared["path"] == "/auth/callback"
    assert len(sessions) == 1


async def test_login_cookie_of_another_browser_is_refused(tmp_path, idp, make_app, run_app):
    import httpx

    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as victim:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://cp.example") as mallory:
            start = await mallory.get("/auth/login")
            code, state = idp.authorize(start.headers["location"])  # Mallory signs in
            await victim.get("/auth/login")  # the victim has a login cookie of their own
            r = await victim.get("/auth/callback", params={"code": code, "state": state})
            sessions = await _rows(app, SESSIONS)
            mine = await mallory.get("/auth/callback", params={"code": code, "state": state})
    assert r.status_code == 400 and COOKIE not in _cookie(r) and sessions == []
    assert mine.status_code == 302  # the state was not consumed by the refused attempt


@pytest.mark.parametrize("secure", [True, False])
async def test_callback_creates_session_cookie_flags(secure, db_url, idp, make_app, run_app):
    idp.groups = "cp-operators unknown-group cp-security"  # a space-separated claim
    app = make_app(oidc_settings(db_url, session={"cookie_secure": secure}))
    async with run_app(app) as c:
        r = await login(c, idp, "/tasks")
        me = await c.get("/api/v1/me")
        sessions = await _rows(app, SESSIONS)
        users = await _rows(app, USERS)
        logins = await audit_rows(app, "cp.login")
    assert r.status_code == 302 and r.headers["location"] == "/tasks"
    morsel = _cookie(r)[COOKIE]
    sid = morsel.value
    assert morsel["httponly"] is True and morsel["path"] == "/"
    assert morsel["samesite"].lower() == "lax"
    assert bool(morsel["secure"]) is secure
    [session] = sessions
    assert session["digest"] == token_digest(sid) and sid not in json.dumps(sessions)
    assert session["user_id"] == "oidc:alice"
    assert [u["id"] for u in users] == ["oidc:alice"]
    assert json.loads(users[0]["roles_json"]) == ["operator", "security"]
    body = me.json()
    assert me.status_code == 200
    assert body["id"] == "oidc:alice" and body["email"] == "alice@example.com"
    assert body["name"] == "Alice Example" and body["roles"] == ["operator", "security"]
    assert body["permissions"] == sorted(
        ["read", "tasks.operate", "partners.trust", "policy.edit", "audit.read"]
    )
    assert body["csrf_token"] == csrf_token_for(sid)
    assert session["csrf_digest"] == token_digest(body["csrf_token"])
    assert logins[-1]["outcome"] == "ok" and logins[-1]["actor"] == "oidc:alice"
    assert logins[-1]["detail"] == {"role": "operator,security"}


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/",
        "//evil.example/x",
        "/\\evil.example",
        "javascript:alert(1)",
        "relative/path",
        "/ok\r\nSet-Cookie: x=1",
    ],
)
async def test_open_redirect_next_rejected(target, tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        r = await c.get("/auth/login", params={"next": target})
        states = await _rows(app, LOGIN_STATES)
    assert r.status_code == 400 and r.json()["error"] == "bad_request"
    assert "location" not in r.headers and states == []


async def test_session_idle_and_absolute_expiry(tmp_path, idp, clock, make_app, run_app):
    settings = oidc_settings(
        f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}", session={"absolute_s": 1800, "idle_s": 600}
    )
    app = make_app(settings)
    async with run_app(app) as c:
        await login(c, idp)
        statuses = []
        for _ in range(4):  # used every 500 s: idle never reached, absolute limit at 1800 s
            clock.advance(500)
            statuses.append((await c.get("/api/v1/me")).status_code)
        assert statuses == [200, 200, 200, 401]
        assert await _rows(app, SESSIONS) == []  # an expired session is deleted when seen
        await login(c, idp)
        clock.advance(590)
        assert (await c.get("/api/v1/me")).status_code == 200
        clock.advance(590)  # 590 s since the last use: still inside the idle limit
        assert (await c.get("/api/v1/me")).status_code == 200
        clock.advance(601)
        assert (await c.get("/api/v1/me")).status_code == 401


async def test_new_session_id_on_login(tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        first = _cookie(await login(c, idp))[COOKIE].value
        second = _cookie(await login(c, idp))[COOKIE].value  # the old cookie is sent along
        sessions = await _rows(app, SESSIONS)
        old = await c.get("/api/v1/me", headers={"cookie": f"{COOKIE}={first}"})
    assert first != second
    assert [s["digest"] for s in sessions] == [token_digest(second)]
    assert old.status_code == 401


async def test_logout_requires_csrf(tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        await login(c, idp)
        csrf = (await c.get("/api/v1/me")).json()["csrf_token"]
        missing = await c.post("/auth/logout")
        wrong = await c.post("/auth/logout", headers={"x-a2agw-csrf": "nope"})
        still = await c.get("/api/v1/me")
        ok = await c.post("/auth/logout", headers={"x-a2agw-csrf": csrf})
        after = await c.get("/api/v1/me")
        sessions = await _rows(app, SESSIONS)
        logouts = await audit_rows(app, "cp.logout")
    for r in (missing, wrong):
        assert r.status_code == 403 and r.json()["error"] == "csrf"
    assert still.status_code == 200
    assert ok.status_code == 204
    cleared = _cookie(ok)[COOKIE]
    assert cleared.value == "" and cleared["max-age"] == "0"
    assert after.status_code == 401 and sessions == []
    assert [(r["actor"], r["outcome"]) for r in logouts] == [("oidc:alice", "ok")]


async def test_api_key_auth_and_revocation(db_url, idp, make_app, run_app):
    app = make_app(oidc_settings(db_url))
    async with run_app(app) as c:
        store = app.state.store
        key_id, key = await store.create_api_key("ci", "operator", actor="test")
        auth = {"authorization": f"Bearer {key}"}
        me = await c.get("/api/v1/me", headers=auth)
        doc = await c.get("/api/openapi.json", headers=auth)
        bad = await c.get("/api/v1/me", headers={"authorization": "Bearer not-a-key"})
        await store.revoke_api_key(key_id, actor="test")
        revoked = await c.get("/api/v1/me", headers=auth)
        anonymous = await c.get("/api/v1/me")
        revokes = await audit_rows(app, "cp.apikey.revoke")
    assert me.status_code == 200
    assert me.json() == {
        "id": key_id,
        "kind": "api_key",
        "name": "ci",
        "email": None,
        "roles": ["operator"],
        "permissions": ["read", "tasks.operate"],
        "csrf_token": None,
        "message": None,
    }
    assert doc.status_code == 200 and "/api/v1/me" in doc.json()["paths"]
    for r in (bad, revoked, anonymous):
        assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    assert [r["detail"]["key_id"] for r in revokes] == [key_id]


async def test_disabled_user_sessions_end(tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        await login(c, idp)
        assert (await c.get("/api/v1/me")).status_code == 200
        await app.state.store.set_user_disabled("oidc:alice", True, actor="admin")
        gone = await c.get("/api/v1/me")
        sessions = await _rows(app, SESSIONS)
        again = await login(c, idp)
        refused = (await audit_rows(app, "cp.login"))[-1]
        updates = await audit_rows(app, "cp.user.update")
    assert gone.status_code == 401 and sessions == []
    assert again.status_code == 403 and again.json()["error"] == "login_failed"
    assert COOKIE not in _cookie(again)
    assert refused["outcome"] == "refused" and refused["detail"]["reason"] == "disabled"
    assert updates[-1]["outcome"] == "disabled" and updates[-1]["actor"] == "admin"


async def test_no_role_user_gets_a_session_and_only_me_and_logout(tmp_path, idp, make_app, run_app):
    idp.groups = ["unmapped"]
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        assert (await login(c, idp)).status_code == 302
        me = await c.get("/api/v1/me")
        doc = await c.get("/api/openapi.json")
        out = await c.post("/auth/logout", headers={"x-a2agw-csrf": me.json()["csrf_token"]})
    assert me.status_code == 200
    assert me.json()["roles"] == [] and me.json()["permissions"] == []
    assert me.json()["message"] == "no role assigned"
    assert doc.status_code == 403 and doc.json()["error"] == "forbidden"
    assert out.status_code == 204


async def test_openapi_requires_auth(tmp_path, idp, make_app, run_app):
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    async with run_app(app) as c:
        anonymous = await c.get("/api/openapi.json")
        idp.groups = ["cp-viewers"]
        await login(c, idp)
        viewer = await c.get("/api/openapi.json")
        docs = [await c.get(p) for p in ("/docs", "/redoc", "/openapi.json")]
    assert anonymous.status_code == 401
    assert viewer.status_code == 200 and "/healthz" in viewer.json()["paths"]
    assert [r.status_code for r in docs] == [404, 404, 404]


async def test_idp_calls_are_cached_and_use_the_partner_tier(
    tmp_path, idp, clock, cp_http, monkeypatch, run_app
):
    import a2agw.control.app as app_mod
    from a2agw.control.app import create_app

    tiers: list[str] = []
    real = app_mod.guarded_async_client

    def spy(tier_for_host, **kw):
        tiers.append(tier_for_host("idp.example"))
        return real(tier_for_host, **kw)

    monkeypatch.setattr(app_mod, "guarded_async_client", spy)
    owned = create_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}"))
    async with run_app(owned):
        assert owned.state.idp_http is not None and owned.state.idp_http is not owned.state.http
    assert "partner" in tiers  # the provider is reached through a guarded client, tier partner

    app = create_app(
        oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'b.db'}"),
        http=cp_http,
        clock=clock,
        maintenance_interval_s=3600,
    )
    async with run_app(app) as c:
        for _ in range(3):
            assert (await login(c, idp)).status_code == 302
    assert idp.routes["discovery"].call_count == 1 and idp.routes["jwks"].call_count == 1
    assert idp.routes["token"].call_count == 3


async def test_login_without_oidc_configured(sqlite_settings, run_app):
    from a2agw.control.app import create_app

    app = create_app(sqlite_settings)
    async with run_app(app) as c:
        r = await c.get("/auth/login")
    assert r.status_code == 503 and r.json()["error"] == "oidc_not_configured"


async def test_no_secret_in_logs(tmp_path, idp, make_app, run_app, caplog):
    caplog.set_level(logging.DEBUG)
    app = make_app(oidc_settings(f"sqlite+aiosqlite:///{tmp_path / 'cp.db'}"))
    secrets_seen: list[str] = [CLIENT_SECRET]
    async with run_app(app) as c:
        start = await c.get("/auth/login", params={"next": "/x"})
        secrets_seen.append(_cookie(start)[LOGIN_COOKIE].value)
        q = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
        [row] = await _rows(app, LOGIN_STATES)
        secrets_seen += [q["state"], q["nonce"], row["code_verifier"]]
        code, state = idp.authorize(start.headers["location"])
        r = await c.get("/auth/callback", params={"code": code, "state": state})
        sid = _cookie(r)[COOKIE].value
        csrf = (await c.get("/api/v1/me")).json()["csrf_token"]
        await c.post("/auth/logout", headers={"x-a2agw-csrf": csrf})
        _key_id, key = await app.state.store.create_api_key("ci", "admin", actor="t")
        await c.get("/api/v1/me", headers={"authorization": f"Bearer {key}"})
        await c.get("/api/v1/me", headers={"authorization": "Bearer wrong-key-value"})
        idp.bad = "sig"
        await login(c, idp)
        audit = json.dumps(await audit_rows(app))
    secrets_seen += idp.issued + [sid, csrf, key, "wrong-key-value"]
    # The test's own client (the browser) logs the URLs it opens, the callback's code and
    # state included; those lines are not the app's. Everything else is checked.
    records = [
        r
        for r in caplog.records
        if not (r.name == "httpx" and "https://cp.example/" in r.getMessage())
    ]
    logged = "\n".join(r.getMessage() + str(r.args) + str(r.exc_text) for r in records)
    assert any("idp.example" in r.getMessage() for r in records)  # the app's calls were seen
    for secret in secrets_seen:
        assert secret not in logged, "a secret reached the log"
        assert secret not in audit, "a secret reached the audit log"
