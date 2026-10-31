"""A fake OpenID Connect provider for control-plane tests, served through respx.

It answers the discovery document, a JWKS with one generated EC P-256 key, and a token
endpoint that checks the code, the PKCE verifier, the redirect URI and the client's basic
credentials, then returns an ID token signed with that key. ``bad`` makes the next token
wrong in one way: ``iss``, ``aud``, ``nonce``, ``exp``, ``sig`` (signed with another key) or
``alg`` (HS256). Every token and code it hands out is kept in ``issued`` so tests can check
that none of them leaks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import jwt
import respx
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "https://idp.example"
CLIENT_ID = "cp-client"
CLIENT_SECRET = "cs-0123456789-secret"
CLIENT_SECRET_ENV = "A2AGW_TEST_OIDC_SECRET"
PUBLIC_IP = "93.184.216.34"  # what netguard's resolver answers for idp.example in tests


def s256(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


@dataclass
class _Grant:
    challenge: str
    nonce: str
    redirect_uri: str
    client_id: str


@dataclass
class FakeIdP:
    clock: Callable[[], float]
    sub: str = "alice"
    groups: Any = field(default_factory=lambda: ["cp-admins"])
    name: str = "Alice Example"
    email: str = "alice@example.com"
    bad: str | None = None
    kid: str = "k1"
    issued: list[str] = field(default_factory=list)  # codes and tokens handed out
    _grants: dict[str, _Grant] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.other_key = ec.generate_private_key(ec.SECP256R1())

    # -- the provider's endpoints --------------------------------------------------------

    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256"],
        }

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "ES256"})
        return {"keys": [jwk]}

    def install(self, router: respx.MockRouter) -> dict[str, respx.Route]:
        return {
            "discovery": router.get(f"{ISSUER}/.well-known/openid-configuration").mock(
                side_effect=lambda _r: httpx.Response(200, json=self.discovery())
            ),
            "jwks": router.get(f"{ISSUER}/jwks").mock(
                side_effect=lambda _r: httpx.Response(200, json=self.jwks())
            ),
            "token": router.post(f"{ISSUER}/token").mock(side_effect=self._token),
        }

    def authorize(self, location: str) -> tuple[str, str]:
        """What the browser does at the authorization endpoint: returns ``(code, state)``."""
        parts = urlsplit(location)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/authorize"
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
        code = "code-" + secrets.token_urlsafe(16)
        self._grants[code] = _Grant(
            q["code_challenge"], q["nonce"], q["redirect_uri"], q["client_id"]
        )
        self.issued.append(code)
        return code, q["state"]

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Basic "):
            return httpx.Response(401, json={"error": "invalid_client"})
        user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
        if unquote(user) != CLIENT_ID or unquote(password) != CLIENT_SECRET:
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self._grants.pop(form.get("code", ""), None)
        if (
            form.get("grant_type") != "authorization_code"
            or grant is None
            or s256(form.get("code_verifier", "")) != grant.challenge
            or form.get("redirect_uri") != grant.redirect_uri
        ):
            return httpx.Response(400, json={"error": "invalid_grant"})
        id_token = self.id_token(grant.nonce)
        access = "at-" + secrets.token_urlsafe(16)
        self.issued += [id_token, access]
        return httpx.Response(
            200, json={"id_token": id_token, "access_token": access, "token_type": "Bearer"}
        )

    # -- tokens --------------------------------------------------------------------------

    def id_token(self, nonce: str) -> str:
        now = self.clock()
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": self.sub,
            "iat": int(now),
            "exp": int(now) + 300,
            "nonce": nonce,
            "name": self.name,
            "email": self.email,
            "groups": self.groups,
        }
        key: Any = self.key
        alg = "ES256"
        if self.bad == "iss":
            claims["iss"] = "https://evil.example"
        elif self.bad == "aud":
            claims["aud"] = "someone-else"
        elif self.bad == "nonce":
            claims["nonce"] = "not-the-nonce"
        elif self.bad == "exp":
            claims["exp"] = int(now) - 3600
        elif self.bad == "sig":
            key = self.other_key
        elif self.bad == "alg":
            key, alg = "shared-secret-shared-secret-shared", "HS256"
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": self.kid})


async def login(client: httpx.AsyncClient, idp: FakeIdP, next_path: str = "/") -> httpx.Response:
    """The whole sign-in from the browser's side; returns the callback's response."""
    start = await client.get("/auth/login", params={"next": next_path})
    assert start.status_code == 302, start.text
    code, state = idp.authorize(start.headers["location"])
    return await client.get("/auth/callback", params={"code": code, "state": state})


# -- helpers for control-plane tests that need a signed-in user or the audit rows ----------

COOKIE = "a2agw_session"


async def audit_rows(app: Any, action: str | None = None) -> list[dict[str, Any]]:
    """The ``cp_audit`` rows (actor, action, outcome, detail), oldest first."""
    from sqlalchemy import text

    async with app.state.engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT actor, action, outcome, detail_json FROM cp_audit ORDER BY seq")
            )
        ).all()
    out = [
        {"actor": r[0], "action": r[1], "outcome": r[2], "detail": json.loads(r[3] or "{}")}
        for r in rows
    ]
    return [r for r in out if action is None or r["action"] == action]


async def signed_in(app: Any, roles: list[str], user: str = "oidc:u1") -> dict[str, str]:
    """A session for ``user`` with ``roles`` made through the store; returns the request
    headers that use it (the cookie and the CSRF header)."""
    store, settings, now = app.state.store, app.state.settings, app.state.clock()
    await store.upsert_user(user, email=None, name=None, roles=roles, now=now)
    sid, csrf = await store.create_session(
        user, now=now, absolute_s=settings.session.absolute_s, idle_s=settings.session.idle_s
    )
    return {"cookie": f"{COOKIE}={sid}", "x-a2agw-csrf": csrf}


def oidc_settings(db_url: str, **overrides: Any) -> Any:
    """Control settings with sign-in through the fake provider; group cp-admins -> admin,
    cp-security -> security, cp-operators -> operator, cp-viewers -> viewer. A dict override
    is merged into the section of that name."""
    from a2agw.control.settings import ControlSettings

    data: dict[str, Any] = {
        "base_url": "https://cp.example",
        "db_url": db_url,
        "oidc": {
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
            "client_secret_env": CLIENT_SECRET_ENV,
            "role_map": {
                "cp-viewers": "viewer",
                "cp-operators": "operator",
                "cp-security": "security",
                "cp-admins": "admin",
            },
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    return ControlSettings.model_validate(data)
