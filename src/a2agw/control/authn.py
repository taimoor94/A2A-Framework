"""Control-plane sign-in: OpenID Connect, server side (a BFF), and the session cookie.

``GET /auth/login`` starts an authorization code flow with PKCE (S256): the state, nonce and
code verifier are kept in ``cp_login_states`` (the state and nonce as digests), never in the
browser. ``GET /auth/callback`` takes that state once, exchanges the code at the token
endpoint and validates the ID token (signature from the provider's JWKS with RS256, ES256 or
EdDSA; ``iss``, ``aud``, ``exp``, ``nonce``). Roles are re-derived from the token at every
login through ``oidc.role_map``; the user is upserted and a new session is created (a fresh
id at every login: no session fixation), sent as the ``a2agw_session`` cookie (HttpOnly,
Secure unless ``session.cookie_secure`` is false, SameSite=Lax, Path=/).

Every call to the provider (discovery, JWKS, token endpoint) goes through ``netguard`` at the
``partner`` tier, over the app's IdP client (a guarded client, or the injected test client).
Discovery and JWKS are cached in memory (``DISCOVERY_TTL_S``; the JWKS cache is the
gateway's ``security.auth.JwksCache``).

A refused sign-in answers one uninformative ``login_failed`` and is audited as ``cp.login``
``refused`` with a fixed ``detail.reason`` (never token content), coalesced per reason.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from a2agw.consult import netguard
from a2agw.consult.netguard import FetchError, Tier, UnsafeURL, require_https
from a2agw.control.rbac import (
    COOKIE,
    as_roles,
    authenticate,
    csrf_refused,
    csrf_valid,
    permissions_for,
    public,
    unauthorized,
)
from a2agw.control.settings import ControlSettings, OidcSettings, Role
from a2agw.control.store import csrf_token_for, token_digest
from a2agw.ops.audit import AuditEvent
from a2agw.security.auth import ALLOWED_JWT_ALGORITHMS, JwksCache, JwksUnavailable

IDP_TIER: Tier = "partner"
IDP_TIMEOUT_S = 5.0
IDP_MAX_BYTES = 1024 * 1024
DISCOVERY_TTL_S = 300.0
LEEWAY_S = 60  # clock skew allowed on exp / nbf
NEXT_MAX_CHARS = 2048
NO_STORE = {"Cache-Control": "no-store"}
_USER_ID_MAX = 64


class LoginRefused(Exception):
    """A sign-in that cannot complete. ``reason`` is a fixed word for the audit log."""

    def __init__(self, reason: str, status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


class IdpUnavailable(Exception):
    """The provider's discovery document could not be fetched or is unusable."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode()).digest())


def safe_next(path: str) -> bool:
    """Whether ``path`` is a same-origin relative path (``/x?y``): no scheme, no host, no
    ``//`` or backslash that a browser could read as another origin, no control chars."""
    if not path.startswith("/") or path.startswith("//") or len(path) > NEXT_MAX_CHARS:
        return False
    if "\\" in path or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return False
    parts = urlsplit(path)
    return not parts.scheme and not parts.netloc


def user_id_for(sub: str) -> str:
    """``oidc:<sub>``; a ``sub`` too long for an id column is replaced by its digest."""
    plain = f"oidc:{sub}"
    if len(plain) <= _USER_ID_MAX:
        return plain
    return "oidc:~" + hashlib.sha256(sub.encode()).hexdigest()[: _USER_ID_MAX - 6]


class OidcClient:
    """The control plane's view of its OpenID provider."""

    def __init__(
        self,
        settings: OidcSettings,
        *,
        http: httpx.AsyncClient | None,
        clock: Callable[[], float],
    ) -> None:
        self.settings = settings
        self.http = http
        self.clock = clock
        self._metadata: dict[str, Any] | None = None
        self._metadata_at = 0.0  # time.monotonic() of the last successful discovery
        self._jwks: JwksCache | None = None
        self._lock = asyncio.Lock()

    def client_secret(self) -> str | None:
        return os.environ.get(self.settings.client_secret_env) or None

    async def _get(self, url: str) -> bytes:
        return await netguard.safe_get(
            url, IDP_TIER, max_bytes=IDP_MAX_BYTES, deadline_s=IDP_TIMEOUT_S, http=self.http
        )

    async def metadata(self) -> dict[str, Any]:
        """The discovery document (cached ``DISCOVERY_TTL_S``); ``IdpUnavailable`` if it
        cannot be fetched, names another issuer or lacks an https endpoint."""
        if self._metadata is not None and time.monotonic() - self._metadata_at < DISCOVERY_TTL_S:
            return self._metadata
        async with self._lock:
            if (
                self._metadata is not None
                and time.monotonic() - self._metadata_at < DISCOVERY_TTL_S
            ):
                return self._metadata
            issuer = self.settings.issuer.rstrip("/")
            try:
                doc = json.loads(await self._get(f"{issuer}/.well-known/openid-configuration"))
            except (FetchError, UnsafeURL, ValueError) as e:
                raise IdpUnavailable(type(e).__name__) from None
            if not isinstance(doc, dict) or str(doc.get("issuer", "")).rstrip("/") != issuer:
                raise IdpUnavailable("issuer mismatch")
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                value = doc.get(name)
                if not isinstance(value, str):
                    raise IdpUnavailable(f"no {name}")
                try:
                    require_https(value)
                except UnsafeURL:
                    raise IdpUnavailable(f"{name} is not https") from None
            if self._jwks is None or self._jwks.url != doc["jwks_uri"]:
                self._jwks = JwksCache(doc["jwks_uri"], IDP_TIER, http=self.http)
            self._metadata, self._metadata_at = doc, time.monotonic()
            return doc

    async def authorization_url(
        self, *, state: str, nonce: str, challenge: str, redirect_uri: str
    ) -> str:
        endpoint = (await self.metadata())["authorization_endpoint"]
        params = {
            "response_type": "code",
            "client_id": self.settings.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.settings.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{urlencode(params)}"

    async def exchange(self, *, code: str, verifier: str, redirect_uri: str) -> str:
        """The ID token for ``code`` (client_secret_basic, with the PKCE verifier)."""
        try:
            endpoint = (await self.metadata())["token_endpoint"]
        except IdpUnavailable:
            raise LoginRefused("idp_unavailable", 502) from None
        secret = self.client_secret()
        if secret is None:
            raise LoginRefused("client_secret_missing", 503)
        basic = f"{quote(self.settings.client_id, safe='')}:{quote(secret, safe='')}"
        try:
            body = await netguard.safe_post(
                endpoint,
                IDP_TIER,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                },
                headers={
                    "Authorization": "Basic " + base64.b64encode(basic.encode()).decode(),
                    "Accept": "application/json",
                },
                max_bytes=IDP_MAX_BYTES,
                deadline_s=IDP_TIMEOUT_S,
                http=self.http,
            )
            token = json.loads(body).get("id_token")
        except (FetchError, UnsafeURL, ValueError, AttributeError):
            raise LoginRefused("token_exchange") from None
        if not isinstance(token, str) or not token:
            raise LoginRefused("token_exchange")
        return token

    async def verify(self, id_token: str, *, nonce_digest: str) -> dict[str, Any]:
        """The claims of a valid ID token; ``LoginRefused`` naming the failed check."""
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise LoginRefused("malformed") from None
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in ALLOWED_JWT_ALGORITHMS:
            raise LoginRefused("algorithm")
        if not isinstance(kid, str) or not kid:
            raise LoginRefused("unknown_key")
        await self.metadata()
        assert self._jwks is not None
        try:
            key = await self._jwks.key(kid)
        except JwksUnavailable:
            raise LoginRefused("idp_unavailable", 502) from None
        if key is None:
            raise LoginRefused("unknown_key")
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key.key,
                algorithms=[alg],
                audience=self.settings.client_id,
                issuer=self.settings.issuer,
                # times are checked below, against the app's clock
                options={
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "require": ["iss", "aud", "sub", "exp"],
                },
            )
        except jwt.InvalidSignatureError:
            raise LoginRefused("signature") from None
        except jwt.InvalidIssuerError:
            raise LoginRefused("issuer") from None
        except jwt.InvalidAudienceError:
            raise LoginRefused("audience") from None
        except (jwt.InvalidAlgorithmError, jwt.InvalidKeyError):
            raise LoginRefused("algorithm") from None
        except jwt.PyJWTError:
            raise LoginRefused("claims") from None
        now = self.clock()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if not isinstance(exp, int | float) or now > exp + LEEWAY_S:
            raise LoginRefused("expired")
        if nbf is not None and (not isinstance(nbf, int | float) or now + LEEWAY_S < nbf):
            raise LoginRefused("expired")
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.settings.client_id:
            raise LoginRefused("audience")
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not hmac.compare_digest(token_digest(nonce), nonce_digest):
            raise LoginRefused("nonce")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > 255:
            raise LoginRefused("claims")
        return claims

    def roles(self, claims: dict[str, Any]) -> frozenset[Role]:
        """The Console roles of the groups in ``roles_claim`` (a list, or a space-separated
        string); groups not in ``role_map`` are ignored."""
        raw = claims.get(self.settings.roles_claim)
        groups = raw.split() if isinstance(raw, str) else raw if isinstance(raw, list) else []
        role_map = self.settings.role_map
        return as_roles(role_map[g] for g in groups if isinstance(g, str) and g in role_map)


def _text_claim(claims: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    return None


def _oidc(request: Request) -> OidcClient:
    oidc: OidcClient | None = getattr(request.app.state, "oidc", None)
    if oidc is None or oidc.client_secret() is None:
        raise HTTPException(
            503, {"error": "oidc_not_configured", "detail": "sign-in is not configured"}
        )
    return oidc


def _redirect_uri(settings: ControlSettings) -> str:
    return settings.base_url.rstrip("/") + "/auth/callback"


async def _audit(request: Request, ev: AuditEvent, coalesce: str | None = None) -> None:
    audit = request.app.state.audit
    if coalesce is None:
        await audit.emit(ev)
    else:
        await audit.emit_coalesced(ev, coalesce)


@public("GET", "/auth/login")
async def login(request: Request, next_path: str = Query("/", alias="next")) -> Response:
    """Start a sign-in; ``next`` is where the browser goes afterwards (a same-origin path)."""
    oidc = _oidc(request)
    if not safe_next(next_path):
        raise HTTPException(400, "next must be a same-origin relative path")
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    try:
        url = await oidc.authorization_url(
            state=state,
            nonce=nonce,
            challenge=pkce_challenge(verifier),
            redirect_uri=_redirect_uri(request.app.state.settings),
        )
    except IdpUnavailable:
        raise HTTPException(
            503, {"error": "idp_unavailable", "detail": "the identity provider is unavailable"}
        ) from None
    await request.app.state.store.create_login_state(
        state=state,
        nonce=nonce,
        code_verifier=verifier,
        next_path=next_path,
        now=request.app.state.clock(),
    )
    return RedirectResponse(url, status_code=302, headers=NO_STORE)


@public("GET", "/auth/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> Response:
    """The provider sends the browser back here with ``code`` and ``state``."""
    oidc = _oidc(request)
    app = request.app.state
    try:
        if error is not None:
            raise LoginRefused("idp_error")
        if not code or not state:
            raise LoginRefused("missing_params")
        pending = await app.store.take_login_state(state, now=app.clock())
        if pending is None:
            raise LoginRefused("state")
        id_token = await oidc.exchange(
            code=code, verifier=pending.code_verifier, redirect_uri=_redirect_uri(app.settings)
        )
        claims = await oidc.verify(id_token, nonce_digest=pending.nonce_digest)
        roles = oidc.roles(claims)
        user = await app.store.upsert_user(
            user_id_for(claims["sub"]),
            email=_text_claim(claims, "email"),
            name=_text_claim(claims, "name", "preferred_username"),
            roles=roles,
            now=app.clock(),
        )
        if user.disabled:
            raise LoginRefused("disabled", 403)
    except LoginRefused as refused:
        event = AuditEvent(
            actor="anonymous",
            action="cp.login",
            outcome="refused",
            detail={"reason": refused.reason},
            ts=app.clock(),
        )
        await _audit(request, event, coalesce=f"login:{refused.reason}")
        return JSONResponse(
            {"error": "login_failed", "detail": "sign-in failed"},
            status_code=refused.status,
            headers=NO_STORE,
        )
    limits = app.settings.session
    session_id, _csrf = await app.store.create_session(
        user.id,
        now=app.clock(),
        absolute_s=limits.absolute_s,
        idle_s=limits.idle_s,
        replace=request.cookies.get(COOKIE),
    )
    await _audit(
        request,
        AuditEvent(
            actor=user.id,
            action="cp.login",
            outcome="ok",
            detail={"role": ",".join(sorted(roles))},
            ts=app.clock(),
        ),
    )
    response = RedirectResponse(pending.next_path, status_code=302, headers=NO_STORE)
    response.set_cookie(
        COOKIE,
        session_id,
        max_age=limits.absolute_s,
        path="/",
        secure=limits.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@public("POST", "/auth/logout", status_code=204)
async def logout(request: Request) -> Response:
    """End the session of the cookie (needs its CSRF token); clears the cookie."""
    app = request.app.state
    session_id = request.cookies.get(COOKIE)
    if session_id:
        limits = app.settings.session
        session = await app.store.get_session(
            session_id, now=app.clock(), absolute_s=limits.absolute_s, idle_s=limits.idle_s
        )
        if session is not None:
            if not csrf_valid(request, session.csrf_digest):
                raise csrf_refused()
            await app.store.delete_session(session_id)
            await _audit(
                request,
                AuditEvent(actor=session.user_id, action="cp.logout", outcome="ok", ts=app.clock()),
            )
    response = Response(status_code=204, headers=NO_STORE)
    response.delete_cookie(
        COOKIE, path="/", secure=app.settings.session.cookie_secure, httponly=True, samesite="lax"
    )
    return response


@public("GET", "/api/v1/me")
async def me(request: Request) -> JSONResponse:
    """Who is signed in, their roles and permissions, and the session's CSRF token. A user
    without any role gets an empty permission list and ``message``."""
    caller = await authenticate(request)
    if caller is None:
        raise unauthorized()
    actor = caller.actor
    return JSONResponse(
        {
            "id": actor.id,
            "kind": actor.kind,
            "name": caller.name,
            "email": caller.email,
            "roles": sorted(actor.roles),
            "permissions": sorted(p.value for p in permissions_for(actor.roles)),
            "csrf_token": csrf_token_for(caller.session_id) if caller.session_id else None,
            "message": None if actor.roles else "no role assigned",
        },
        headers=NO_STORE,
    )
