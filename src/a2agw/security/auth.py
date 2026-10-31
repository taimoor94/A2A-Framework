"""API-key and JWT authentication for inbound A2A calls, plus agent-level authorization."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Literal

import jwt
from a2a.auth.user import UnauthenticatedUser, User
from a2a.server.context import ServerCallContext
from a2a.server.routes.common import DefaultServerCallContextBuilder
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
)
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse

from a2agw.consult import netguard
from a2agw.consult.netguard import Tier, UnsafeURL
from a2agw.security.principal import Principal, PrincipalUser

logger = logging.getLogger(__name__)

ALLOWED_JWT_ALGORITHMS = ["RS256", "ES256", "EdDSA"]
# Key, in the ASGI scope state and the SDK's ServerCallContext.state, of the raw bearer JWT of
# a JWT-authenticated caller (never an API key). It is a secret: never log it.
BEARER_STATE_KEY = "a2agw_bearer"
_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key"})
JWT_LEEWAY_SECONDS = 30
JWKS_TIMEOUT_S = 5.0  # whole fetch: vetting, connect and body
JWKS_TTL_S = 300.0  # PyJWKClient's default JWK set lifespan
JWKS_REFETCH_MIN_S = 30.0  # unknown kid: at most one cache bypass per this
JWKS_FAIL_BACKOFF_S = 30.0  # after a failed fetch, none is tried for this long
JWKS_MAX_BYTES = 1024 * 1024


class PermissionDenied(Exception):
    """The authenticated principal may not access the agent."""


def hash_api_key(key: str) -> str:
    """The form ``AuthConfig.api_keys`` stores an API key in: its sha256 hex digest."""
    return hashlib.sha256(key.encode()).hexdigest()


class ApiKeyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal_id: str
    scopes: list[str] = Field(default_factory=list)


class JwtConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer: str
    audience: str
    jwks_url: str | None = None
    # netguard tier the JWKS host is vetted with (the IdP is usually an internal service;
    # use "public" for a hosted IdP to require https and a public address).
    jwks_tier: Literal["internal", "partner", "public"] = "internal"
    public_key_pem: str | None = None
    scopes_claim: str = "scope"

    @model_validator(mode="after")
    def _exactly_one_key_source(self) -> JwtConfig:
        if bool(self.jwks_url) == bool(self.public_key_pem):
            raise ValueError("exactly one of jwks_url or public_key_pem is required")
        if self.jwks_url and not self.jwks_url.lower().startswith(("http://", "https://")):
            raise ValueError("jwks_url must be http(s)")
        if self.jwks_url and self.jwks_url.lower().startswith("http://") and not _dev():
            # Every tier: keys fetched in plain text could be swapped in transit.
            raise ValueError("jwks_url must be https (http only with A2AGW_DEV=1)")
        return self


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_keys: dict[str, ApiKeyEntry] = Field(default_factory=dict)  # sha256 hex -> entry
    jwt: JwtConfig | None = None
    allow_anonymous: bool = False

    @field_validator("api_keys", mode="before")
    @classmethod
    def _normalise_key_hashes(cls, v: Any) -> Any:
        if not isinstance(v, dict):
            return v
        out: dict[str, Any] = {}
        for k, entry in v.items():
            if not isinstance(k, str) or not _SHA256_HEX.fullmatch(k):
                raise ValueError("api_keys keys must be 64-char sha256 hex digests")
            if k.lower() in out:
                raise ValueError("duplicate api key hash")
            out[k.lower()] = entry
        return out


@dataclass(frozen=True)
class AgentAccess:
    allowed_principals: frozenset[str] | None = None  # None = any authenticated principal
    required_scopes: frozenset[str] = frozenset()


_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
_ANONYMOUS = Principal(id="anonymous", kind="anonymous", scopes=frozenset())


class JwksUnavailable(Exception):
    """The JWKS could not be fetched (refused, unreachable, bad status or malformed)."""


def _dev() -> bool:
    return os.environ.get("A2AGW_DEV") == "1"


class _JwksCache:
    """The inbound JWT keys of one JWKS URL, fetched through a guarded client
    (``netguard.safe_get``: the host is vetted for ``tier`` at connect time, no redirects,
    a size cap and one ``JWKS_TIMEOUT_S`` deadline).

    Caching like PyJWKClient: the key set is kept ``JWKS_TTL_S``; an unknown kid refetches
    it, at most once per ``JWKS_REFETCH_MIN_S`` since the last attempt (successful or not).
    After a failed fetch no fetch is tried for ``JWKS_FAIL_BACKOFF_S``: requests needing it
    fail fast. Concurrent misses share one fetch: a waiter that finds another fetch completed
    meanwhile (``_generation`` moved, whatever its outcome) uses its result and never fetches
    again itself."""

    def __init__(self, url: str, tier: Tier) -> None:
        self.url = url
        self.tier = tier
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float | None = None  # last successful fetch
        self._attempted_at: float | None = None  # last fetch, successful or not
        self._failed_at: float | None = None  # last failed fetch, cleared by a success
        self._generation = 0  # completed fetches
        self._lock = asyncio.Lock()

    async def _refresh(self) -> None:
        previous_attempt, self._attempted_at = self._attempted_at, time.monotonic()
        try:
            if self.url.lower().startswith("http://") and not _dev():
                raise UnsafeURL("https is required")
            body = await netguard.safe_get(
                self.url, self.tier, max_bytes=JWKS_MAX_BYTES, deadline_s=JWKS_TIMEOUT_S
            )
            jwk_set = jwt.PyJWKSet.from_json(body.decode("utf-8"))
        except asyncio.CancelledError:
            # Our caller went away: no outcome. The generation stays, so the next waiter in
            # line fetches itself instead of taking this as a finished fetch.
            self._attempted_at = previous_attempt
            raise
        except Exception as e:  # noqa: BLE001 - refused, unreachable or malformed: fail closed
            self._failed_at = time.monotonic()
            self._generation += 1
            raise JwksUnavailable(type(e).__name__) from None
        self._generation += 1
        # Like PyJWKClient: signing keys only ("use" absent or "sig"), each with a kid.
        self._keys = {
            k.key_id: k for k in jwk_set.keys if k.key_id and k.public_key_use in ("sig", None)
        }
        self._fetched_at = time.monotonic()
        self._failed_at = None

    def _fresh(self) -> bool:
        return self._fetched_at is not None and time.monotonic() - self._fetched_at < JWKS_TTL_S

    def _cached(self, kid: str) -> jwt.PyJWK | None:
        """The cached key, or None for an unknown kid; JwksUnavailable without a usable set."""
        if not self._fresh():
            raise JwksUnavailable("no current key set")
        return self._keys.get(kid)

    async def key(self, kid: str) -> jwt.PyJWK | None:
        if self._fresh() and kid in self._keys:
            return self._keys[kid]
        generation = self._generation
        async with self._lock:
            if self._generation != generation:
                return self._cached(kid)  # a fetch finished while we waited: use its outcome
            now = time.monotonic()
            if self._failed_at is not None and now - self._failed_at < JWKS_FAIL_BACKOFF_S:
                return self._cached(kid)  # backing off after a failure: no fetch
            if self._fresh():
                assert self._attempted_at is not None
                if kid in self._keys or now - self._attempted_at < JWKS_REFETCH_MIN_S:
                    return self._keys.get(kid)
            await self._refresh()
            return self._keys.get(kid)


def _fail() -> AuthenticationError:
    # Deliberately uninformative: never reveal which check failed.
    return AuthenticationError("unauthenticated")


class GatewayAuthBackend(AuthenticationBackend):
    """Reads X-API-Key or Authorization: Bearer.

    A bearer token with exactly two dots is treated as a JWT, so API keys sent as
    Bearer must not contain two dots. X-API-Key takes precedence over Authorization.
    Any presented credential (even an empty one) disables the anonymous fallback.
    """

    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._jwks: _JwksCache | None = None

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, PrincipalUser] | None:
        api_key = conn.headers.get("x-api-key")
        bearer: str | None = None
        authz = conn.headers.get("authorization")
        if api_key is not None and not api_key.strip():
            raise _fail()
        if authz is not None:
            scheme, _, value = authz.partition(" ")
            if scheme.lower() != "bearer" or not value.strip():
                raise _fail()
            bearer = value.strip()

        if api_key is not None:
            principal = self._check_api_key(api_key)
        elif bearer is not None:
            if bearer.count(".") == 2:
                principal = await self._check_jwt(bearer)
                # Kept for an outbound token exchange on this caller's behalf. A copy, so a
                # state dict shared with other requests is never written to.
                state = dict(conn.scope.get("state") or {})
                state[BEARER_STATE_KEY] = bearer
                conn.scope["state"] = state
            else:
                principal = self._check_api_key(bearer)
        elif self._config.allow_anonymous:
            principal = _ANONYMOUS
        else:
            raise _fail()
        return AuthCredentials(sorted(principal.scopes)), PrincipalUser(principal)

    def _check_api_key(self, key: str) -> Principal:
        digest = hash_api_key(key)
        match: ApiKeyEntry | None = None
        for stored, entry in self._config.api_keys.items():  # scan all: no early exit
            if hmac.compare_digest(stored.encode(), digest.encode()):
                match = entry
        if match is None:
            raise _fail()
        return Principal(f"key:{match.principal_id}", "api_key", frozenset(match.scopes))

    async def _check_jwt(self, token: str) -> Principal:
        cfg = self._config.jwt
        if cfg is None:
            raise _fail()
        try:
            if cfg.public_key_pem:
                key: Any = cfg.public_key_pem
            elif cfg.jwks_url:
                if self._jwks is None:
                    self._jwks = _JwksCache(cfg.jwks_url, cfg.jwks_tier)
                kid = jwt.get_unverified_header(token).get("kid")
                if not isinstance(kid, str) or not kid:
                    raise jwt.InvalidTokenError("no kid")
                key = await self._jwks.key(kid)
                if key is None:
                    raise jwt.InvalidTokenError("unknown kid")
            else:
                raise _fail()
            claims = jwt.decode(
                token,
                key,
                algorithms=ALLOWED_JWT_ALGORITHMS,
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=JWT_LEEWAY_SECONDS,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except AuthenticationError:
            raise
        except JwksUnavailable as e:
            logger.error("jwks unreachable: %s", e)
            raise _fail() from None
        except Exception as e:  # noqa: BLE001 - any failure is a plain 401
            logger.warning("jwt rejected: %s", type(e).__name__)
            raise _fail() from None
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip() or "\x00" in sub:
            logger.warning("jwt rejected: %s", "InvalidSubject")
            raise _fail()
        raw = claims.get(cfg.scopes_claim, [])
        if isinstance(raw, str):
            scopes = frozenset(raw.split())
        elif isinstance(raw, list):
            scopes = frozenset(str(s) for s in raw)
        else:
            scopes = frozenset()
        return Principal(f"jwt:{sub}", "jwt", scopes)


def on_auth_error(conn: HTTPConnection, exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"error": "unauthenticated"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


class GatewayCallContextBuilder(DefaultServerCallContextBuilder):
    def build(self, request: Request) -> ServerCallContext:
        ctx = super().build(request)
        # The SDK copies every request header into the state: drop the caller's credentials.
        headers = ctx.state.get("headers")
        if isinstance(headers, dict):
            ctx.state["headers"] = {
                k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS
            }
        token = (request.scope.get("state") or {}).get(BEARER_STATE_KEY)
        if isinstance(token, str) and token:
            ctx.state[BEARER_STATE_KEY] = token
        return ctx

    def build_user(self, request: Request) -> User:
        user = request.scope.get("user")
        if isinstance(user, PrincipalUser):
            return user
        return UnauthenticatedUser()


def authorize(principal: Principal | None, agent_policy: AgentAccess) -> None:
    if principal is None or principal.kind == "anonymous":
        raise PermissionDenied("authentication required")
    allowed = agent_policy.allowed_principals
    if allowed is not None and principal.id not in allowed:
        raise PermissionDenied("principal not allowed")
    if not agent_policy.required_scopes <= principal.scopes:
        raise PermissionDenied("missing required scope")
