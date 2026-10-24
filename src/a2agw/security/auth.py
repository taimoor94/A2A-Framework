"""API-key and JWT authentication for inbound A2A calls, plus agent-level authorization."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

import jwt
from a2a.auth.user import UnauthenticatedUser, User
from a2a.server.routes.common import DefaultServerCallContextBuilder
from pydantic import BaseModel, Field
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
)
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse

from a2agw.security.principal import Principal, PrincipalUser

ALLOWED_JWT_ALGORITHMS = ["RS256", "ES256", "EdDSA"]
JWT_LEEWAY_SECONDS = 30


class PermissionDenied(Exception):
    """The authenticated principal may not access the agent."""


class ApiKeyEntry(BaseModel):
    principal_id: str
    scopes: list[str] = Field(default_factory=list)


class JwtConfig(BaseModel):
    issuer: str
    audience: str
    jwks_url: str | None = None
    public_key_pem: str | None = None
    scopes_claim: str = "scope"


class AuthConfig(BaseModel):
    api_keys: dict[str, ApiKeyEntry] = Field(default_factory=dict)  # sha256 hex -> entry
    jwt: JwtConfig | None = None
    allow_anonymous: bool = False


@dataclass(frozen=True)
class AgentAccess:
    allowed_principals: frozenset[str] | None = None  # None = any authenticated principal
    required_scopes: frozenset[str] = frozenset()


_ANONYMOUS = Principal(id="anonymous", kind="anonymous", scopes=frozenset())


def _fail() -> AuthenticationError:
    # Deliberately uninformative: never reveal which check failed.
    return AuthenticationError("unauthenticated")


class GatewayAuthBackend(AuthenticationBackend):
    def __init__(self, config: AuthConfig) -> None:
        self._config = config
        self._jwks_client: jwt.PyJWKClient | None = None

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, User] | None:
        api_key = conn.headers.get("x-api-key")
        bearer: str | None = None
        authz = conn.headers.get("authorization")
        if authz:
            scheme, _, value = authz.partition(" ")
            if scheme.lower() != "bearer" or not value.strip():
                raise _fail()
            bearer = value.strip()

        if api_key:
            principal = self._check_api_key(api_key)
        elif bearer is not None:
            if bearer.count(".") == 2:
                principal = await self._check_jwt(bearer)
            else:
                principal = self._check_api_key(bearer)
        elif self._config.allow_anonymous:
            principal = _ANONYMOUS
        else:
            raise _fail()
        return AuthCredentials(sorted(principal.scopes)), PrincipalUser(principal)

    def _check_api_key(self, key: str) -> Principal:
        digest = hashlib.sha256(key.encode()).hexdigest()
        match: ApiKeyEntry | None = None
        for stored, entry in self._config.api_keys.items():  # scan all: no early exit
            if hmac.compare_digest(stored.lower().encode(), digest.encode()):
                match = entry
        if match is None:
            raise _fail()
        return Principal(match.principal_id, "api_key", frozenset(match.scopes))

    async def _check_jwt(self, token: str) -> Principal:
        cfg = self._config.jwt
        if cfg is None:
            raise _fail()
        try:
            if cfg.public_key_pem:
                key: Any = cfg.public_key_pem
            elif cfg.jwks_url:
                if self._jwks_client is None:
                    self._jwks_client = jwt.PyJWKClient(cfg.jwks_url, cache_keys=True)
                signing = await asyncio.to_thread(self._jwks_client.get_signing_key_from_jwt, token)
                key = signing.key
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
        except Exception:  # noqa: BLE001 - any failure is a plain 401
            raise _fail() from None
        raw = claims.get(cfg.scopes_claim, [])
        if isinstance(raw, str):
            scopes = frozenset(raw.split())
        elif isinstance(raw, list):
            scopes = frozenset(str(s) for s in raw)
        else:
            scopes = frozenset()
        return Principal(str(claims["sub"]), "jwt", scopes)


def on_auth_error(conn: HTTPConnection, exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"error": "unauthenticated"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


class GatewayCallContextBuilder(DefaultServerCallContextBuilder):
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
