"""Control-plane roles, permissions, and who is calling.

Four roles (``Role``, from settings) grant permissions (``ROLE_PERMISSIONS``); a caller with
several roles gets the union. A caller is either a signed-in user (the ``a2agw_session``
cookie) or an API key (``Authorization: Bearer <key>``); ``authenticate`` resolves it once
per request into an ``Actor``.

Every route is registered through ``route(method, path, permission)``, ``public(...)`` or
``gateway_route(...)``, so ``ROUTE_PERMISSIONS`` lists each route with what it needs, and the
tests check every route against every role:

- ``route``: the ``require(permission)`` dependency. No credentials: 401. A session
  request that is not GET/HEAD/OPTIONS without the session's CSRF token in
  ``X-A2AGW-CSRF``: 403 ``csrf`` (API keys are not subject to CSRF: a browser never sends
  them on its own). A missing permission: 403 ``forbidden``, audited as ``cp.denied``
  (coalesced per actor and permission, like the gateway's anonymous denials).
- ``public``: no permission check. A public handler that needs a caller (``/api/v1/me``,
  ``/auth/logout``) checks for one itself: a user without any role may use those two.
- ``gateway_route``: the ``/cp/v1`` routes gateways call, authenticated with gateway tokens
  only (``require_gateway``). A user session or an API key never passes there.
"""

from __future__ import annotations

import functools
import hmac
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, TypeVar, cast

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, FastAPI, HTTPException, Request

from a2agw.control.settings import ROLES, Role
from a2agw.control.store import token_digest
from a2agw.ops.audit import AuditEvent

COOKIE = "a2agw_session"
CSRF_HEADER = "X-A2AGW-CSRF"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
GATEWAY_PREFIX = "/cp/v1/"


class Permission(StrEnum):
    READ = "read"
    TASKS_OPERATE = "tasks.operate"
    PARTNERS_REGISTER = "partners.register"
    PARTNERS_TRUST = "partners.trust"
    POLICY_EDIT = "policy.edit"
    ASSIGN = "assign"
    AUDIT_READ = "audit.read"
    GATEWAYS_MANAGE = "gateways.manage"
    USERS_MANAGE = "users.manage"
    APIKEYS_MANAGE = "apikeys.manage"
    SETTINGS_MANAGE = "settings.manage"


_VIEWER = frozenset({Permission.READ})
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    "viewer": _VIEWER,
    "operator": _VIEWER | {Permission.TASKS_OPERATE},
    "security": _VIEWER
    | {Permission.PARTNERS_TRUST, Permission.POLICY_EDIT, Permission.AUDIT_READ},
    "admin": frozenset(Permission),
}


def as_roles(names: Iterable[str]) -> frozenset[Role]:
    """The known roles among ``names`` (anything else is ignored)."""
    return frozenset(cast(Role, n) for n in names if n in ROLES)


def permissions_for(roles: Iterable[str]) -> frozenset[Permission]:
    """The union of the permissions of ``roles``; nothing for no (known) role."""
    out: frozenset[Permission] = frozenset()
    for role in as_roles(roles):
        out |= ROLE_PERMISSIONS[role]
    return out


@dataclass(frozen=True)
class Actor:
    id: str  # "oidc:<sub>" for a user, the key id ("ak-...") for an API key
    kind: Literal["user", "api_key"]
    roles: frozenset[Role]
    csrf_ok: bool  # always True for API keys and safe methods


@dataclass(frozen=True)
class Caller:
    """An authenticated request: the actor and what ``/api/v1/me`` shows about it."""

    actor: Actor
    name: str | None
    email: str | None
    session_id: str | None  # the cookie's session id (a secret: never log it)


_UNSET = object()


def csrf_valid(request: Request, csrf_digest: str) -> bool:
    """Whether the request carries the session's CSRF token (compared as digests)."""
    sent = request.headers.get(CSRF_HEADER)
    return sent is not None and hmac.compare_digest(token_digest(sent), csrf_digest)


async def authenticate(request: Request) -> Caller | None:
    """The caller of ``request``, resolved once per request (cached on ``request.state``).

    An ``Authorization`` header is the only credential looked at when present (an API key;
    anything else there means no caller): it never falls back to the cookie."""
    cached = getattr(request.state, "cp_caller", _UNSET)
    if cached is not _UNSET:
        return cast(Caller | None, cached)
    caller = await _resolve(request)
    request.state.cp_caller = caller
    return caller


async def _resolve(request: Request) -> Caller | None:
    state = request.app.state
    now = state.clock()
    authorization = request.headers.get("authorization")
    if authorization is not None:
        scheme, _, key = authorization.partition(" ")
        key = key.strip()
        if scheme.lower() != "bearer" or not key:
            return None
        api_key = await state.store.get_api_key(key, now=now)
        if api_key is None:
            return None
        actor = Actor(api_key.id, "api_key", as_roles([api_key.role]), csrf_ok=True)
        return Caller(actor, name=api_key.name, email=None, session_id=None)
    session_id = request.cookies.get(COOKIE)
    if not session_id:
        return None
    limits = state.settings.session
    session = await state.store.get_session(
        session_id, now=now, absolute_s=limits.absolute_s, idle_s=limits.idle_s
    )
    if session is None:
        return None
    csrf_ok = request.method in SAFE_METHODS or csrf_valid(request, session.csrf_digest)
    actor = Actor(session.user_id, "user", as_roles(session.roles), csrf_ok=csrf_ok)
    return Caller(actor, name=session.name, email=session.email, session_id=session_id)


def unauthorized() -> HTTPException:
    return HTTPException(
        401,
        {"error": "unauthorized", "detail": "authentication required"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def csrf_refused() -> HTTPException:
    return HTTPException(403, {"error": "csrf", "detail": f"missing or invalid {CSRF_HEADER}"})


async def _audit_denied(request: Request, actor: Actor, permission: Permission) -> None:
    audit = getattr(request.app.state, "audit", None)
    if audit is None:
        return
    event = AuditEvent(
        actor=actor.id,
        action="cp.denied",
        outcome="denied",
        detail={"reason": "permission", "rule": permission.value, "principal_kind": actor.kind},
        ts=request.app.state.clock(),
    )
    await audit.emit_coalesced(event, f"{actor.id}:{permission.value}")


@functools.cache
def require(permission: Permission) -> Callable[[Request], Awaitable[Actor]]:
    """The dependency guarding a route with ``permission``; returns the ``Actor``. One
    callable per permission, so a handler can also take ``Depends(require(p))`` for the
    actor and FastAPI resolves it once."""

    async def dependency(request: Request) -> Actor:
        caller = await authenticate(request)
        if caller is None:
            raise unauthorized()
        actor = caller.actor
        if not actor.csrf_ok:
            raise csrf_refused()
        if permission not in permissions_for(actor.roles):
            await _audit_denied(request, actor, permission)
            raise HTTPException(
                403, {"error": "forbidden", "detail": f"needs the {permission.value} permission"}
            )
        return actor

    dependency.__name__ = f"require_{permission.name.lower()}"
    return dependency


GatewayAuth = Callable[[Request], Awaitable[str | None]]


async def require_gateway(request: Request) -> str:
    """The dependency of ``/cp/v1`` routes: the id of the calling gateway.

    It asks ``app.state.gateway_auth`` (set by the gateway API, Task 6), which checks
    gateway tokens only; until that exists every call is 401. Sessions and API keys are
    never looked at here."""
    resolve: GatewayAuth | None = getattr(request.app.state, "gateway_auth", None)
    gateway_id = await resolve(request) if resolve is not None else None
    if gateway_id is None:
        raise unauthorized()
    return gateway_id


Access = Permission | Literal["public", "gateway"]
F = TypeVar("F", bound=Callable[..., Any])


class Routes:
    """Routes that each say what they need. ``permissions`` maps ``(method, path)`` to a
    ``Permission``, ``"public"`` or ``"gateway"``; ``mount(app)`` adds them all to an app
    (as plain routes, so ``app.routes`` lists each one).
    """

    def __init__(self) -> None:
        self.permissions: dict[tuple[str, str], Access] = {}
        self._specs: list[tuple[str, str, Callable[..., Any], list[Any], dict[str, Any]]] = []

    def mount(self, app: FastAPI) -> None:
        for method, path, fn, dependencies, kw in self._specs:
            app.add_api_route(path, fn, methods=[method], dependencies=dependencies, **kw)

    def _add(
        self, method: str, path: str, access: Access, dependencies: list[Any], **kw: Any
    ) -> Callable[[F], F]:
        method = method.upper()
        if (access == "gateway") != path.startswith(GATEWAY_PREFIX):
            raise ValueError(f"{path}: gateway routes, and only they, live under {GATEWAY_PREFIX}")
        key = (method, path)
        if key in self.permissions:
            raise ValueError(f"{method} {path} is already registered")

        def register(fn: F) -> F:
            self._specs.append((method, path, fn, dependencies, kw))
            self.permissions[key] = access
            return fn

        return register

    def route(self, method: str, path: str, permission: Permission, **kw: Any) -> Callable[[F], F]:
        """A route needing ``permission`` (see ``require``)."""
        return self._add(method, path, permission, [Depends(require(permission))], **kw)

    def public(self, method: str, path: str, **kw: Any) -> Callable[[F], F]:
        """A route without a permission check (sign-in, /healthz, /api/v1/me)."""
        return self._add(method, path, "public", [], **kw)

    def gateway_route(self, method: str, path: str, **kw: Any) -> Callable[[F], F]:
        """A ``/cp/v1`` route for gateways, authenticated with a gateway token."""
        return self._add(method, path, "gateway", [Depends(require_gateway)], **kw)


# The control plane's own routes (app.py, authn.py and later tasks register here).
ROUTES = Routes()
ROUTE_PERMISSIONS = ROUTES.permissions
route = ROUTES.route
public = ROUTES.public
gateway_route = ROUTES.gateway_route
