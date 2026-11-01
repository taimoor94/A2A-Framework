"""Console API: gateways (``gateways.manage``), users (``users.manage``), API keys
(``apikeys.manage``) and the effective settings (``settings.manage``).

- ``POST /api/v1/gateways`` ``{name}``: register a gateway; answers ``{id, name, token}``.
  The token is shown only in this response (its digest is stored).
- ``GET /api/v1/gateways``: every gateway with its status, when it was last seen, whether
  it is connected (seen within two keepalive intervals), the versions applied and desired,
  its last rejected version and the info it reported.
- ``POST /api/v1/gateways/{id}/tokens``: a new token (shown once); the old ones stop
  working, and a stream open with one closes at its next poll.
- ``POST /api/v1/gateways/{id}/revoke``: the gateway is revoked with all its tokens.
- ``GET /api/v1/users``: the users who signed in, with their roles (from the last sign-in)
  and whether they are disabled. ``PATCH /api/v1/users/{id}`` ``{disabled?}``: disabling a
  user ends all their sessions at once (and a disabled user cannot sign in again).
- ``GET /api/v1/api-keys``: the keys (never a key or its digest). ``POST /api/v1/api-keys``
  ``{name, role}``: a new key, shown only in this response. Its role's permissions must be
  ones the caller holds: nobody makes a key above their own permissions.
  ``POST /api/v1/api-keys/{id}/revoke``: the key stops working at its next use.
- ``GET /api/v1/settings``: the effective control.yaml without secrets: no ``*_env`` names,
  and ``db_url`` with its password masked. Read-only: edits go through the file.

Lists answer ``{items, next_cursor}`` with keyset cursors (``views.Keyset``).
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, tuple_
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from a2agw.control.rbac import Actor, Permission, permissions_for, require, route
from a2agw.control.settings import ControlSettings, Role
from a2agw.control.store import API_KEYS, DESIRED, GATEWAYS, NAME, USERS, ControlStore
from a2agw.control.views import Keyset, PageQuery

MANAGE = Permission.GATEWAYS_MANAGE
NO_STORE = {"Cache-Control": "no-store"}
USERS_MANAGE = Permission.USERS_MANAGE
APIKEYS_MANAGE = Permission.APIKEYS_MANAGE
# the caller of a gateways.manage route (resolved once with the route's own check)
Manager = Annotated[Actor, Depends(require(MANAGE))]
UserManager = Annotated[Actor, Depends(require(USERS_MANAGE))]
KeyManager = Annotated[Actor, Depends(require(APIKEYS_MANAGE))]


def _not_blank(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("name must not be blank")
    return v


class CreateGateway(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=NAME)

    _name = field_validator("name")(_not_blank)


class UserChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disabled: bool | None = None


class CreateApiKey(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=NAME)
    role: Role

    _name = field_validator("name")(_not_blank)


def _not_found() -> HTTPException:
    return HTTPException(404, {"error": "not_found", "detail": "unknown gateway"})


def _conflict(detail: str) -> HTTPException:
    return HTTPException(409, {"error": "conflict", "detail": detail})


@route("POST", "/api/v1/gateways", MANAGE, status_code=201)
async def create_gateway(body: CreateGateway, request: Request, actor: Manager) -> JSONResponse:
    store: ControlStore = request.app.state.store
    try:
        gateway_id, token = await store.create_gateway(body.name, actor=actor.id)
    except ValueError:
        raise _conflict("a gateway with this name already exists") from None
    return JSONResponse(
        {"id": gateway_id, "name": body.name, "token": token}, status_code=201, headers=NO_STORE
    )


@route("GET", "/api/v1/gateways", MANAGE)
async def list_gateways(request: Request) -> dict[str, Any]:
    state = request.app.state
    store: ControlStore = state.store
    window = 2 * state.settings.limits.stream_keepalive_s
    now = state.clock()
    query = (
        select(GATEWAYS, DESIRED.c.version.label("version_desired"))
        .select_from(GATEWAYS.outerjoin(DESIRED, DESIRED.c.gateway_id == GATEWAYS.c.id))
        .order_by(GATEWAYS.c.name)
    )
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    out = []
    for row in rows:
        try:
            info = json.loads(row.info_json or "{}")
        except ValueError:
            info = {}
        if not isinstance(info, dict):
            info = {}
        last_rejection = info.pop("last_rejection", None)
        seen = row.last_seen_at
        out.append(
            {
                "id": row.id,
                "name": row.name,
                "status": row.status,
                "last_seen_at": seen,
                "connected": row.status == "active" and seen is not None and now - seen <= window,
                "version_applied": row.last_version_applied,
                "version_desired": row.version_desired or 0,
                "epoch_applied": row.epoch_applied,
                "epoch_desired": store.epoch if row.version_desired is not None else None,
                "last_rejection": last_rejection,
                "info": info,
            }
        )
    return {"gateways": out}


@route("POST", "/api/v1/gateways/{gateway_id}/tokens", MANAGE)
async def rotate_token(gateway_id: str, request: Request, actor: Manager) -> JSONResponse:
    store: ControlStore = request.app.state.store
    try:
        token = await store.rotate_gateway_token(gateway_id, actor=actor.id)
    except KeyError:
        raise _not_found() from None
    except ValueError:
        raise _conflict("gateway is revoked") from None
    return JSONResponse({"id": gateway_id, "token": token}, headers=NO_STORE)


@route("POST", "/api/v1/gateways/{gateway_id}/revoke", MANAGE)
async def revoke_gateway(gateway_id: str, request: Request, actor: Manager) -> dict[str, str]:
    store: ControlStore = request.app.state.store
    try:
        await store.revoke_gateway(gateway_id, actor=actor.id)
    except KeyError:
        raise _not_found() from None
    return {"id": gateway_id, "status": "revoked"}


# -- users ---------------------------------------------------------------------------------


def _user(r: Any) -> dict[str, Any]:
    try:
        roles = json.loads(r.roles_json or "[]")
    except ValueError:
        roles = []
    return {
        "id": r.id,
        "email": r.email,
        "name": r.name,
        "roles": sorted(x for x in roles if isinstance(x, str)) if isinstance(roles, list) else [],
        "disabled": bool(r.disabled),
        "created_at": r.created_at,
        "last_login_at": r.last_login_at,
    }


@route("GET", "/api/v1/users", USERS_MANAGE)
async def list_users(request: Request, page: PageQuery) -> dict[str, Any]:
    keyset = Keyset("users", {}, (str,), page)
    after = keyset.after()
    store: ControlStore = request.app.state.store
    query = select(USERS).order_by(USERS.c.id).limit(keyset.limit + 1)
    if after is not None:
        query = query.where(USERS.c.id > after[0])
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    more = len(rows) > keyset.limit
    rows = rows[: keyset.limit]
    return keyset.page([_user(r) for r in rows], (rows[-1].id,) if rows else None, more)


@route("PATCH", "/api/v1/users/{user_id}", USERS_MANAGE)
async def change_user(
    user_id: str, body: UserChange, request: Request, actor: UserManager
) -> dict[str, Any]:
    store: ControlStore = request.app.state.store
    if body.disabled is not None:
        try:  # disabling deletes the user's sessions in the same transaction
            await store.set_user_disabled(user_id, body.disabled, actor=actor.id)
        except KeyError:
            raise HTTPException(404, {"error": "not_found", "detail": "unknown user"}) from None
    async with store.engine.connect() as conn:
        found = (await conn.execute(select(USERS).where(USERS.c.id == user_id))).first()
    if found is None:
        raise HTTPException(404, {"error": "not_found", "detail": "unknown user"})
    return _user(found)


# -- API keys ------------------------------------------------------------------------------


@route("GET", "/api/v1/api-keys", APIKEYS_MANAGE)
async def list_api_keys(request: Request, page: PageQuery) -> dict[str, Any]:
    keyset = Keyset("api-keys", {}, (float, str), page)
    after = keyset.after()
    store: ControlStore = request.app.state.store
    k = API_KEYS.c
    query = (
        select(k.id, k.name, k.role, k.created_by, k.created_at, k.revoked_at, k.last_used_at)
        .order_by(k.created_at.desc(), k.id.desc())
        .limit(keyset.limit + 1)
    )
    if after is not None:
        query = query.where(tuple_(k.created_at, k.id) < tuple_(*after))
    async with store.engine.connect() as conn:
        rows = (await conn.execute(query)).all()
    more = len(rows) > keyset.limit
    rows = rows[: keyset.limit]
    items = [dict(r._mapping) for r in rows]
    last = (rows[-1].created_at, rows[-1].id) if rows else None
    return keyset.page(items, last, more)


@route("POST", "/api/v1/api-keys", APIKEYS_MANAGE, status_code=201)
async def create_api_key(body: CreateApiKey, request: Request, actor: KeyManager) -> JSONResponse:
    """A new key, shown once. Its role must not carry a permission the caller lacks."""
    if not permissions_for([body.role]) <= permissions_for(actor.roles):
        raise HTTPException(
            403,
            {
                "error": "forbidden",
                "detail": "an API key cannot have permissions its creator lacks",
            },
        )
    store: ControlStore = request.app.state.store
    key_id, key = await store.create_api_key(body.name, body.role, actor=actor.id)
    return JSONResponse(
        {"id": key_id, "name": body.name, "role": body.role, "key": key},
        status_code=201,
        headers=NO_STORE,
    )


@route("POST", "/api/v1/api-keys/{key_id}/revoke", APIKEYS_MANAGE)
async def revoke_api_key(key_id: str, request: Request, actor: KeyManager) -> dict[str, str]:
    store: ControlStore = request.app.state.store
    try:
        await store.revoke_api_key(key_id, actor=actor.id)
    except KeyError:
        raise HTTPException(404, {"error": "not_found", "detail": "unknown API key"}) from None
    return {"id": key_id, "status": "revoked"}


# -- settings ------------------------------------------------------------------------------


def _masked_url(url: str) -> str | None:
    try:
        return make_url(url).render_as_string(hide_password=True)
    except (ArgumentError, ValueError):
        return None  # not a URL SQLAlchemy can read: nothing of it is shown


def _without_secrets(value: Any) -> Any:
    """Drop every ``*_env`` key (the name of a secret's variable) at any depth."""
    if isinstance(value, dict):
        return {
            k: _without_secrets(v)
            for k, v in value.items()
            if not (isinstance(k, str) and k.endswith("_env"))
        }
    if isinstance(value, list):
        return [_without_secrets(v) for v in value]
    return value


def redacted_settings(settings: ControlSettings) -> dict[str, Any]:
    """The effective settings as JSON without secrets: no ``*_env`` names and the database
    password masked (an interpolated ``${VAR}`` may have put one in ``db_url``). Inline
    secrets are refused when control.yaml is loaded, so nothing else holds one."""
    out: dict[str, Any] = _without_secrets(settings.model_dump(mode="json"))
    out["db_url"] = _masked_url(settings.db_url)
    return out


@route("GET", "/api/v1/settings", Permission.SETTINGS_MANAGE)
async def get_settings(request: Request) -> JSONResponse:
    return JSONResponse(redacted_settings(request.app.state.settings), headers=NO_STORE)
