"""Console API: gateway management (``gateways.manage``).

- ``POST /api/v1/gateways`` ``{name}``: register a gateway; answers ``{id, name, token}``.
  The token is shown only in this response (its digest is stored).
- ``GET /api/v1/gateways``: every gateway with its status, when it was last seen, whether
  it is connected (seen within two keepalive intervals), the versions applied and desired,
  its last rejected version and the info it reported.
- ``POST /api/v1/gateways/{id}/tokens``: a new token (shown once); the old ones stop
  working, and a stream open with one closes at its next poll.
- ``POST /api/v1/gateways/{id}/revoke``: the gateway is revoked with all its tokens.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from a2agw.control import require_fastapi

require_fastapi()

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from a2agw.control.rbac import Actor, Permission, require, route
from a2agw.control.store import DESIRED, GATEWAYS, NAME, ControlStore

MANAGE = Permission.GATEWAYS_MANAGE
NO_STORE = {"Cache-Control": "no-store"}
# the caller of a gateways.manage route (resolved once with the route's own check)
Manager = Annotated[Actor, Depends(require(MANAGE))]


class CreateGateway(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=NAME)

    @field_validator("name")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        return v


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
