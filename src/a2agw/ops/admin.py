"""Read-only management API, mounted by AgentHost under /a2agw/admin.

Every route except /healthz needs a principal with the ``a2agw:admin`` scope.
Authentication happens in the host middleware; here we only read ``scope["user"]``.
With no auth configured there are no principals, so admin fails closed unless the
host was created with ``admin_without_auth=True`` (development only).
Secrets (credential refs, headers) are never part of any response.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any

from a2a.types import TaskState
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from a2agw.security.principal import PrincipalUser

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

ADMIN_PREFIX = "/a2agw/admin"
HEALTH_PATH = f"{ADMIN_PREFIX}/healthz"
ADMIN_SCOPE = "a2agw:admin"
KEEPALIVE_S = 15.0  # module constant so tests can shorten it
REPLAY = 50
MAX_EVENTS = 1000

Handler = Callable[[Request], Awaitable[Response]]


class _BadRequest(Exception):
    def __init__(self, field: str) -> None:
        self.field = field


def _bad(field: str) -> JSONResponse:
    return JSONResponse({"error": "bad request", "field": field}, status_code=400)


def _int_param(request: Request, name: str, *, lo: int, hi: int, default: int | None) -> int | None:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise _BadRequest(name) from None
    if not lo <= value <= hi:
        raise _BadRequest(name)
    return value


def _allowed(host: AgentHost, request: Request) -> bool:
    user = request.scope.get("user")
    if not isinstance(user, PrincipalUser):
        return False
    if host.auth is None:
        return host.admin_without_auth
    return ADMIN_SCOPE in user.principal.scopes


def admin_routes(host: AgentHost) -> list[Route]:
    def guarded(fn: Handler) -> Handler:
        async def wrapper(request: Request) -> Response:
            if not _allowed(host, request):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            try:
                return await fn(request)
            except _BadRequest as exc:
                return _bad(exc.field)

        return wrapper

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def agents(_: Request) -> Response:
        out = [
            {
                "id": agent_id,
                "name": spec.name,
                "version": spec.version,
                "skills": [{"id": s.id, "name": s.name} for s in spec.skills],
                "card_url": f"{host.base_url}/agents/{agent_id}/.well-known/agent-card.json",
                "durable": bool(spec.adapter.durable_sessions),
            }
            for agent_id, spec in host.specs.items()
        ]
        return JSONResponse(out)

    async def partners(_: Request) -> Response:
        registry = getattr(host, "partners", None)
        client = getattr(host, "client", None)
        out: list[dict[str, Any]] = []
        for rec in registry.all() if registry is not None else []:
            stats = client.partner_stats(rec.id) if client is not None else {}
            out.append(
                {
                    "id": rec.id,
                    "tier": rec.tier,
                    "status": rec.status,
                    "card_hash": rec.card_hash,
                    "fetched_at": rec.fetched_at,
                    "card_url": rec.card_url,
                    "breaker_state": stats.get("breaker_state", "closed"),
                    "in_flight": stats.get("in_flight", 0),
                }
            )
        return JSONResponse(out)

    async def tasks(request: Request) -> Response:
        limit = _int_param(request, "limit", lo=1, hi=100, default=50)
        state = request.query_params.get("state")
        if state is not None and state not in TaskState.keys():  # noqa: SIM118
            raise _BadRequest("state")
        if host.index is None:
            return JSONResponse({"error": "not started"}, status_code=503)
        try:
            rows, next_cursor = await host.index.list(
                agent_id=request.query_params.get("agent"),
                state=state,
                limit=limit or 50,
                cursor=request.query_params.get("cursor"),
            )
        except ValueError:
            raise _BadRequest("cursor") from None
        return JSONResponse({"tasks": rows, "next_cursor": next_cursor})

    async def events(request: Request) -> Response:
        limit = _int_param(request, "limit", lo=1, hi=MAX_EVENTS, default=None)

        async def stream() -> AsyncIterator[str]:
            sent = 0
            snapshot, sub = host.bus.subscribe_with_replay(REPLAY)
            async with sub:
                for ev in snapshot:
                    yield _frame(ev)
                    sent += 1
                    if limit is not None and sent >= limit:
                        return
                while True:
                    try:
                        ev = await asyncio.wait_for(sub.__anext__(), KEEPALIVE_S)
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    except StopAsyncIteration:
                        return
                    yield _frame(ev)
                    sent += 1
                    if limit is not None and sent >= limit:
                        return

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def route(name: str, fn: Handler) -> Route:
        return Route(f"{ADMIN_PREFIX}/{name}", guarded(fn), methods=["GET"])

    return [
        Route(HEALTH_PATH, healthz, methods=["GET"]),
        route("agents", agents),
        route("partners", partners),
        route("tasks", tasks),
        route("events", events),
    ]


def _frame(ev: Any) -> str:
    payload = json.dumps(
        {"kind": ev.kind, "agent_id": ev.agent_id, "data": ev.data, "ts": ev.ts}, default=str
    )
    return f"event: {ev.kind}\nid: {ev.ts}\ndata: {payload}\n\n"
