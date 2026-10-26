"""Management API (read only, except POST /tasks/reap and POST /partners/reload), mounted by
AgentHost under /a2agw/admin.

Every route except /healthz needs a principal with the ``a2agw:admin`` scope. Every POST
also needs the header ``X-A2AGW-Admin: 1`` (403 without it, in every auth mode, including
``admin_without_auth``): a cross-site form or a simple request cannot set it.
Authentication happens in the host middleware; here we only read ``scope["user"]``.
With no auth configured there are no principals, so admin fails closed unless the
host was created with ``admin_without_auth=True`` (development only).
Secrets (credential refs, headers) are never part of any response.

Audit: every admitted admin request appends one ``admin.read`` event (the path category in
``detail.reason``); a request refused for lack of the admin scope appends ``authz.deny``.
``/audit`` lists audit events (newest first) and ``/audit/verify`` checks the hash chain.
``POST /tasks/reap?agent=<id>`` fails the open tasks of an agent no gateway serves. Without
``confirm=true`` it is a dry run (counts only); 409 for an agent this host serves or tasks
changed within 10 minutes (unless ``force=true``). Every attempt is audited as ``task.reap``.
``/push`` reports per-agent push delivery counters (no URLs, task ids or config contents).
``POST /partners/reload`` re-reads the partners file into the running registry (partners added
with ``a2agw partners add`` become usable without a restart) and returns the ids added,
updated and removed plus ``open_handles``; 400 if the file is invalid, 409 if removed partners
still have open outbound tasks (unless ``force=true``). Nothing changes on an error. Every
attempt is audited as ``partner.reload``.
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

from a2agw.ops.audit import ACTIONS, AuditEvent, parse_since
from a2agw.security.principal import PrincipalUser

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

ADMIN_PREFIX = "/a2agw/admin"
HEALTH_PATH = f"{ADMIN_PREFIX}/healthz"
ADMIN_SCOPE = "a2agw:admin"
# Lets a principal use the outbound REST API (``a2agw.gateway.rest``) without a consult
# token, as one of the agent ids ``sidecar.clients`` maps it to.
SIDECAR_SCOPE = "a2agw:sidecar"
# Required on every admin POST (CSRF): ``X-A2AGW-Admin: 1``.
ADMIN_HEADER = "X-A2AGW-Admin"
AUDIT_MAX_LIMIT = 500
AUDIT_DEFAULT_LIMIT = 100
MAX_FILTER_CHARS = 256
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


def _str_param(request: Request, name: str) -> str | None:
    raw = request.query_params.get(name)
    if raw is not None and (not raw or len(raw) > MAX_FILTER_CHARS):
        raise _BadRequest(name)
    return raw


def admin_routes(host: AgentHost) -> list[Route]:
    async def audit(request: Request, action: Any, outcome: str, reason: str) -> None:
        log = getattr(host, "audit", None)
        if log is None:
            return
        user = request.scope.get("user")
        principal = user.principal if isinstance(user, PrincipalUser) else None
        ev = AuditEvent(
            actor=principal.id if principal is not None else "anonymous",
            action=action,
            outcome=outcome,
            detail={"reason": reason},
        )
        if action == "authz.deny" and (principal is None or principal.kind == "anonymous"):
            await log.emit_coalesced(ev, reason)  # one row per admin category per window
        else:
            await log.emit(ev)

    def guarded(category: str, fn: Handler, *, read: bool = True) -> Handler:
        async def wrapper(request: Request) -> Response:
            if not _allowed(host, request):
                await audit(request, "authz.deny", "forbidden", f"admin {category}")
                return JSONResponse({"error": "forbidden"}, status_code=403)
            if not read and request.headers.get(ADMIN_HEADER) != "1":
                # CSRF: a browser cannot add this header to a cross-site form POST.
                await audit(request, "authz.deny", "forbidden", f"admin {category}: no header")
                return JSONResponse(
                    {"error": f"forbidden: send the {ADMIN_HEADER}: 1 header"}, status_code=403
                )
            if read:
                await audit(request, "admin.read", "ok", category)
            try:
                return await fn(request)
            except _BadRequest as exc:
                return _bad(exc.field)

        return wrapper

    async def healthz(_: Request) -> Response:
        body: dict[str, Any] = {"status": "ok"}
        log = getattr(host, "audit", None)
        if log is not None:
            body["audit_errors"] = log.audit_errors
        return JSONResponse(body)

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
                    "v03_only": rec.v03_only,
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

    async def audit_list(request: Request) -> Response:
        limit = _int_param(request, "limit", lo=1, hi=AUDIT_MAX_LIMIT, default=AUDIT_DEFAULT_LIMIT)
        action = _str_param(request, "action")
        if action is not None and action not in ACTIONS:
            raise _BadRequest("action")
        filters: dict[str, Any] = {
            "action": action,
            "agent": _str_param(request, "agent"),
            "partner": _str_param(request, "partner"),
        }
        since = _str_param(request, "since")
        if since is not None:
            try:
                filters["since"] = parse_since(since)
            except ValueError:
                raise _BadRequest("since") from None
        cursor = _str_param(request, "cursor")
        log = host.audit
        if log is None:
            return JSONResponse({"error": "audit unavailable"}, status_code=503)
        try:
            rows, next_cursor = await log.query(filters, limit or AUDIT_DEFAULT_LIMIT, cursor)
        except ValueError:
            raise _BadRequest("cursor") from None
        return JSONResponse({"events": rows, "next_cursor": next_cursor})

    async def audit_verify(_: Request) -> Response:
        log = host.audit
        if log is None:
            return JSONResponse({"error": "audit unavailable"}, status_code=503)
        bad = await log.verify_chain()
        if bad is None:
            return JSONResponse({"ok": True})
        return JSONResponse({"ok": False, "first_bad_seq": bad})

    async def push(_: Request) -> Response:
        senders = getattr(host, "push_senders", {})
        return JSONResponse(
            {
                "enabled": getattr(host, "push", None) is not None,
                "agents": {agent_id: s.counters() for agent_id, s in senders.items()},
            }
        )

    async def tasks_reap(request: Request) -> Response:
        from a2agw.serve.reap import AgentServedError, RecentActivityError

        agent_id = _str_param(request, "agent")
        if agent_id is None:
            raise _BadRequest("agent")
        flags = {}
        for name in ("confirm", "force"):
            raw = request.query_params.get(name, "false")
            if raw not in ("true", "false"):
                raise _BadRequest(name)
            flags[name] = raw == "true"
        if host.index is None:
            return JSONResponse({"error": "not started"}, status_code=503)
        user = request.scope.get("user")
        actor = user.principal.id if isinstance(user, PrincipalUser) else "anonymous"
        try:
            result = await host.reap(agent_id, actor=actor, **flags)
        except AgentServedError:
            return JSONResponse({"error": "agent is served by this gateway"}, status_code=409)
        except RecentActivityError as exc:
            return JSONResponse(
                {"error": "tasks changed recently; use force=true", "recent": exc.count},
                status_code=409,
            )
        if result.dry_run:
            return JSONResponse(
                {
                    "dry_run": True,
                    "tasks": result.tasks,
                    "handles": result.handles,
                    "recent": result.recent,
                }
            )
        report = result.report
        assert report is not None
        return JSONResponse(
            {
                "dry_run": False,
                "reaped": len(report.failed),
                "outbound_cancelled": report.outbound_cancelled,
                "cancel_errors": len(report.cancel_errors),
                "errors": len(report.errors),
            }
        )

    async def partners_reload(request: Request) -> Response:
        from a2agw.consult.registry import ReloadConflict
        from a2agw.serve.host import PartnersInUse

        raw = request.query_params.get("force", "false")
        if raw not in ("true", "false"):
            raise _BadRequest("force")
        try:
            changes = await host.reload_partners(force=raw == "true")
        except PartnersInUse as exc:
            await audit(request, "partner.reload", "refused", f"open handles {exc.open_handles}")
            return JSONResponse(
                {
                    "error": "removed partners have open outbound tasks; use force=true",
                    "open_handles": exc.open_handles,
                },
                status_code=409,
            )
        except ReloadConflict:
            await audit(request, "partner.reload", "conflict", "registry changed")
            return JSONResponse({"error": "registry changed during reload; retry"}, status_code=409)
        except (ValueError, OSError) as exc:
            # The message may quote the file; only its class goes out (and to the audit).
            await audit(request, "partner.reload", "error", type(exc).__name__)
            return JSONResponse({"error": "partners file not reloaded"}, status_code=400)
        except Exception as exc:
            await audit(request, "partner.reload", "error", type(exc).__name__)
            raise  # a bug, not a bad file: a plain 500
        counts = ", ".join(f"{k} {len(v)}" for k, v in changes.items() if isinstance(v, list))
        await audit(request, "partner.reload", "ok", counts)
        return JSONResponse(changes)

    def route(name: str, fn: Handler, *, method: str = "GET") -> Route:
        handler = guarded(name.replace("/", "."), fn, read=method == "GET")
        return Route(f"{ADMIN_PREFIX}/{name}", handler, methods=[method])

    return [
        Route(HEALTH_PATH, healthz, methods=["GET"]),
        route("agents", agents),
        route("partners", partners),
        route("tasks", tasks),
        route("events", events),
        route("audit", audit_list),
        route("audit/verify", audit_verify),
        route("push", push),
        route("tasks/reap", tasks_reap, method="POST"),
        route("partners/reload", partners_reload, method="POST"),
    ]


def _frame(ev: Any) -> str:
    payload = json.dumps(
        {"kind": ev.kind, "agent_id": ev.agent_id, "data": ev.data, "ts": ev.ts}, default=str
    )
    return f"event: {ev.kind}\nid: {ev.ts}\ndata: {payload}\n\n"
