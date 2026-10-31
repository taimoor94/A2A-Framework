"""Management API, mounted by AgentHost under /a2agw/admin: reads, and the operator writes
(partners, policy, task cancel and answer, reap, partners reload).

Every route except /healthz needs a principal with the ``a2agw:admin`` scope. Every write
(POST, PUT, DELETE) also needs the header ``X-A2AGW-Admin: 1`` (403 without it, in every
auth mode, including ``admin_without_auth``): a cross-site form or a simple request cannot
set it.
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
still have open outbound tasks (unless ``force=true``, which disables those partners and
cancels their partner tasks first, best effort). A refused or invalid reload changes
nothing; a forced one that then answers 409 ``registry changed during reload`` has already
disabled the removed partners and cancelled their tasks (retry the reload). Every attempt
is audited as ``partner.reload``.

Tasks: ``GET tasks/{agent}/{task}`` (detail: last 50 messages and artifacts, files by name,
MIME type and size only; the partner tasks; the pending prompt), ``POST .../cancel`` (409
"task is final") and ``POST .../answer`` ``{"text"}`` (input-required only, else 409). A
404 is the same body for an unknown agent and an unknown task, after the same single index
lookup. Partners: ``GET``/``DELETE partners/{id}``, ``POST partners`` and
``POST partners/{id}/{approve|reject|disable|enable|refresh}``. Policy: ``GET``/``PUT
policy`` (409 while the control plane manages it; 422 with the invalid field paths).

The POST handlers only parse and map errors to responses: the operations themselves are
``a2agw.ops.actions`` (shared with the CLI and the control-plane connector).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import TYPE_CHECKING, Any

from a2a.types import TaskState
from a2a.utils.errors import A2AError
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from a2agw.consult.netguard import Tier
from a2agw.consult.registry import CardFetchError
from a2agw.ops import actions
from a2agw.ops.audit import ACTIONS, AuditEvent, parse_since
from a2agw.security.policy import PolicyError
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


NOT_FOUND = {"error": "not found"}


class _AddPartner(BaseModel):
    """``POST partners``: exactly one of ``card_url`` (fetched and checked) or ``card``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    tier: Tier
    card_url: str | None = None
    card: dict[str, Any] | None = None
    credential_ref: str | None = None
    tls_ref: str | None = None
    tags: list[str] = []


async def _json(request: Request) -> Any:
    try:
        return json.loads(await request.body())
    except ValueError:
        raise _BadRequest("body") from None


def _first_field(exc: ValidationError) -> str:
    errors = exc.errors(include_input=False, include_url=False)
    if not errors:
        return "body"
    return ".".join(str(p) for p in errors[0]["loc"]) or "body"


def _not_found() -> JSONResponse:
    return JSONResponse(NOT_FOUND, status_code=404)


def _card_error(exc: CardFetchError) -> JSONResponse:
    # The reason's category only (the message after it may quote a URL or an error).
    reason = str(exc).split(":", 1)[0][:100]
    return JSONResponse({"error": "card not accepted", "reason": reason}, status_code=422)


def _actor(request: Request) -> str:
    """The audit actor of an admin request: the principal id."""
    user = request.scope.get("user")
    return user.principal.id if isinstance(user, PrincipalUser) else "anonymous"


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
        user = request.scope.get("user")
        principal = user.principal if isinstance(user, PrincipalUser) else None
        ev = AuditEvent(
            actor=principal.id if principal is not None else "anonymous",
            action=action,
            outcome=outcome,
            detail={"reason": reason},
        )
        if action == "authz.deny":
            # A security.denied bus event too; the audit row of an anonymous caller is
            # coalesced (one row per admin category per window), the event never.
            anonymous = principal is None or principal.kind == "anonymous"
            await host.report_denied(ev, coalesce=reason if anonymous else None)
            return
        log = getattr(host, "audit", None)
        if log is not None:
            await log.emit(ev)

    def guarded(
        category: str, fn: Handler, *, read: bool = True, audit_read: bool = True
    ) -> Handler:
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
            if read and audit_read:
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
        try:
            body = await actions.reap(host, agent_id, actor=_actor(request), **flags)
        except AgentServedError:
            return JSONResponse({"error": "agent is served by this gateway"}, status_code=409)
        except RecentActivityError as exc:
            return JSONResponse(
                {"error": "tasks changed recently; use force=true", "recent": exc.count},
                status_code=409,
            )
        return JSONResponse(body)

    async def partners_reload(request: Request) -> Response:
        from a2agw.consult.registry import ReloadConflict
        from a2agw.serve.host import PartnersInUse

        raw = request.query_params.get("force", "false")
        if raw not in ("true", "false"):
            raise _BadRequest("force")
        # Audited (ok / refused / conflict / error) by ``actions.reload_partners``.
        try:
            changes = await actions.reload_partners(
                host, actor=_actor(request), force=raw == "true"
            )
        except PartnersInUse as exc:
            return JSONResponse(
                {
                    "error": "removed partners have open outbound tasks; use force=true",
                    "open_handles": exc.open_handles,
                },
                status_code=409,
            )
        except ReloadConflict:
            return JSONResponse({"error": "registry changed during reload; retry"}, status_code=409)
        except (ValueError, OSError):
            # The message may quote the file; only its class goes out (and to the audit).
            return JSONResponse({"error": "partners file not reloaded"}, status_code=400)
        # Any other error is a bug, not a bad file: a plain 500.
        return JSONResponse(changes)

    # -- partners ---------------------------------------------------------------------------

    async def partner_get(request: Request) -> Response:
        try:
            return JSONResponse(
                await actions.partner_detail(host, request.path_params["id"], actor=_actor(request))
            )
        except KeyError:
            return _not_found()

    async def partner_add(request: Request) -> Response:
        try:
            body = _AddPartner.model_validate(await _json(request))
        except ValidationError as exc:
            raise _BadRequest(_first_field(exc)) from None
        if (body.card_url is None) == (body.card is None):
            raise _BadRequest("card")
        actor = _actor(request)
        try:
            await actions.add_partner(host, actor=actor, **body.model_dump())
        except CardFetchError as exc:
            return _card_error(exc)
        except ValueError as exc:
            if str(exc).startswith("duplicate"):
                return JSONResponse({"error": "partner already exists"}, status_code=409)
            raise _BadRequest("id") from None
        return JSONResponse(await actions.partner_detail(host, body.id, actor=actor))

    def partner_op(op: str) -> Handler:
        async def handler(request: Request) -> Response:
            pid = request.path_params["id"]
            actor = _actor(request)
            extra: dict[str, Any] = {}
            try:
                if op == "approve":
                    body = await _json(request)
                    expected = body.get("expected_hash") if isinstance(body, dict) else None
                    if not isinstance(expected, str) or not expected:
                        raise _BadRequest("expected_hash")
                    await actions.approve_partner(host, pid, expected_hash=expected, actor=actor)
                elif op == "refresh":
                    extra["result"] = (await actions.refresh_partner(host, pid, actor=actor))[
                        "result"
                    ]
                else:
                    fn = {
                        "reject": actions.reject_partner,
                        "disable": actions.disable_partner,
                        "enable": actions.enable_partner,
                    }[op]
                    await fn(host, pid, actor=actor)
            except KeyError:
                return _not_found()
            except CardFetchError as exc:
                return _card_error(exc)
            except ValueError as exc:
                # The registry's own messages: ids and reasons, never secrets.
                return JSONResponse({"error": str(exc)[:256]}, status_code=409)
            return JSONResponse({**await actions.partner_detail(host, pid, actor=actor), **extra})

        return handler

    async def partner_delete(request: Request) -> Response:
        from a2agw.serve.host import PartnersInUse

        raw = request.query_params.get("force", "false")
        if raw not in ("true", "false"):
            raise _BadRequest("force")
        pid = request.path_params["id"]
        try:
            out = await actions.remove_partner(
                host, pid, actor=_actor(request), force=raw == "true"
            )
        except KeyError:
            return _not_found()
        except PartnersInUse as exc:
            return JSONResponse(
                {
                    "error": "partner has open outbound tasks; use force=true",
                    "open_handles": exc.open_handles,
                },
                status_code=409,
            )
        return JSONResponse(
            {
                "removed": pid,
                "open_handles": out["open_handles"],
                "cancelled": out["cancelled"],
                "cancel_errors": out["cancel_errors"],
            }
        )

    # -- policy -----------------------------------------------------------------------------

    async def policy_get(_: Request) -> Response:
        return JSONResponse(actions.policy_state(host))

    async def policy_put(request: Request) -> Response:
        doc = await _json(request)
        try:
            out = await actions.set_policy(
                host, doc, actor=_actor(request), source="admin", allow_clear=False
            )
        except actions.PolicyManaged:
            return JSONResponse(
                {"error": "policy is managed by the control plane"}, status_code=409
            )
        except PolicyError as exc:
            return JSONResponse({"error": "invalid policy", "fields": exc.fields}, status_code=422)
        return JSONResponse({"policy": actions.policy_state(host)["policy"], "hash": out["hash"]})

    # -- tasks ------------------------------------------------------------------------------

    def task_route(fn: Callable[[Request, str, str], Awaitable[Response]]) -> Handler:
        async def handler(request: Request) -> Response:
            if host.index is None:
                return JSONResponse({"error": "not started"}, status_code=503)
            try:
                return await fn(
                    request, request.path_params["agent_id"], request.path_params["task_id"]
                )
            except actions.TaskNotFound:
                return _not_found()
            except actions.TaskConflict as exc:
                return JSONResponse({"error": exc.error}, status_code=409)
            except A2AError:
                # The handler refused for another reason (e.g. the owner's concurrency
                # cap); its message may describe the task, so only this goes out.
                return JSONResponse({"error": "task not changed"}, status_code=409)

        return handler

    async def task_get(request: Request, agent_id: str, task_id: str) -> Response:
        return JSONResponse(
            await actions.task_detail(host, agent_id, task_id, actor=_actor(request))
        )

    async def task_cancel(request: Request, agent_id: str, task_id: str) -> Response:
        return JSONResponse(
            await actions.cancel_task(host, agent_id, task_id, actor=_actor(request))
        )

    async def task_answer(request: Request, agent_id: str, task_id: str) -> Response:
        body = await _json(request)
        if not isinstance(body, dict):
            raise _BadRequest("body")
        extra = sorted(set(body) - {"text"})
        if extra:
            raise _BadRequest(str(extra[0])[:MAX_FILTER_CHARS])
        try:
            text = actions.check_answer(body.get("text"))
        except ValueError:
            raise _BadRequest("text") from None
        return JSONResponse(
            await actions.answer_task(host, agent_id, task_id, text, actor=_actor(request))
        )

    def route(
        name: str,
        fn: Handler,
        *,
        method: str = "GET",
        category: str | None = None,
        audit_read: bool = True,
    ) -> Route:
        handler = guarded(
            category or name.replace("/", "."),
            fn,
            read=method == "GET",
            audit_read=audit_read,
        )
        return Route(f"{ADMIN_PREFIX}/{name}", handler, methods=[method])

    partner_ops = [
        route(f"partners/{{id}}/{op}", partner_op(op), method="POST", category=f"partners.{op}")
        for op in ("approve", "reject", "disable", "enable", "refresh")
    ]

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
        # Task detail audits itself (``admin.read`` naming the task): see actions.
        route(
            "tasks/{agent_id}/{task_id}",
            task_route(task_get),
            category="tasks.detail",
            audit_read=False,
        ),
        route(
            "tasks/{agent_id}/{task_id}/cancel",
            task_route(task_cancel),
            method="POST",
            category="tasks.cancel",
        ),
        route(
            "tasks/{agent_id}/{task_id}/answer",
            task_route(task_answer),
            method="POST",
            category="tasks.answer",
        ),
        route("partners", partner_add, method="POST", category="partners.add"),
        route("partners/{id}", partner_get, category="partners.detail"),
        route("partners/{id}", partner_delete, method="DELETE", category="partners.remove"),
        *partner_ops,
        route("policy", policy_get),
        route("policy", policy_put, method="PUT"),
    ]


def _frame(ev: Any) -> str:
    payload = json.dumps(
        {"kind": ev.kind, "agent_id": ev.agent_id, "data": ev.data, "ts": ev.ts}, default=str
    )
    return f"event: {ev.kind}\nid: {ev.ts}\ndata: {payload}\n\n"
