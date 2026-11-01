"""The VSC admin API, under ``/a2agw/admin/vsc`` (mounted by ``attach_vsc`` through
``AgentHost.admin_extra_routes``), behind the admin API's rules (``a2agw.ops.admin.guard``):
the ``a2agw:vsc`` scope or ``a2agw:admin`` (``admin_without_auth`` on a host without auth),
and the ``X-A2AGW-Admin: 1`` header on every POST and PUT. JSON bodies; errors are
``{"error": ...}`` with 400 (plus ``field``), 404, 409 (plus ``state``) or 503.

- Non-admin principals see and act on their own jobs only (404 for another's; ``GET /jobs``
  lists their own); ``a2agw:admin`` sees all.
- ``GET /jobs`` (``state``, ``limit``), ``POST /jobs`` ``{"request"}`` (201; the caller owns it)
- ``GET /jobs/{id}`` (job, spec, plan, steps, ``waiting_step``), ``GET /jobs/{id}/receipt``
  (409 until the job has finished)
- ``POST /jobs/{id}/approve`` / ``reject`` ``{"step_id", "note"}`` (409 unless the job is
  ``awaiting_approval`` and ``step_id`` is the step it waits for; 400 for a step that is not
  a privileged step of its plan)
- ``POST /jobs/{id}/cancel``
- ``PUT /jobs/{id}/spec`` (an ``ExecutableSpec``; 409 outside ``awaiting_spec``; audited as
  ``vsc.job`` ``spec_edited``, then the job runs from it)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route

from a2agw.ops.admin import ADMIN_PREFIX, ADMIN_SCOPE, guard
from a2agw.ops.audit import AuditEvent
from a2agw.security.auth import VSC_SCOPE, has_scope
from a2agw.security.principal import PrincipalUser
from a2agw.vsc.gate import Gate
from a2agw.vsc.plan import PRIVILEGED_KINDS, Plan
from a2agw.vsc.runner import JobRunner
from a2agw.vsc.spec import ExecutableSpec, validate_against
from a2agw.vsc.store import VscStore

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost
    from a2agw.vsc.host import VscRuntime

VSC_ADMIN_PREFIX = f"{ADMIN_PREFIX}/vsc"
MAX_ID_CHARS = 256
DELIVER_AGENT = "deliver"  # the agent id of the job audit rows (``a2agw.vsc.runner``)


class _Bad(Exception):
    def __init__(self, field: str) -> None:
        self.field = field


def _allowed(host: AgentHost, request: Request) -> bool:
    user = request.scope.get("user")
    if not isinstance(user, PrincipalUser):
        return False
    if host.auth is None:
        return host.admin_without_auth
    return has_scope(user.principal, VSC_SCOPE)


def _is_admin(host: AgentHost, request: Request) -> bool:
    """Admins (``a2agw:admin``; anyone on an ``admin_without_auth`` host) see every job;
    other ``a2agw:vsc`` principals only their own."""
    if host.auth is None:
        return True  # only reached with admin_without_auth (``_allowed``)
    user = request.scope.get("user")
    return isinstance(user, PrincipalUser) and ADMIN_SCOPE in user.principal.scopes


def _actor(request: Request) -> str:
    user = request.scope.get("user")
    return user.principal.id if isinstance(user, PrincipalUser) else "anonymous"


def _error(status: int, error: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": error, **extra}, status_code=status)


async def _body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise _Bad("body") from None
    if not isinstance(body, dict):
        raise _Bad("body")
    return body


def _text(body: dict[str, Any], name: str, *, required: bool) -> str:
    value = body.get(name, None if required else "")
    if not isinstance(value, str) or (required and not value.strip()):
        raise _Bad(name)
    return value


def _summary(job: dict[str, Any]) -> dict[str, Any]:
    keys = ("job_id", "state", "reason", "owner", "created_at", "updated_at", "spec_hash")
    out = {k: job.get(k) for k in keys}
    out["plan_hash"] = job.get("plan_hash")
    out["usage"] = {
        k: job.get(k) for k in ("tokens_in", "tokens_out", "cost", "attempts", "active_s")
    }
    return out


def _step_view(row: dict[str, Any]) -> dict[str, Any]:
    keys = ("step_id", "system", "kind", "state", "attempt", "worker", "started_at", "ended_at")
    return {k: row.get(k) for k in keys}


def vsc_admin_routes(runtime: VscRuntime) -> list[BaseRoute]:
    """The routes under ``/a2agw/admin/vsc`` (served by the host's admin API)."""
    host = runtime.host

    def parts() -> tuple[VscStore, JobRunner, Gate]:
        if runtime.store is None or runtime.runner is None or runtime.gate is None:
            raise _NotStarted
        return runtime.store, runtime.runner, runtime.gate

    async def job_or_404(request: Request) -> dict[str, Any]:
        job_id = request.path_params["job_id"]
        store, _, _ = parts()
        job = await store.get_job(job_id) if len(job_id) <= MAX_ID_CHARS else None
        if job is None or (not _is_admin(host, request) and job["owner"] != _actor(request)):
            raise _NotFound  # another principal's job is not there for this caller
        return job

    async def list_jobs(request: Request) -> Response:
        store, _, _ = parts()
        state = request.query_params.get("state")
        if state is not None and len(state) > MAX_ID_CHARS:
            raise _Bad("state")
        try:
            limit = int(request.query_params.get("limit", "100"))
        except ValueError:
            raise _Bad("limit") from None
        if not 1 <= limit <= 500:
            raise _Bad("limit")
        owner = None if _is_admin(host, request) else _actor(request)
        jobs = await store.list_jobs(state=state, owner=owner, limit=limit)
        return JSONResponse({"jobs": [_summary(j) for j in jobs]})

    async def create_job(request: Request) -> Response:
        _, runner, _ = parts()
        text = _text(await _body(request), "request", required=True)
        try:
            job_id = await runner.submit(text, owner=_actor(request))
        except ValueError:
            raise _Bad("request") from None
        runner.start(job_id)
        return JSONResponse({"job_id": job_id, "state": "submitted"}, status_code=201)

    async def get_job(request: Request) -> Response:
        job = await job_or_404(request)
        store, _, _ = parts()
        out = _summary(job)
        out["request"] = job["request"]
        out["spec"] = json.loads(job["spec_json"]) if job["spec_json"] else None
        out["plan"] = json.loads(job["plan_json"]) if job["plan_json"] else None
        out["steps"] = [_step_view(r) for r in await store.steps(job["job_id"])]
        out["waiting_step"] = (
            await runtime.waiting_step(job["job_id"])
            if job["state"] == "awaiting_approval"
            else None
        )
        return JSONResponse(out)

    async def receipt(request: Request) -> Response:
        job = await job_or_404(request)
        if host.audit is None:
            return _error(503, "audit unavailable")
        try:
            return JSONResponse(await runtime.receipt(job["job_id"]))
        except ValueError:
            return _error(409, "job is not finished", state=job["state"])

    async def decide(request: Request, verb: str) -> Response:
        job = await job_or_404(request)
        _, _, gate = parts()
        body = await _body(request)
        step_id = _text(body, "step_id", required=True)
        note = _text(body, "note", required=False)
        if job["state"] != "awaiting_approval":
            return _error(409, "job is not awaiting approval", state=job["state"])
        plan = Plan.model_validate_json(job["plan_json"]) if job["plan_json"] else None
        steps = {s.id: s for s in plan.steps} if plan is not None else {}
        if step_id not in steps or steps[step_id].kind not in PRIVILEGED_KINDS:
            raise _Bad("step_id")
        waiting = await runtime.waiting_step(job["job_id"])
        if step_id != waiting:
            return _error(409, "that step is not waiting for approval", waiting_step=waiting)
        actor = _actor(request)
        if verb == "approve":
            await gate.approve(job["job_id"], step_id, actor=actor, note=note)
        else:
            await gate.reject(job["job_id"], step_id, actor=actor, note=note)
        return JSONResponse({"job_id": job["job_id"], "step_id": step_id, "decision": verb})

    async def approve(request: Request) -> Response:
        return await decide(request, "approve")

    async def reject(request: Request) -> Response:
        return await decide(request, "reject")

    async def cancel(request: Request) -> Response:
        job = await job_or_404(request)
        store, runner, _ = parts()
        await runner.cancel(job["job_id"], actor=_actor(request))
        now = await store.get_job(job["job_id"])
        assert now is not None
        return JSONResponse({"job_id": job["job_id"], "state": now["state"]})

    async def put_spec(request: Request) -> Response:
        job = await job_or_404(request)
        store, runner, _ = parts()
        body = await _body(request)
        if job["state"] != "awaiting_spec":
            return _error(
                409, "the spec can only be set in state awaiting_spec", state=job["state"]
            )
        try:
            spec = ExecutableSpec.model_validate(body)
            validate_against(spec, runtime.cfg)
        except (ValidationError, ValueError):
            raise _Bad("spec") from None
        await store.set_spec(job["job_id"], spec)
        now = await store.get_job(job["job_id"])
        assert now is not None
        if host.audit is not None:
            await host.audit.emit(
                AuditEvent(
                    actor=_actor(request),
                    action="vsc.job",
                    agent_id=DELIVER_AGENT,
                    task_id=job["job_id"],
                    outcome="spec_edited",
                    detail={"spec_hash": now["spec_hash"]},
                )
            )
        runner.start(job["job_id"])
        return JSONResponse({"job_id": job["job_id"], "spec_hash": now["spec_hash"]})

    def route(path: str, category: str, fn: Callable[[Request], Any], method: str) -> Route:
        async def handler(request: Request) -> Response:
            try:
                return await fn(request)
            except _Bad as exc:
                return _error(400, "bad request", field=exc.field)
            except _NotFound:
                return _error(404, "not found")
            except _NotStarted:
                return _error(503, "not started")

        guarded = guard(host, f"vsc.{category}", handler, read=method == "GET", allowed=_allowed)
        return Route(f"{VSC_ADMIN_PREFIX}{path}", guarded, methods=[method])

    return [
        route("/jobs", "jobs", list_jobs, "GET"),
        route("/jobs", "jobs.create", create_job, "POST"),
        route("/jobs/{job_id}", "job", get_job, "GET"),
        route("/jobs/{job_id}/receipt", "receipt", receipt, "GET"),
        route("/jobs/{job_id}/approve", "approve", approve, "POST"),
        route("/jobs/{job_id}/reject", "reject", reject, "POST"),
        route("/jobs/{job_id}/cancel", "cancel", cancel, "POST"),
        route("/jobs/{job_id}/spec", "spec", put_spec, "PUT"),
    ]


class _NotFound(Exception):
    pass


class _NotStarted(Exception):
    pass
