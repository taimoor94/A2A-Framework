"""The outbound REST API, ``/a2agw/v1``: lets an external agent (any language) consult the
partner agents it may use, through the gateway (see ``docs/sidecar.md``).

Each route is one of the partner tools (``a2agw.consult.tools``), run with ``invoke`` for the
agent the caller acts as (``a2agw.gateway.auth``): the agent's routing (visible and forbidden
partners) and egress policy apply, and the response is the tool's result. A call made with a
consult token runs linked to its inbound task, exactly as an embedded agent's tool call would:
under that task's call context, caller and agent (``use_call``, ``use_inbound``,
``use_agent``), so ``PartnerClient`` applies cascade cancel, the fan-out cap and call-context
propagation. A standalone call has no inbound task: its call context is a fresh root and the
partner task's handle is owned by ``sidecar:<agent id>`` (so the host's TTL expiry covers it).

Every response has ``Cache-Control: no-store``. Request bodies are JSON objects of at most
``MAX_BODY_BYTES`` (413 beyond).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from a2agw.consult.tools import PartnerTool, invoke
from a2agw.context.call_context import (
    CallContext,
    use_agent,
    use_call,
    use_inbound,
    use_inbound_token,
)
from a2agw.gateway.auth import SidecarAuthError, SidecarIdentity, audit_denied, resolve_sidecar

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

__all__ = ["MAX_BODY_BYTES", "REST_PREFIX", "rest_routes"]

REST_PREFIX = "/a2agw/v1"
MAX_BODY_BYTES = 256 * 1024
UNKNOWN_PARTNER = "unknown partner"
INBOUND_ENDED = "inbound task ended"  # the consult token was revoked while the call ran
TOKEN_REVOKED = "consult token revoked"

_NO_STORE = {"Cache-Control": "no-store"}
_FIND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "need": {"type": "string", "maxLength": 4096},
        "k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
    },
    "required": ["need"],
    "additionalProperties": False,
}

Args = dict[str, Any]
Work = Callable[[], Awaitable[Any]]


class _BodyError(Exception):
    def __init__(self, status: int, error: str) -> None:
        self.status = status
        self.error = error


def _json(content: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse(content, status_code=status, headers={**_NO_STORE, **(headers or {})})


def _unknown(partner_id: str) -> dict[str, Any]:
    return {"partner": partner_id, "state": "unavailable", "reason": UNKNOWN_PARTNER}


async def _read_object(request: Request) -> Args:
    """The JSON object body, read up to ``MAX_BODY_BYTES``."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _BodyError(413, "payload too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY_BYTES:
            raise _BodyError(413, "payload too large")
    try:
        obj = json.loads(buf)
    except (ValueError, RecursionError):  # incl. UnicodeDecodeError
        raise _BodyError(400, "bad request") from None
    if not isinstance(obj, dict):
        raise _BodyError(400, "bad request")
    return obj


def _visible(host: AgentHost, tools: list[PartnerTool]) -> set[str]:
    """The partner ids the agent's tools can reach."""
    for t in tools:
        if t.kind in ("find", "consult_any"):
            active = {r.id for r in host.partners.active()}
            return active if t.allowed is None else active & t.allowed
    return {t.partner_id for t in tools if t.kind == "consult" and t.partner_id}


@contextmanager
def _acting_as(ident: SidecarIdentity) -> Iterator[None]:
    """The context an embedded agent's tool call would run in: its call context, inbound
    task, caller and agent id. A standalone call is a fresh root with no inbound task."""
    b = ident.binding
    if b is not None:
        call = b.call or CallContext.new(ident.agent_id)
        task_id, principal = b.inbound_task_id, b.caller
    else:
        call, task_id, principal = CallContext.new(ident.agent_id), None, ident.principal
    with (
        use_call(call),
        use_inbound(task_id, principal),
        use_inbound_token(None),
        use_agent(ident.agent_id),
    ):
        yield


def rest_routes(host: AgentHost) -> list[Route]:
    """The ``/a2agw/v1`` routes of ``host`` (mounted by ``AgentHost.app``)."""

    async def run(ident: SidecarIdentity, tool: PartnerTool, args: Any) -> dict[str, Any]:
        assert host.client is not None
        b = ident.binding
        return await invoke(
            tool,
            args,
            host.client,
            b.inbound_task_id if b is not None else None,
            ident.principal,
            owner=None if b is not None else host.sidecar_owner(ident.agent_id),
        )

    async def call(ident: SidecarIdentity, partner: str | None, work: Work) -> Any:
        """Run ``work`` as the agent. A linked call is tracked: revoking its token (the run
        ended) cancels it, and it then answers ``unavailable``."""
        with _acting_as(ident):
            if ident.binding is None:
                return await work()
            task = asyncio.ensure_future(work())
        with host.consult_tokens.track(ident.binding, task) as live:
            if not live:
                task.cancel()  # never started
                raise SidecarAuthError(401, TOKEN_REVOKED, agent_id=ident.agent_id)
            try:
                return await task
            except asyncio.CancelledError:
                this = asyncio.current_task()
                if this is not None and this.cancelling():
                    raise  # the request itself is being cancelled
        out: dict[str, Any] = {"state": "unavailable", "reason": INBOUND_ENDED}
        return out if partner is None else {"partner": partner, **out}

    def endpoint(
        handler: Callable[[Request, SidecarIdentity, Args], Awaitable[tuple[str | None, Work]]],
        *,
        body: bool,
    ) -> Callable[[Request], Awaitable[Response]]:
        async def endpoint_(request: Request) -> Response:
            try:
                ident = await resolve_sidecar(request, host)
                args = await _read_object(request) if body else {}
                if host.client is None:
                    return _json({"error": "not started"}, 503)
                partner, work = await handler(request, ident, args)
                return _json(await call(ident, partner, work))
            except SidecarAuthError as e:
                if e.reason == TOKEN_REVOKED:
                    await audit_denied(host, e)
                if e.status == 403:
                    return _json({"error": "forbidden"}, 403)
                return _json({"error": "unauthenticated"}, 401, {"WWW-Authenticate": "Bearer"})
            except _BodyError as e:
                return _json({"error": e.error}, e.status)

        return endpoint_

    def tools_of(ident: SidecarIdentity) -> list[PartnerTool]:
        return host.partner_tools(ident.agent_id)

    async def partners(_: Request, ident: SidecarIdentity, _a: Args) -> tuple[None, Work]:
        async def work() -> list[dict[str, Any]]:
            return [
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                    "partner_id": t.partner_id,
                    "kind": t.kind,
                }
                for t in tools_of(ident)
            ]

        return None, work

    async def messages(request: Request, ident: SidecarIdentity, args: Args) -> tuple[str, Work]:
        pid = request.path_params["partner_id"]
        tools = tools_of(ident)
        tool = next((t for t in tools if t.kind == "consult" and t.partner_id == pid), None)

        async def work() -> dict[str, Any]:
            if "partner_id" in args:  # the path names the partner
                return {"state": "rejected", "reason": "invalid arguments: partner_id"}
            if tool is not None:
                return await run(ident, tool, args)
            anyone = next((t for t in tools if t.kind == "consult_any"), None)
            if anyone is None or pid not in _visible(host, tools):
                return _unknown(pid)
            return await run(ident, anyone, {**args, "partner_id": pid})

        return pid, work

    def task_route(kind: str) -> Callable[..., Awaitable[tuple[str, Work]]]:
        async def handler(request: Request, ident: SidecarIdentity, _a: Args) -> tuple[str, Work]:
            pid, tid = request.path_params["partner_id"], request.path_params["task_id"]
            tools = tools_of(ident)

            async def work() -> dict[str, Any]:
                if pid not in _visible(host, tools):
                    return _unknown(pid)
                tool = next(t for t in tools if t.kind == kind)
                return await run(ident, tool, {"partner_id": pid, "task_id": tid})

            return pid, work

        return handler

    async def wait(_: Request, ident: SidecarIdentity, args: Args) -> tuple[None, Work]:
        tools = tools_of(ident)

        async def work() -> dict[str, Any]:
            visible = _visible(host, tools)
            items = args.get("tasks")
            for item in items if isinstance(items, list) else ():
                pid = item.get("partner_id") if isinstance(item, dict) else None
                if isinstance(pid, str) and pid not in visible:
                    return _unknown(pid)
            return await run(ident, next(t for t in tools if t.kind == "wait"), args)

        return None, work

    async def find(_: Request, ident: SidecarIdentity, args: Args) -> tuple[None, Work]:
        tools = tools_of(ident)

        async def work() -> dict[str, Any]:
            tool = next((t for t in tools if t.kind == "find"), None)
            if tool is None:  # few partners: no discovery tool, rank the visible ones
                visible = frozenset(_visible(host, tools))
                tool = PartnerTool("find_partners", "", _FIND_SCHEMA, None, "find", visible)
            return await run(ident, tool, args)

        return None, work

    p = REST_PREFIX
    return [
        Route(f"{p}/partners", endpoint(partners, body=False), methods=["GET"]),
        Route(
            f"{p}/partners/{{partner_id}}/messages", endpoint(messages, body=True), methods=["POST"]
        ),
        Route(
            f"{p}/partners/{{partner_id}}/tasks/{{task_id}}",
            endpoint(task_route("check"), body=False),
            methods=["GET"],
        ),
        Route(
            f"{p}/partners/{{partner_id}}/tasks/{{task_id}}/cancel",
            endpoint(task_route("cancel"), body=False),
            methods=["POST"],
        ),
        Route(f"{p}/wait", endpoint(wait, body=True), methods=["POST"]),
        Route(f"{p}/find", endpoint(find, body=True), methods=["POST"]),
    ]
