"""The outbound REST API, ``/a2agw/v1``: lets an external agent (any language) consult the
partner agents it may use, through the gateway (see ``docs/sidecar.md``).

Each route is one of the partner tools (``a2agw.consult.tools``), run for the agent the
caller acts as (``a2agw.gateway.auth``) through the call path it shares with the MCP server
(``a2agw.gateway.calls``): the agent's routing (visible and forbidden partners) and egress
policy apply, and the response is the tool's result. A call made with a consult token runs
linked to its inbound task, exactly as an embedded agent's tool call would, so
``PartnerClient`` applies cascade cancel, the fan-out cap and call-context propagation. A
standalone call has no inbound task: its call context is a fresh root and the partner task's
handle is owned by ``sidecar:<agent id>`` (so the host's TTL expiry covers it).

Every response has ``Cache-Control: no-store``. Request bodies are JSON objects of at most
``MAX_BODY_BYTES`` (413 beyond).
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Match, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from a2agw.gateway.auth import SidecarAuthError, SidecarIdentity, audit_denied, resolve_sidecar
from a2agw.gateway.calls import TOKEN_REVOKED, Args, Work, unknown

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

__all__ = ["MAX_BODY_BYTES", "REST_PREFIX", "rest_routes"]

REST_PREFIX = "/a2agw/v1"
MAX_BODY_BYTES = 256 * 1024

_NO_STORE = {"Cache-Control": "no-store"}


class _AsgiApp:
    """Wraps an ASGI callable so Starlette mounts it as an app (every method) rather than as
    a request/response endpoint (GET only)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)


class _BodyError(Exception):
    def __init__(self, status: int, error: str) -> None:
        self.status = status
        self.error = error


def _json(content: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return JSONResponse(content, status_code=status, headers={**_NO_STORE, **(headers or {})})


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


def rest_routes(host: AgentHost) -> list[Route]:
    """The ``/a2agw/v1`` routes of ``host`` (mounted by ``AgentHost.app``)."""
    calls = host.sidecar_calls

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
                return _json(await calls.call(ident, partner, work))
            except SidecarAuthError as e:
                if e.reason == TOKEN_REVOKED:
                    await audit_denied(host, e)
                if e.status == 403:
                    return _json({"error": "forbidden"}, 403)
                return _json({"error": "unauthenticated"}, 401, {"WWW-Authenticate": "Bearer"})
            except _BodyError as e:
                return _json({"error": e.error}, e.status)

        return endpoint_

    async def partners(_: Request, ident: SidecarIdentity, _a: Args) -> tuple[None, Work]:
        async def work() -> list[dict[str, Any]]:
            return calls.listing(ident)

        return None, work

    async def messages(request: Request, ident: SidecarIdentity, args: Args) -> tuple[str, Work]:
        pid = request.path_params["partner_id"]
        tools = calls.tools(ident)
        tool = next((t for t in tools if t.kind == "consult" and t.partner_id == pid), None)

        async def work() -> dict[str, Any]:
            if "partner_id" in args:  # the path names the partner
                return {"state": "rejected", "reason": "invalid arguments: partner_id"}
            if tool is not None:
                return await calls.consult(ident, tool, args, pid)
            anyone = next((t for t in tools if t.kind == "consult_any"), None)
            if anyone is None or pid not in calls.visible(tools):
                return unknown(pid)
            return await calls.consult(ident, anyone, {**args, "partner_id": pid}, pid)

        return pid, work

    def task_route(kind: str) -> Callable[..., Awaitable[tuple[str, Work]]]:
        async def handler(request: Request, ident: SidecarIdentity, _a: Args) -> tuple[str, Work]:
            pid, tid = request.path_params["partner_id"], request.path_params["task_id"]
            tools = calls.tools(ident)

            async def work() -> dict[str, Any]:
                return await calls.task_op(ident, tools, kind, pid, tid)

            return pid, work

        return handler

    async def wait(_: Request, ident: SidecarIdentity, args: Args) -> tuple[None, Work]:
        tools = calls.tools(ident)

        async def work() -> dict[str, Any]:
            return await calls.wait(ident, tools, args)

        return None, work

    async def find(_: Request, ident: SidecarIdentity, args: Args) -> tuple[None, Work]:
        tools = calls.tools(ident)

        async def work() -> dict[str, Any]:
            return await calls.find(ident, tools, args)

        return None, work

    async def fallback(scope: Scope, receive: Receive, send: Send) -> None:
        """Anything else under the prefix, whatever the method: 405 for a known path, else
        404. Never handed on to the rest of the gateway (the auth middleware lets these
        paths through). An ASGI app, not a function, so its routes take every method."""
        methods = {
            m for r in routes if r.matches(scope)[0] == Match.PARTIAL for m in (r.methods or ())
        }
        if methods:
            allow = {"Allow": ", ".join(sorted(methods))}
            response = _json({"error": "method not allowed"}, 405, allow)
        else:
            response = _json({"error": "not found"}, 404)
        await response(scope, receive, send)

    catch_all = _AsgiApp(fallback)

    p = REST_PREFIX
    routes = [
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
    return [*routes, Route(p, catch_all), Route(f"{p}/{{rest:path}}", catch_all)]
