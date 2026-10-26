"""The outbound MCP server (spec 7.7): the partner tools of one agent id, served over MCP, so an
MCP-capable agent (Claude Code, Cursor, the Claude Agent SDK, OpenAI Agents, ...) can consult
the partner network with no code of its own (see ``docs/sidecar.md``).

This module is the only one that imports ``mcp`` (the ``mcp`` extra); the host imports it only
when an MCP server is configured.

**Tools** are ``host.partner_tools(agent_id)`` (the companion tools included), recomputed on
every ``tools/list``: each description ends with ``UNTRUSTED_NOTE``, and the input schema is
the tool's own without its ``x-`` keys (the full schema, limits included, still checks every
call). A call answers ``CallToolResult`` with the tool's JSON result as text and as
``structuredContent``, ``isError`` for a ``failed`` or ``rejected`` one. A tool that is not in
the current list (a partner since quarantined, removed or forbidden) answers ``isError`` with
``{"state": "unavailable", "reason": "unknown tool"}``. When partners change, open sessions
get ``notifications/tools/list_changed`` (handshake-era sessions; best effort).

**Calls** run through the call path the REST API uses (``a2agw.gateway.calls``), so a tool
call behaves exactly like the corresponding REST call: partner-task ownership, the hidden
partner and unknown task answers, the standalone open-task cap, linked contexts and grant
audit detail.

**Transports:**

- Streamable HTTP at ``/a2agw/mcp/{agent_id}`` (``mcp_asgi_app``; ``agent_id`` must be one of
  the host's ``mcp_agents``, else 404). Every request is authenticated like the REST API
  (``a2agw.gateway.auth``): a consult token links the session's calls to its inbound run, or
  a standalone principal with the ``a2agw:sidecar`` scope must be mapped to ``agent_id`` (the
  path names the agent; no ``X-A2AGW-Agent`` header is needed). A session can only be used
  by the caller that opened it. DNS-rebinding protection allows the ``base_url`` host only.
- Stdio (``run_stdio``, ``a2agw mcp --agent <id>``): calls are standalone, owned by
  ``sidecar:<agent id>`` for the local caller ``local:<agent id>``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from collections.abc import Callable
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import mcp_types as types
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.session import ServerSession
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import get_route_path
from starlette.types import Receive, Scope, Send

from a2agw.consult.registry import PartnerRecord
from a2agw.consult.tools import UNTRUSTED_NOTE, PartnerTool, rejection
from a2agw.gateway.auth import (
    AGENT_HEADER,
    OTHER_AGENT,
    SidecarAuthError,
    SidecarIdentity,
    audit_denied,
    from_headers,
)
from a2agw.gateway.calls import INBOUND_ENDED, Work, unknown
from a2agw.security.principal import Principal, PrincipalUser

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

__all__ = ["McpHttpApp", "build_mcp_server", "mcp_asgi_app", "run_stdio"]

logger = logging.getLogger(__name__)

UNKNOWN_TOOL = "unknown tool"
IDENTITY_KEY = "a2agw.sidecar"  # the request scope key the HTTP app stores the caller under
MAX_TRACKED_SESSIONS = 1024  # sessions told about tool list changes (most recently active)
NOTIFY_TIMEOUT_S = 5.0
_ERROR_STATES = frozenset({"failed", "rejected"})
_NO_STORE = {"Cache-Control": "no-store"}


def _strip_x(schema: Any) -> Any:
    """``schema`` without its ``x-`` keys (gateway-only limits clients need not know)."""
    if isinstance(schema, dict):
        return {k: _strip_x(v) for k, v in schema.items() if not str(k).startswith("x-")}
    if isinstance(schema, list):
        return [_strip_x(v) for v in schema]
    return schema


def _result(envelope: dict[str, Any], *, error: bool | None = None) -> types.CallToolResult:
    if error is None:
        error = envelope.get("state") in _ERROR_STATES
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(envelope))],
        structured_content=envelope,
        is_error=error,
    )


class _Server(Server[Any]):
    """A low-level server that advertises ``tools.listChanged`` (the streamable-HTTP manager
    builds each session's initialization options without arguments)."""

    def create_initialization_options(
        self,
        notification_options: NotificationOptions | None = None,
        experimental_capabilities: dict[str, dict[str, Any]] | None = None,
        extensions: dict[str, dict[str, Any]] | None = None,
    ) -> InitializationOptions:
        return super().create_initialization_options(
            notification_options or NotificationOptions(tools_changed=True),
            experimental_capabilities,
            extensions,
        )


class _AgentServer:
    """One agent id's MCP server, and the sessions it tells about tool list changes."""

    def __init__(self, host: AgentHost, agent_id: str, identity: SidecarIdentity | None) -> None:
        self.host = host
        self.agent_id = agent_id
        self.identity = identity  # fixed (stdio); None: the HTTP request's caller
        self._sessions: OrderedDict[str, ServerSession] = OrderedDict()
        self._notify_due = False
        self._tasks: set[asyncio.Task[None]] = set()
        self.server = _Server(
            f"a2agw-{agent_id}",
            instructions=UNTRUSTED_NOTE,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )

    def _ident(self, ctx: ServerRequestContext[Any, Any]) -> SidecarIdentity | None:
        if self.identity is not None:
            return self.identity
        scope = getattr(ctx.request, "scope", None)
        ident = scope.get(IDENTITY_KEY) if isinstance(scope, dict) else None
        if isinstance(ident, SidecarIdentity) and ident.agent_id == self.agent_id:
            return ident
        return None

    def _track(self, ctx: ServerRequestContext[Any, Any]) -> None:
        """Remember the session for list-change notifications (stdio has exactly one; an
        HTTP session is known by its id once it has one)."""
        if ctx.request is None:
            key = ""
        else:
            key = ctx.request.headers.get("mcp-session-id") or ""
            if not key:
                return
        self._sessions[key] = ctx.session
        self._sessions.move_to_end(key)
        while len(self._sessions) > MAX_TRACKED_SESSIONS:
            self._sessions.popitem(last=False)

    async def _list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        ident = self._ident(ctx)
        if ident is None:
            return types.ListToolsResult(tools=[])
        self._track(ctx)
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=t.name,
                    description=t.description + "\n\n" + UNTRUSTED_NOTE,
                    input_schema=_strip_x(t.parameters),
                )
                for t in self.host.sidecar_calls.tools(ident)
            ]
        )

    async def _call_tool(
        self, ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        ident = self._ident(ctx)
        if ident is None:
            return _result({"state": "unavailable", "reason": "unauthenticated"}, error=True)
        self._track(ctx)
        if self.host.client is None:
            return _result({"state": "unavailable", "reason": "not started"}, error=True)
        calls = self.host.sidecar_calls
        tools = calls.tools(ident)
        tool = next((t for t in tools if t.name == params.name), None)
        if tool is None:
            return _result({"state": "unavailable", "reason": UNKNOWN_TOOL}, error=True)
        args = params.arguments or {}
        rejected = rejection(tool, args)
        if rejected is not None:
            return _result(rejected)
        partner = tool.partner_id or args.get("partner_id")
        try:
            return _result(await calls.call(ident, partner, self._work(ident, tools, tool, args)))
        except SidecarAuthError as e:  # the token was revoked before the call started
            await audit_denied(self.host, e)
            out: dict[str, Any] = {"state": "unavailable", "reason": INBOUND_ENDED}
            return _result(out if partner is None else {"partner": partner, **out}, error=True)

    def _work(
        self,
        ident: SidecarIdentity,
        tools: list[PartnerTool],
        tool: PartnerTool,
        args: dict[str, Any],
    ) -> Work:
        """The REST route's work for this (validated) tool call."""
        calls = self.host.sidecar_calls
        if tool.kind == "consult":
            assert tool.partner_id is not None
            pid: str = tool.partner_id
            return lambda: calls.consult(ident, tool, args, pid)
        if tool.kind == "consult_any":

            async def consult_any() -> dict[str, Any]:
                target = args["partner_id"]
                if target not in calls.visible(tools):
                    return unknown(target)
                return await calls.consult(ident, tool, args, target)

            return consult_any
        if tool.kind in ("check", "cancel"):
            kind = tool.kind
            return lambda: calls.task_op(ident, tools, kind, args["partner_id"], args["task_id"])
        if tool.kind == "wait":
            return lambda: calls.wait(ident, tools, args)
        return lambda: calls.find(ident, tools, args)

    def changed(self, rec: PartnerRecord | None = None, event: str = "") -> None:
        """Registry listener: tell the open sessions the tool list changed (coalesced)."""
        if not self._sessions or self._notify_due:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # a change made outside the event loop: the next tools/list sees it
        self._notify_due = True
        task = loop.create_task(self._notify(), name="a2agw:mcp-list-changed")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _notify(self) -> None:
        self._notify_due = False
        for key, session in list(self._sessions.items()):
            try:
                async with asyncio.timeout(NOTIFY_TIMEOUT_S):
                    await session.send_tool_list_changed()
            except Exception:  # noqa: BLE001 - a closed or stuck session: forget it
                if self._sessions.get(key) is session:
                    del self._sessions[key]

    async def aclose(self) -> None:
        tasks, self._tasks = list(self._tasks), set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._sessions.clear()


def build_mcp_server(
    host: AgentHost, agent_id: str, *, identity: SidecarIdentity | None = None
) -> Server[Any]:
    """The MCP server of ``agent_id``'s partner tools on ``host``. Calls act as ``identity``
    when given, else as the caller ``mcp_asgi_app`` authenticated for the HTTP request."""
    return _AgentServer(host, agent_id, identity).server


async def _respond(
    scope: Scope, receive: Receive, send: Send, status: int, error: str, **headers: str
) -> None:
    response = JSONResponse({"error": error}, status_code=status, headers={**_NO_STORE, **headers})
    await response(scope, receive, send)


class McpHttpApp:
    """The streamable-HTTP MCP endpoints of a host's ``mcp_agents``, mounted at
    ``/a2agw/mcp``. ``start``/``stop`` run the session managers (the host calls them at
    startup and shutdown); until started it answers 503."""

    def __init__(self, host: AgentHost) -> None:
        self.host = host
        url = urlsplit(host.base_url)
        hostname = url.hostname or ""
        if ":" in hostname:  # IPv6
            hostname = f"[{hostname}]"
        self.security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[url.netloc, f"{hostname}:*"],
            allowed_origins=[f"{url.scheme}://{url.netloc}", f"{url.scheme}://{hostname}:*"],
        )
        self._agents: dict[str, _AgentServer] = {}
        self._managers: dict[str, StreamableHTTPSessionManager] = {}
        self._task: asyncio.Task[None] | None = None
        self._stop: asyncio.Event | None = None

    async def start(self) -> None:
        """Run a session manager per agent id, in a task of its own (its task group must be
        entered and left in one task; the host's startup and shutdown may not be)."""
        if self._task is not None:
            return
        agents = {a: _AgentServer(self.host, a, None) for a in sorted(self.host.mcp_agents or ())}
        managers = {
            a: StreamableHTTPSessionManager(app=s.server, security_settings=self.security)
            for a, s in agents.items()
        }
        ready, stop = asyncio.Event(), asyncio.Event()

        async def run() -> None:
            async with AsyncExitStack() as stack:
                for manager in managers.values():
                    await stack.enter_async_context(manager.run())
                ready.set()
                await stop.wait()

        task = asyncio.create_task(run(), name="a2agw:mcp")
        waiter = asyncio.ensure_future(ready.wait())
        await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        if not ready.is_set():
            await task  # raises its error
            raise RuntimeError("MCP session managers stopped during startup")
        self._agents, self._managers, self._task, self._stop = agents, managers, task, stop
        self.host.partners.add_listener(self._changed)

    async def stop(self) -> None:
        """End every session (their calls in flight are cancelled)."""
        task, stop, agents = self._task, self._stop, self._agents
        if task is None or stop is None:
            return
        self.host.partners.remove_listener(self._changed)
        self._agents, self._managers, self._task, self._stop = {}, {}, None, None
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        for agent in agents.values():
            await agent.aclose()

    def _changed(self, rec: PartnerRecord, event: str) -> None:
        for agent in self._agents.values():
            agent.changed(rec, event)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        agent_id = get_route_path(scope).removeprefix("/")
        if agent_id not in (self.host.mcp_agents or ()):
            await _respond(scope, receive, send, 404, "not found")
            return
        manager = self._managers.get(agent_id)
        if manager is None:
            await _respond(scope, receive, send, 503, "not started")
            return
        user = scope.get("user")
        principal = user.principal if isinstance(user, PrincipalUser) else None
        headers = dict(Headers(scope=scope).items())
        headers[AGENT_HEADER] = agent_id  # the path names the agent
        try:
            ident = from_headers(headers, principal, self.host)
            if ident.agent_id != agent_id:
                raise SidecarAuthError(
                    403, OTHER_AGENT, agent_id=agent_id, principal=ident.principal
                )
        except SidecarAuthError as e:
            await audit_denied(self.host, e)
            if e.status == 403:
                await _respond(scope, receive, send, 403, "forbidden")
            else:
                await _respond(scope, receive, send, 401, "unauthenticated", **_BEARER)
            return
        # The session manager binds each session to the caller that opened it.
        b, p = ident.binding, ident.principal
        owner = f"inbound:{b.inbound_task_id}" if b is not None else f"principal:{_id(p)}"
        session_user = AuthenticatedUser(AccessToken(token="", client_id=owner, scopes=[]))
        await manager.handle_request(
            {**scope, "user": session_user, IDENTITY_KEY: ident}, receive, send
        )


_BEARER = {"WWW-Authenticate": "Bearer"}


def _id(p: Principal | None) -> str:
    return p.id if p is not None else "anonymous"


def mcp_asgi_app(host: AgentHost) -> McpHttpApp:
    """The ASGI app serving ``host.mcp_agents`` over streamable HTTP behind the gateway
    auth (``AgentHost.app`` mounts it at ``/a2agw/mcp`` and runs its lifecycle)."""
    return McpHttpApp(host)


async def run_stdio(host: AgentHost, agent_id: str) -> None:
    """Serve ``agent_id``'s partner tools over stdio until stdin closes. ``host`` must be
    started. Calls are standalone, owned by ``sidecar:<agent_id>`` for the caller
    ``local:<agent_id>``."""
    ident = SidecarIdentity(agent_id, None, Principal.from_id(f"local:{agent_id}"))
    agent = _AgentServer(host, agent_id, ident)
    listener: Callable[[PartnerRecord, str], None] = agent.changed
    host.partners.add_listener(listener)
    try:
        async with stdio_server() as (read, write):
            await agent.server.run(read, write, agent.server.create_initialization_options())
    finally:
        host.partners.remove_listener(listener)
        await agent.aclose()
