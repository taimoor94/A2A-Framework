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

- Streamable HTTP at ``/a2agw/mcp/{agent_id}`` (``mcp_asgi_app``). Every request is first
  authenticated like the REST API (``a2agw.gateway.auth``): a consult token links the
  session's calls to its inbound run (and the session ends with the token), or a standalone
  principal with the ``a2agw:sidecar`` scope must be mapped to ``agent_id`` (the path names
  the agent; no ``X-A2AGW-Agent`` header is needed). Only then is an ``agent_id`` that is not
  one of the host's ``mcp_agents`` a 404. A session can only be used by the caller that
  opened it. DNS-rebinding protection allows the ``base_url`` host only.
- Stdio (``run_stdio``, ``a2agw mcp --agent <id>``): calls are standalone, owned by
  ``sidecar:<agent id>`` for the local caller ``local:<agent id>``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import get_route_path
from starlette.types import Message, Receive, Scope, Send

from a2agw.consult.registry import PartnerRecord
from a2agw.consult.tools import UNTRUSTED_NOTE, PartnerTool, rejection
from a2agw.consult.tools import strip_extensions as _strip_x
from a2agw.consult.tools import with_untrusted_note as _describe
from a2agw.gateway.auth import (
    AGENT_HEADER,
    MCP_EXTRA_HINT,
    MCP_PREFIX,
    OTHER_AGENT,
    SidecarAuthError,
    SidecarIdentity,
    audit_denied,
    from_headers,
)
from a2agw.gateway.calls import INBOUND_ENDED, Work, unknown
from a2agw.security.principal import Principal, PrincipalUser

try:
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
except ImportError as e:  # the extra is not installed
    raise ImportError(MCP_EXTRA_HINT) from e

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
                    description=_describe(t.description),
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


@dataclass
class _Session:
    """An HTTP session this app saw open: who owns it and whether a request is in flight
    (the session manager ends a session idle for its ``session_idle_timeout``)."""

    owner: str
    user: AuthenticatedUser
    active: int = 0
    idle_since: float = 0.0


def _owner(ident: SidecarIdentity, host: AgentHost) -> str:
    """Who a session belongs to: the grant of a consult token (the session ends with it),
    or the standalone principal."""
    b = ident.binding
    if b is not None:
        return f"grant:{host.consult_tokens.grant_id(b)}"
    p = ident.principal
    return f"principal:{p.id if p is not None else 'anonymous'}"


_BEARER = {"WWW-Authenticate": "Bearer"}


class McpHttpApp:
    """The streamable-HTTP MCP endpoints of a host's ``mcp_agents``, mounted at
    ``/a2agw/mcp``. ``start``/``stop`` run the session managers (the host calls them at
    startup and shutdown); until started it answers 503.

    Sessions end promptly: those of a consult token when the token stops working, and all
    of them on ``close_sessions`` (the host calls it as soon as it is told to exit, since
    the server waits for open responses, such as a session's notification stream, before
    the host shuts down). After ``close_sessions`` new requests answer 503."""

    def __init__(self, host: AgentHost) -> None:
        self.host = host
        url = urlsplit(host.base_url)
        hostname = url.hostname or ""
        if ":" in hostname:  # IPv6
            hostname = f"[{hostname}]"
        self._netloc = url.netloc
        self._scheme = url.scheme
        self.security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[url.netloc, f"{hostname}:*"],
            allowed_origins=[f"{url.scheme}://{url.netloc}", f"{url.scheme}://{hostname}:*"],
        )
        self._agents: dict[str, _AgentServer] = {}
        self._managers: dict[str, StreamableHTTPSessionManager] = {}
        self._sessions: dict[tuple[str, str], _Session] = {}  # (agent id, session id)
        self._task: asyncio.Task[None] | None = None
        self._stop: asyncio.Event | None = None
        self._closing = False
        self._pending: set[asyncio.Task[None]] = set()

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
        self._closing = False
        self.host.partners.add_listener(self._changed)
        self.host.consult_tokens.add_revoke_listener(self._revoked)

    async def stop(self) -> None:
        """End every session (cleanly, then whatever is left is cancelled)."""
        task, stop, agents = self._task, self._stop, self._agents
        if task is None or stop is None:
            return
        await self.close_sessions()
        self.host.partners.remove_listener(self._changed)
        self.host.consult_tokens.remove_revoke_listener(self._revoked)
        pending, self._pending = list(self._pending), set()
        await asyncio.gather(*pending, return_exceptions=True)
        self._agents, self._managers, self._task, self._stop = {}, {}, None, None
        self._sessions.clear()
        stop.set()
        await asyncio.gather(task, return_exceptions=True)
        for agent in agents.values():
            await agent.aclose()

    async def close_sessions(self) -> None:
        """End every open session, and refuse new requests (503) from now on."""
        self._closing = True
        await asyncio.gather(*(self._terminate(key) for key in list(self._sessions)))

    def _changed(self, rec: PartnerRecord, event: str) -> None:
        for agent in self._agents.values():
            agent.changed(rec, event)

    def _revoked(self, grant_id: str) -> None:
        """Consult-token listener: a revoked grant's sessions end now."""
        owner = f"grant:{grant_id}"
        keys = [k for k, s in self._sessions.items() if s.owner == owner]
        if not keys:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # revoked outside the event loop: its requests are refused anyway
        task = loop.create_task(self._terminate_all(keys), name="a2agw:mcp-revoke")
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _terminate_all(self, keys: list[tuple[str, str]]) -> None:
        await asyncio.gather(*(self._terminate(k) for k in keys))

    async def _terminate(self, key: tuple[str, str]) -> None:
        """End one session the way its client would (``DELETE`` with its session id, as its
        owner): the manager closes its streams, so open responses complete."""
        info = self._sessions.pop(key, None)
        manager = self._managers.get(key[0])
        if info is None or manager is None:
            return
        agent_id, sid = key
        path = f"{MCP_PREFIX}/{agent_id}"
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "DELETE",
            "scheme": self._scheme,
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": [(b"host", self._netloc.encode()), (b"mcp-session-id", sid.encode())],
            "client": None,
            "server": None,
            "user": info.user,
        }

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def discard(message: Message) -> None:
            return None

        try:
            await manager.handle_request(scope, receive, discard)
        except Exception as e:  # noqa: BLE001 - the session is gone either way
            logger.debug("MCP session termination failed: %s", type(e).__name__)

    def _prune(self, manager: StreamableHTTPSessionManager) -> None:
        """Forget sessions the manager has ended for idleness."""
        timeout = manager.session_idle_timeout
        if timeout is None:
            return
        now = time.monotonic()
        for key, info in list(self._sessions.items()):
            if info.active == 0 and now - info.idle_since > timeout:
                del self._sessions[key]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        agent_id = get_route_path(scope).removeprefix("/")
        # Authenticate first: whether an agent id is served is not revealed to anyone else.
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
        if agent_id not in (self.host.mcp_agents or ()):
            await _respond(scope, receive, send, 404, "not found")
            return
        manager = self._managers.get(agent_id)
        if manager is None or self._closing:
            await _respond(scope, receive, send, 503, "not started")
            return
        await self._serve(manager, agent_id, ident, scope, receive, send)

    async def _serve(
        self,
        manager: StreamableHTTPSessionManager,
        agent_id: str,
        ident: SidecarIdentity,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Hand the request to the session manager, which binds each session to the caller
        that opened it; keep track of the sessions (see ``_Session``)."""
        owner = _owner(ident, self.host)
        session_user = AuthenticatedUser(AccessToken(token="", client_id=owner, scopes=[]))
        sid = Headers(scope=scope).get("mcp-session-id")
        info = self._sessions.get((agent_id, sid)) if sid else None
        if info is not None and info.owner != owner:
            info = None  # the manager refuses it
        opened: list[_Session] = []

        async def watch(message: Message) -> None:
            if sid is None and message["type"] == "http.response.start":
                new = dict(message.get("headers", [])).get(b"mcp-session-id")
                if new is not None and message["status"] < 400:
                    self._prune(manager)
                    opened.append(_Session(owner, session_user, active=1))
                    self._sessions[(agent_id, new.decode("latin-1"))] = opened[0]
            await send(message)

        if info is not None:
            info.active += 1
        try:
            await manager.handle_request(
                {**scope, "user": session_user, IDENTITY_KEY: ident}, receive, watch
            )
        finally:
            for s in (info, *opened):
                if s is not None:
                    s.active -= 1
                    s.idle_since = time.monotonic()
            if sid is not None and info is not None and scope["method"] == "DELETE":
                self._sessions.pop((agent_id, sid), None)  # ended by its client


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
