"""AgentHost: one Starlette app serving N agents over A2A JSON-RPC and REST."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from a2a.server.context import ServerCallContext
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
    create_rest_routes,
)
from a2a.server.tasks import TaskStore
from a2a.types import AgentCard, SendMessageRequest
from a2a.utils.errors import InvalidParamsError
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials, AuthenticationError
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Mount, get_route_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from a2agw.consult.client import PartnerClient
from a2agw.consult.credentials import CredentialProvider
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import PartnerRegistry
from a2agw.ops.admin import ADMIN_PREFIX, HEALTH_PATH, admin_routes
from a2agw.ops.bus import EventBus
from a2agw.security.auth import (
    AuthConfig,
    GatewayAuthBackend,
    GatewayCallContextBuilder,
    PermissionDenied,
    authorize,
    on_auth_error,
)
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.agent import AgentSpec, build_card
from a2agw.serve.executor import AdapterExecutor
from a2agw.serve.store import (
    RecoveryReport,
    TaskIndex,
    create_engine,
    recover_on_startup,
    task_store_for,
)

CARD_PATH = "/.well-known/agent-card.json"
__all__ = ["ADMIN_PREFIX", "HEALTH_PATH", "AgentHost"]


class LimitedRequestHandler(DefaultRequestHandler):
    """DefaultRequestHandler that rejects messages with too many parts."""

    def __init__(self, *args: Any, max_parts: int, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._max_parts = max_parts

    def _check_parts(self, params: SendMessageRequest) -> None:
        if len(params.message.parts) > self._max_parts:
            raise InvalidParamsError(message="too many parts")

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):  # type: ignore[override]
        self._check_parts(params)
        return await super().on_message_send(params, context)

    async def on_message_send_stream(  # type: ignore[override]
        self, params: SendMessageRequest, context: ServerCallContext
    ) -> AsyncGenerator[Any, None]:
        self._check_parts(params)
        async for event in super().on_message_send_stream(params, context):
            yield event


class _BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        too_large = JSONResponse({"error": "payload too large"}, status_code=413)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await too_large(scope, receive, send)
                    return
            except ValueError:
                pass
        seen = 0
        responded = False
        rejected = False

        async def limited_receive() -> Message:
            nonlocal seen, rejected, responded
            if rejected:
                raise _TooLarge
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    # Downstream code may swallow exceptions, so answer right here.
                    rejected = True
                    if not responded:
                        responded = True
                        await too_large(scope, receive, send)
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal responded
            if rejected:
                return
            if message["type"] == "http.response.start":
                responded = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            pass


class _TooLarge(Exception):
    pass


# A2A 1.0 section 5.4: HTTP statuses for error reasons the SDK maps differently.
_REST_STATUS_BY_REASON = {
    "TASK_NOT_CANCELABLE": 409,
    "CONTENT_TYPE_NOT_SUPPORTED": 415,
    "INVALID_AGENT_RESPONSE": 502,
}
_A2A_JSON = b"application/a2a+json"
_MAX_ERROR_BODY = 64 * 1024


def _remapped_error(body: bytes) -> tuple[int, bytes] | None:
    """(status, body) for a REST error body whose reason maps to another status, else None."""
    try:
        payload = json.loads(body)
        error = payload["error"]
        reasons = [d.get("reason") for d in error.get("details", []) if isinstance(d, dict)]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    for reason in reasons:
        status = _REST_STATUS_BY_REASON.get(reason)
        if status is not None and error.get("code") != status:
            error["code"] = status
            return status, json.dumps(payload, separators=(",", ":")).encode()
    return None


class _RestConformance:
    """Aligns the SDK's HTTP+JSON responses with A2A 1.0.

    - Section 11.1: responses use ``Content-Type: application/json`` (the SDK labels them
      ``application/a2a+json``).
    - Section 5.4: ``TaskNotCancelableError`` is 409, ``ContentTypeNotSupportedError`` 415
      and ``InvalidAgentResponseError`` 502 (the SDK sends 400, 400 and 500). The error body's
      ``code`` field is updated to match.

    It wraps the agent's whole sub-app (card, JSON-RPC and REST routes), but only acts on
    responses labelled ``application/a2a+json`` (header rewrite) and on JSON error responses
    with status >= 400 and a body of at most 64 KiB (status remap). JSON-RPC errors travel
    with HTTP 200, so in practice only REST errors are remapped. The body's gRPC-style
    ``error.status`` string (e.g. ``FAILED_PRECONDITION``) is kept on purpose: section 5.4
    pairs these errors with exactly those gRPC statuses.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start: Message | None = None
        chunks: list[bytes] = []
        size = 0

        async def flush(status: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
            headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]
            headers.append((b"content-length", str(len(body)).encode()))
            await send({**start, "status": status, "headers": headers})  # type: ignore[dict-item]
            await send({"type": "http.response.body", "body": body})

        async def conforming_send(message: Message) -> None:
            nonlocal start, size
            if message["type"] == "http.response.start":
                headers = [
                    (k, b"application/json" + v[len(_A2A_JSON) :])
                    if k.lower() == b"content-type" and v.startswith(_A2A_JSON)
                    else (k, v)
                    for k, v in message.get("headers", [])
                ]
                message = {**message, "headers": headers}
                ctype = {k.lower(): v for k, v in headers}.get(b"content-type", b"")
                if message["status"] >= 400 and b"json" in ctype:
                    start = message  # hold it until the body is known
                    return
                await send(message)
                return
            if start is None or message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            size += len(chunks[-1])
            more = message.get("more_body", False)
            if size > _MAX_ERROR_BODY:  # too big to inspect: pass through unchanged
                held, start = start, None
                await send(held)
                for chunk in chunks:
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                chunks.clear()
                if not more:
                    await send({"type": "http.response.body", "body": b""})
                return
            if more:
                return
            body = b"".join(chunks)
            remapped = _remapped_error(body)
            status, body = remapped if remapped is not None else (start["status"], body)
            await flush(status, list(start["headers"]), body)
            start = None

        await self.app(scope, receive, conforming_send)


def _anonymous_user() -> PrincipalUser:
    return PrincipalUser(Principal(id="anonymous", kind="anonymous", scopes=frozenset()))


class _AnonymousMiddleware:
    """No auth configured: every caller is the anonymous principal (owner "anonymous")."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            scope["user"] = _anonymous_user()
            scope["auth"] = AuthCredentials()
        await self.app(scope, receive, send)


def _is_public(scope: Scope) -> bool:
    """Public paths (cards, health), matched on the route path so root_path cannot confuse it."""
    path = get_route_path(scope)
    if path == HEALTH_PATH:
        return True
    if scope["type"] != "http" or scope["method"] not in ("GET", "HEAD"):
        return False
    if path == CARD_PATH:
        return True
    parts = path.split("/")
    return (
        len(parts) == 5
        and parts[0] == ""
        and parts[1] == "agents"
        and parts[3:] == [".well-known", "agent-card.json"]
    )


class _AuthMiddleware:
    """Authenticates every non-public request and stores the principal in the scope."""

    def __init__(self, app: ASGIApp, config: AuthConfig) -> None:
        self.app = app
        self.backend = GatewayAuthBackend(config)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if _is_public(scope):
            scope["user"] = _anonymous_user()
            scope["auth"] = AuthCredentials()
            await self.app(scope, receive, send)
            return
        conn = HTTPConnection(scope)
        try:
            result = await self.backend.authenticate(conn)
        except AuthenticationError as exc:
            await on_auth_error(conn, exc)(scope, receive, send)  # type: ignore[arg-type,misc]
            return
        # The backend returns None only if no credential is accepted; treat that as anonymous.
        scope["auth"], scope["user"] = result or (AuthCredentials(), _anonymous_user())
        await self.app(scope, receive, send)


class _AgentAuthorizer:
    """Wraps one agent's sub-app: enforces that agent's AgentAccess on everything but its card.

    Bound to the agent at mount time, so no path parsing decides *which* agent is checked.
    """

    def __init__(self, app: ASGIApp, spec: AgentSpec, enforce: bool) -> None:
        self.app = app
        self.spec = spec
        self.enforce = enforce

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        is_card = scope["method"] in ("GET", "HEAD") and get_route_path(scope) == CARD_PATH
        if self.enforce and not is_card:
            user = scope.get("user")
            principal = user.principal if isinstance(user, PrincipalUser) else None
            try:
                authorize(principal, self.spec.access)
            except PermissionDenied:
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


async def _agent_not_found(scope: Scope, receive: Receive, send: Send) -> None:
    if scope["type"] == "http":
        await JSONResponse({"error": "not found"}, status_code=404)(scope, receive, send)


class AgentHost:
    def __init__(
        self,
        base_url: str,
        *,
        auth: AuthConfig | None = None,
        db_url: str = "sqlite+aiosqlite:///a2agw.db",
        max_body_bytes: int = 10 * 1024 * 1024,
        max_parts: int = 64,
        admin: bool = True,
        admin_without_auth: bool = False,
        partners_path: str | Path | None = None,
        credentials: CredentialProvider | None = None,
        partner_http: httpx.AsyncClient | None = None,
        default_deadline_s: float = 60.0,
        card_cache_control: str | None = "public, max-age=300",
    ) -> None:
        self.base_url = base_url
        # Cache-Control on every agent card response (A2A 1.0 section 8.6.1); None omits it.
        self.card_cache_control = card_cache_control
        self.auth = auth
        self.db_url = db_url
        self.max_body_bytes = max_body_bytes
        self.max_parts = max_parts
        self.admin = admin
        self.admin_without_auth = admin_without_auth  # dev only: open admin when auth is None
        self.bus = EventBus()
        self.specs: dict[str, AgentSpec] = {}
        self.executors: dict[str, AdapterExecutor] = {}
        self.handlers: dict[str, LimitedRequestHandler] = {}
        self.cards: dict[str, AgentCard] = {}
        self.extra_routes: list[BaseRoute] = []  # mounted before the agent routes (admin, ...)
        self.engine: AsyncEngine | None = None
        self.index: TaskIndex | None = None  # created at startup
        self.last_recovery: RecoveryReport | None = None
        # Outbound side. The registry exists from construction so operators can register
        # partners before startup; the handle store and client are created at startup.
        self.partners = PartnerRegistry(
            Path(partners_path) if partners_path is not None else None, http=partner_http
        )
        self.credentials = credentials
        self.partner_http = partner_http
        self.default_deadline_s = default_deadline_s
        self.handles: OutboundHandleStore | None = None
        self.client: PartnerClient | None = None
        self._inner: Starlette | None = None
        self._app_built = False
        self._app: Starlette | None = None

    def add(self, spec: AgentSpec) -> None:
        if spec.id in self.specs:
            raise ValueError(f"duplicate agent id: {spec.id}")
        if self._app_built or self._inner is not None:
            raise RuntimeError("cannot add agents after app() or startup()")
        self.specs[spec.id] = spec

    async def startup(self) -> None:
        engine = self.engine = await create_engine(self.db_url)
        index = self.index = TaskIndex(engine)
        await index.initialize()
        self.partners.load()
        handles = self.handles = OutboundHandleStore(engine)
        await handles.initialize()
        client = self.client = PartnerClient(
            self.partners,
            credentials=self.credentials,
            handles=handles,
            bus=self.bus,
            http=self.partner_http,
            default_deadline_s=self.default_deadline_s,
            agent_id="host",
        )
        stores: dict[str, TaskStore] = {}
        routes: list[BaseRoute] = []
        for agent_id, spec in self.specs.items():
            store = task_store_for(engine, agent_id)
            await store.initialize()
            stores[agent_id] = store
            executor = AdapterExecutor(spec, index, self.bus)
            # Cancelling an inbound task cancels the partner tasks it started.
            executor.on_cancel = client.cancel_for_inbound
            card = build_card(spec, self.base_url, security=self.auth)
            handler = LimitedRequestHandler(
                agent_executor=executor,
                task_store=store,
                agent_card=card,
                max_parts=self.max_parts,
            )
            self.executors[agent_id] = executor
            self.handlers[agent_id] = handler
            self.cards[agent_id] = card
            builder = GatewayCallContextBuilder()
            # Each agent gets its own sub-app: the SDK's REST routes include a catch-all
            # "/{tenant}" mount that would otherwise swallow every other agent's paths.
            sub_routes: list[BaseRoute] = [
                *create_agent_card_routes(card, cache_control=self.card_cache_control)
            ]
            sub_routes += create_jsonrpc_routes(
                handler, rpc_url="/", context_builder=builder, enable_v0_3_compat=True
            )
            sub_routes += create_rest_routes(
                handler, context_builder=builder, enable_v0_3_compat=True, path_prefix="/rest"
            )
            routes.append(
                Mount(
                    f"/agents/{agent_id}",
                    app=_AgentAuthorizer(
                        _RestConformance(Starlette(routes=sub_routes)),
                        spec,
                        enforce=self.auth is not None,
                    ),
                )
            )
        routes.append(Mount("/agents", app=_agent_not_found))
        if len(self.cards) == 1:
            routes += create_agent_card_routes(
                next(iter(self.cards.values())), cache_control=self.card_cache_control
            )
        self._inner = Starlette(routes=routes)
        self.last_recovery = await recover_on_startup(
            index,
            stores,
            durable={i: s.adapter.durable_sessions for i, s in self.specs.items()},
            handles=handles,
            cancel_outbound=self._cancel_outbound,
            cancel_timeout_s=self.default_deadline_s,
        )

    async def _cancel_outbound(self, handle: dict[str, Any]) -> None:
        """Recovery: cancel one partner task; raise unless the partner reports it canceled."""
        assert self.client is not None
        result = await self.client.cancel(handle["partner_id"], handle["task_id"])
        if result.state != "canceled":
            raise RuntimeError("not canceled")

    async def shutdown(self) -> None:
        for handler in self.handlers.values():
            await handler.aclose()
        if self.client is not None:
            await self.client.aclose()
        if self.engine is not None:
            await self.engine.dispose()
            self.engine = None

    async def _delegate(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._inner is None:
            await JSONResponse({"error": "not started"}, status_code=503)(scope, receive, send)
            return
        await self._inner(scope, receive, send)

    def app(self) -> Starlette:
        if self._app is not None:
            return self._app
        self._app_built = True

        @asynccontextmanager
        async def lifespan(_: Starlette) -> AsyncIterator[None]:
            await self.startup()
            try:
                yield
            finally:
                await self.shutdown()

        app = Starlette(
            routes=[
                *self.extra_routes,
                *(admin_routes(self) if self.admin else []),
                Mount("/", app=self._delegate),
            ],
            lifespan=lifespan,
        )
        # add_middleware prepends, so the last one added is outermost.
        if self.auth is not None:
            app.add_middleware(_AuthMiddleware, config=self.auth)
        else:
            app.add_middleware(_AnonymousMiddleware)
        app.add_middleware(_BodyLimitMiddleware, max_bytes=self.max_body_bytes)
        self._app = app
        return app

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import uvicorn

        uvicorn.run(self.app(), host=host, port=port)
