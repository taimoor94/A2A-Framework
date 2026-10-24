"""AgentHost: one Starlette app serving N agents over A2A JSON-RPC and REST."""

from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

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
from starlette.routing import BaseRoute, Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send

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
HEALTH_PATH = "/a2agw/admin/healthz"


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
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes and not rejected:
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


def _card_path(path: str) -> bool:
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
        path = scope["path"]
        if path == HEALTH_PATH or _card_path(path):
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


class _AuthorizeMiddleware:
    """Maps /agents/{id}/... to an agent and enforces its AgentAccess."""

    def __init__(self, app: ASGIApp, specs: dict[str, AgentSpec], enforce: bool) -> None:
        self.app = app
        self.specs = specs
        self.enforce = enforce

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        if path.startswith("/agents/") and not _card_path(path):
            agent_id = path.split("/")[2]
            spec = self.specs.get(agent_id)
            if spec is None:
                await JSONResponse({"error": "not found"}, status_code=404)(scope, receive, send)
                return
            if self.enforce:
                user = scope.get("user")
                principal = user.principal if isinstance(user, PrincipalUser) else None
                try:
                    authorize(principal, spec.access)
                except PermissionDenied:
                    await JSONResponse({"error": "forbidden"}, status_code=403)(
                        scope, receive, send
                    )
                    return
        await self.app(scope, receive, send)


class AgentHost:
    def __init__(
        self,
        base_url: str,
        *,
        auth: AuthConfig | None = None,
        db_url: str = "sqlite+aiosqlite:///a2agw.db",
        max_body_bytes: int = 10 * 1024 * 1024,
        max_parts: int = 64,
    ) -> None:
        self.base_url = base_url
        self.auth = auth
        self.db_url = db_url
        self.max_body_bytes = max_body_bytes
        self.max_parts = max_parts
        self.bus = EventBus()
        self.specs: dict[str, AgentSpec] = {}
        self.executors: dict[str, AdapterExecutor] = {}
        self.handlers: dict[str, LimitedRequestHandler] = {}
        self.cards: dict[str, AgentCard] = {}
        self.extra_routes: list[BaseRoute] = []  # mounted before the agent routes (admin, ...)
        self.engine: AsyncEngine | None = None
        self.index: TaskIndex | None = None  # created at startup
        self.last_recovery: RecoveryReport | None = None
        self._inner: Starlette | None = None
        self._app_built = False

    def add(self, spec: AgentSpec) -> None:
        if self._app_built:
            raise RuntimeError("cannot add agents after app() has been called")
        if spec.id in self.specs:
            raise ValueError(f"duplicate agent id: {spec.id}")
        self.specs[spec.id] = spec

    async def startup(self) -> None:
        engine = self.engine = await create_engine(self.db_url)
        index = self.index = TaskIndex(engine)
        await index.initialize()
        stores: dict[str, TaskStore] = {}
        routes: list[BaseRoute] = []
        for agent_id, spec in self.specs.items():
            store = task_store_for(engine, agent_id)
            await store.initialize()
            stores[agent_id] = store
            executor = AdapterExecutor(spec, index, self.bus)
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
            sub_routes: list[BaseRoute] = [*create_agent_card_routes(card)]
            sub_routes += create_jsonrpc_routes(
                handler, rpc_url="/", context_builder=builder, enable_v0_3_compat=True
            )
            sub_routes += create_rest_routes(
                handler, context_builder=builder, enable_v0_3_compat=True, path_prefix="/rest"
            )
            routes.append(Mount(f"/agents/{agent_id}", app=Starlette(routes=sub_routes)))
        if len(self.cards) == 1:
            routes += create_agent_card_routes(next(iter(self.cards.values())))
        self._inner = Starlette(routes=routes)
        self.last_recovery = await recover_on_startup(
            index,
            stores,
            durable={i: s.adapter.durable_sessions for i, s in self.specs.items()},
            handles=None,
            cancel_outbound=None,
        )

    async def shutdown(self) -> None:
        for handler in self.handlers.values():
            await handler.aclose()
        if self.engine is not None:
            await self.engine.dispose()
            self.engine = None

    async def _delegate(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._inner is None:
            await JSONResponse({"error": "not started"}, status_code=503)(scope, receive, send)
            return
        await self._inner(scope, receive, send)

    def app(self) -> Starlette:
        self._app_built = True

        @asynccontextmanager
        async def lifespan(_: Starlette) -> AsyncIterator[None]:
            await self.startup()
            try:
                yield
            finally:
                await self.shutdown()

        app = Starlette(
            routes=[*self.extra_routes, Mount("/", app=self._delegate)], lifespan=lifespan
        )
        # add_middleware prepends, so the last one added is outermost.
        app.add_middleware(_AuthorizeMiddleware, specs=self.specs, enforce=self.auth is not None)
        if self.auth is not None:
            app.add_middleware(_AuthMiddleware, config=self.auth)
        else:
            app.add_middleware(_AnonymousMiddleware)
        app.add_middleware(_BodyLimitMiddleware, max_bytes=self.max_body_bytes)
        return app

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import uvicorn

        uvicorn.run(self.app(), host=host, port=port)
