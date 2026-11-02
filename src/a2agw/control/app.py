"""The control-plane HTTP service (FastAPI; needs the ``control`` extra).

``create_app(settings)`` returns the app. Its lifespan opens the database engine, initializes
the store and the control plane's own audit chain (``cp_audit``), and runs the maintenance
loop; on shutdown it stops the loop (a pass already running finishes: passes run through
``channel.Background``), ends open gateway streams, waits for their polls, drains the audit
log, closes the HTTP client it owns and disposes the engine. An exit signal ends the open
streams at once (``end_streams``), since the server waits for open responses before it runs
that shutdown. Request bodies are capped at ``BODY_MAX_BYTES`` (``BodyLimit``; not
``/cp/v1``), and JSON is answered ASCII-only (``a2agw.control.responses``).

Errors have one shape, ``{"error": "<code>", "detail": "<message>"}``. Validation errors are
422 with ``fields``: dotted paths of the offending inputs, never their values. Unexpected
exceptions are 500 ``internal`` with no message from the exception, answered by the
``InternalErrors`` middleware, which logs the exception class and the request id only.

Every route is registered through ``a2agw.control.rbac`` (``route``, ``public``,
``gateway_route``), which records the permission it needs.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from a2agw.control import require_fastapi

require_fastapi()  # a one-line install hint instead of a bare ModuleNotFoundError

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from a2agw.config import trust_card_verifier
from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.control import admin as _admin  # noqa: F401 - registers the gateway routes
from a2agw.control import (  # noqa: F401 - routes
    authn,
    catalogue,
    channel,
    operations,
    policies,
    views,
)
from a2agw.control.rbac import ROUTES, Permission, public, route
from a2agw.control.responses import JSONResponse
from a2agw.control.settings import ControlSettings
from a2agw.control.store import AUDIT_TABLE, ControlStore
from a2agw.ops.audit import AuditLog
from a2agw.serve.host import _on_exit_signal
from a2agw.serve.store import create_engine

log = logging.getLogger(__name__)

MAINTENANCE_INTERVAL_S = 60.0
# ``a2agw control serve``: how long uvicorn waits for open requests at shutdown before it
# cancels them and runs the lifespan cleanup (open gateway streams end at once on an exit
# signal, see ``end_streams``).
GRACEFUL_SHUTDOWN_S = 10.0
BODY_MAX_BYTES = 1024 * 1024  # every request body but /cp/v1's (``BodyLimit``)
GATEWAY_PREFIX = "/cp/v1/"  # the report keeps its own cap (``limits.report_max_bytes``)
OPENAPI_URL = "/api/openapi.json"

_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "too_large",
    415: "unsupported_media_type",
    422: "invalid",
    429: "too_many_requests",
    503: "unavailable",
}

MaintenanceHook = Callable[[float], Awaitable[Any]]


def error(status: int, detail: str, code: str | None = None) -> JSONResponse:
    """A response in the one error shape."""
    return JSONResponse(
        {"error": code or _CODES.get(status, "error"), "detail": detail}, status_code=status
    )


class Maintenance:
    """The periodic pass: expire commands, purge old events and commands, then run
    ``hooks`` (each awaited with ``now``); the first hook recomputes the desired state of
    gateways marked dirty (``channel.recompute_dirty``). ``run_once`` is the pass;
    ``run_forever`` waits ``interval_s`` before each pass, logs a failed pass and keeps
    going."""

    def __init__(
        self,
        store: ControlStore,
        settings: ControlSettings,
        *,
        clock: Callable[[], float],
        interval_s: float,
        background: channel.Background | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        self.interval_s = interval_s
        self.background = background
        self.stopping = False
        self.hooks: list[MaintenanceHook] = [self._recompute_desired]

    async def _recompute_desired(self, _now: float) -> int:
        return await channel.recompute_dirty(self.store)

    async def run_once(self) -> dict[str, int]:
        now = self.clock()
        expired = await self.store.expire_commands(now=now)
        purged = await self.store.purge(
            now=now,
            events_days=self.settings.retention.events_days,
            commands_days=self.settings.retention.commands_days,
        )
        for hook in list(self.hooks):
            await hook(now)
        return {"expired": expired, **purged}

    async def run_forever(self) -> None:
        """Until ``stopping``: wait, then one pass. A pass runs through ``background`` (when
        given): cancelling the loop at shutdown lands in the wait or at the pass's await, so
        a pass is never cut mid-database-call; the lifespan drains it before the engine
        goes."""
        while not self.stopping:
            await asyncio.sleep(self.interval_s)
            if self.stopping:
                return
            try:
                if self.background is not None:
                    await self.background.run(self.run_once())
                else:
                    await self.run_once()
            except Exception as exc:  # noqa: BLE001 - one failed pass must not stop the loop
                log.warning("control-plane maintenance failed: %s", type(exc).__name__)


def _fields(exc: RequestValidationError) -> list[str]:
    out: list[str] = []
    for err in exc.errors():
        path = ".".join(str(x) for x in err.get("loc", ()))
        if path and path not in out:
            out.append(path)
    return out


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            response = error(exc.status_code, str(detail.get("detail", "")), str(detail["error"]))
        else:
            response = error(exc.status_code, str(detail))
        for name, value in (exc.headers or {}).items():
            response.headers[name] = value
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            {"error": "invalid", "detail": "request validation failed", "fields": _fields(exc)},
            status_code=422,
        )


class InternalErrors:
    """Pure ASGI middleware answering unhandled exceptions with the 500 ``internal`` shape.

    Starlette's own handler for ``Exception`` (in ``ServerErrorMiddleware``) re-raises after
    responding, so the server would log the traceback and the exception's message, which
    can carry secrets or request content. This catches the exception first and logs one
    line: the exception class and a request id (sent as ``X-Request-ID`` on every
    response), never the message. Nothing is re-raised."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = secrets.token_hex(8)
        started = False

        async def send_with_id(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                MutableHeaders(scope=message).append("X-Request-ID", request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_with_id)
        except Exception as exc:  # noqa: BLE001 - every failure becomes one bare 500
            log.error(
                "unhandled error in control-plane request %s: %s", request_id, type(exc).__name__
            )
            if started:  # too late for a response; the server ends the connection
                return
            response = error(500, "internal error", "internal")
            response.headers["X-Request-ID"] = request_id
            await response(scope, receive, send)


class _TooLarge(Exception):
    pass


class BodyLimit:
    """Pure ASGI middleware: a request body larger than ``max_bytes`` is answered 413
    ``too_large`` before a route parses it, by its ``Content-Length`` or, without one
    (chunked), counted as it is read. ``/cp/v1`` is left alone: the report checks its own
    cap while it reads, and the stream has no body."""

    def __init__(self, app: ASGIApp, max_bytes: int = BODY_MAX_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path", "").startswith(GATEWAY_PREFIX):
            await self.app(scope, receive, send)
            return
        too_large = error(413, f"request body exceeds {self.max_bytes} bytes", "too_large")
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await too_large(scope, receive, send)
            return
        seen = 0
        started = refused = False

        async def counted() -> Message:
            nonlocal seen, refused
            if refused:
                raise _TooLarge
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    refused = True
                    if not started:  # answer here: the route may swallow the exception
                        await too_large(scope, receive, send)
                    raise _TooLarge
            return message

        async def tracked(message: Message) -> None:
            nonlocal started
            if refused:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted, tracked)
        except _TooLarge:
            pass


@public("GET", "/healthz")
async def healthz() -> dict[str, str]:
    """Liveness (public)."""
    return {"status": "ok"}


@route("GET", OPENAPI_URL, Permission.READ, include_in_schema=False)
async def openapi(request: Request) -> JSONResponse:
    """The OpenAPI document (needs the read permission)."""
    return JSONResponse(request.app.openapi())


def end_streams(app: FastAPI) -> None:
    """End the open gateway streams (each at its next poll, within ``channel.POLL_S``) and
    refuse new ones. A server waits for open responses before it runs the lifespan
    shutdown, and a gateway stream never ends by itself: the exit signals (SIGINT,
    SIGTERM) do this at once; an embedder stopping its server some other way (e.g.
    uvicorn's ``should_exit``) calls it first."""
    app.state.stopping.set()


def create_app(
    settings: ControlSettings,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Callable[[], float] = time.time,
    maintenance_interval_s: float = MAINTENANCE_INTERVAL_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    config_dir: Path | str = ".",
) -> FastAPI:
    """The control-plane app. ``http`` is the client for outbound calls (the OIDC provider,
    partner cards); when omitted the app owns two guarded clients (``http`` for the
    ``public`` tier and ``idp_http``, tier ``partner``, for the OIDC provider) and closes
    them at shutdown, and each partner card is fetched with a guarded client for the
    partner's tier. ``config_dir``: where the ``trust`` key files are (the directory of
    control.yaml); the card verifier is built here, so a bad key fails at once.
    ``clock`` (epoch seconds), ``maintenance_interval_s`` and ``sleep`` (the wait between
    two polls of a gateway stream) are test seams."""
    trust = settings.trust
    stopping = channel.Stopping()
    cards = catalogue.CardChecker(
        http=http,
        verifier=trust_card_verifier(trust, config_dir),
        require_signed=frozenset(trust.require_signed if trust else ()),
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stopping.clear()
        engine = await create_engine(settings.db_url)
        owned: list[httpx.AsyncClient] = []
        task: asyncio.Task[None] | None = None
        background: channel.Background | None = None
        maintenance: Maintenance | None = None
        audit: AuditLog | None = None
        try:
            audit = AuditLog(engine, table_name=AUDIT_TABLE)
            store = ControlStore(engine, audit=audit, clock=clock)
            await store.initialize()
            await audit.initialize()
            client, idp_client = http, http
            if http is None:
                client = guarded_async_client(fixed_tier("public"))
                owned.append(client)
                idp_client = guarded_async_client(fixed_tier(authn.IDP_TIER))
                owned.append(idp_client)
            background = app.state.background = channel.Background()
            maintenance = Maintenance(
                store,
                settings,
                clock=clock,
                interval_s=maintenance_interval_s,
                background=background,
            )
            app.state.settings = settings
            app.state.engine = engine
            app.state.store = store
            app.state.audit = audit
            app.state.http = client
            app.state.idp_http = idp_client
            app.state.oidc = (
                authn.OidcClient(settings.oidc, http=idp_client, clock=clock)
                if settings.oidc is not None
                else None
            )
            app.state.clock = clock
            app.state.sleep = sleep
            app.state.gateway_auth = channel.gateway_auth  # /cp/v1: gateway tokens only
            app.state.seen = channel.SeenWriter()  # last_seen_at, written at most every 5 s
            app.state.maintenance = maintenance
            app.state.cards = cards  # the partner catalogue's card fetch and checks
            app.state.task_details = views.DetailGate()  # task.get sharing and waiters
            app.state.operations = operations.OperateGate()  # operator actions' waiters
            task = asyncio.create_task(maintenance.run_forever(), name="a2agw:cp-maint")
            with _on_exit_signal(stopping.set):  # end the streams as soon as it is seen
                yield
        finally:
            stopping.set()
            if maintenance is not None:
                maintenance.stopping = True
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if background is not None:  # streams' last polls, before the engine goes
                await background.drain()
            if audit is not None:
                await audit.flush_coalesced()
                await audit.drain()
            for owned_client in owned:
                await owned_client.aclose()
            await engine.dispose()

    app = FastAPI(
        title="a2agw control plane",
        version="1",
        openapi_url=None,  # served by the ``openapi`` route, behind the read permission
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
        lifespan=lifespan,
        default_response_class=JSONResponse,  # ASCII JSON: any stored string can be answered
    )
    app.state.stopping = stopping  # end_streams(app): open gateway streams end
    _install_error_handlers(app)
    app.add_middleware(BodyLimit)
    app.add_middleware(InternalErrors)
    ROUTES.mount(app)
    return app
