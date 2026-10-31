"""The control-plane HTTP service (FastAPI; needs the ``control`` extra).

``create_app(settings)`` returns the app. Its lifespan opens the database engine, initializes
the store and the control plane's own audit chain (``cp_audit``), and runs the maintenance
loop; on shutdown it stops the loop, drains the audit log, closes the HTTP client it owns and
disposes the engine.

Errors have one shape, ``{"error": "<code>", "detail": "<message>"}``. Validation errors are
422 with ``fields``: dotted paths of the offending inputs, never their values. Unexpected
exceptions are 500 ``internal`` with no message from the exception.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx

from a2agw.control import require_fastapi

require_fastapi()  # a one-line install hint instead of a bare ModuleNotFoundError

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.control.settings import ControlSettings
from a2agw.control.store import AUDIT_TABLE, ControlStore
from a2agw.ops.audit import AuditLog
from a2agw.serve.store import create_engine

log = logging.getLogger(__name__)

MAINTENANCE_INTERVAL_S = 60.0
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
    ``hooks`` (each awaited with ``now``). Task 6 adds the desired-state recomputation for
    dirty assignments as a hook. ``run_once`` is the pass; ``run_forever`` waits
    ``interval_s`` before each pass, logs a failed pass and keeps going."""

    def __init__(
        self,
        store: ControlStore,
        settings: ControlSettings,
        *,
        clock: Callable[[], float],
        interval_s: float,
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        self.interval_s = interval_s
        # TODO(Task 6): recompute desired state when assignments are dirty.
        self.hooks: list[MaintenanceHook] = []

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
        while True:
            await asyncio.sleep(self.interval_s)
            try:
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

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error in control-plane request: %s", type(exc).__name__)
        return error(500, "internal error", "internal")


def create_app(
    settings: ControlSettings,
    *,
    http: httpx.AsyncClient | None = None,
    clock: Callable[[], float] = time.time,
    maintenance_interval_s: float = MAINTENANCE_INTERVAL_S,
) -> FastAPI:
    """The control-plane app. ``http`` is the client for outbound calls (the OIDC provider,
    partner cards); when omitted the app owns a guarded client and closes it at shutdown.
    ``clock`` (epoch seconds) and ``maintenance_interval_s`` are test seams."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = await create_engine(settings.db_url)
        owned_http = None
        task: asyncio.Task[None] | None = None
        audit: AuditLog | None = None
        try:
            audit = AuditLog(engine, table_name=AUDIT_TABLE)
            store = ControlStore(engine, audit=audit, clock=clock)
            await store.initialize()
            await audit.initialize()
            if http is None:
                owned_http = guarded_async_client(fixed_tier("public"))
            maintenance = Maintenance(
                store, settings, clock=clock, interval_s=maintenance_interval_s
            )
            app.state.settings = settings
            app.state.engine = engine
            app.state.store = store
            app.state.audit = audit
            app.state.http = http if http is not None else owned_http
            app.state.clock = clock
            app.state.maintenance = maintenance
            task = asyncio.create_task(maintenance.run_forever(), name="a2agw:cp-maint")
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if audit is not None:
                await audit.drain()
            if owned_http is not None:
                await owned_http.aclose()
            await engine.dispose()

    app = FastAPI(
        title="a2agw control plane",
        version="1",
        # TODO(Task 5): serve the OpenAPI document behind the viewer permission.
        openapi_url=OPENAPI_URL,
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
        lifespan=lifespan,
    )
    _install_error_handlers(app)

    @app.get("/healthz", include_in_schema=True)
    async def healthz() -> dict[str, str]:
        """Liveness (public)."""
        return {"status": "ok"}

    return app
