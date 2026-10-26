"""AgentHost: one Starlette app serving N agents over A2A JSON-RPC and REST."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import ipaddress
import json
import logging
import os
import re
import signal
import threading
import time
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Iterable, Iterator, Mapping
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from a2a.compat.v0_3.jsonrpc_adapter import JSONRPC03Adapter
from a2a.server.context import ServerCallContext
from a2a.server.jsonrpc_models import JSONRPCError
from a2a.server.request_handlers import DefaultRequestHandler, RequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
    create_rest_routes,
)
from a2a.server.tasks import TaskStore
from a2a.types import (
    AgentCard,
    GetTaskRequest,
    SendMessageRequest,
    SubscribeToTaskRequest,
    Task,
    TaskState,
)
from a2a.types import Message as A2AMessage
from a2a.utils.errors import (
    JSON_RPC_ERROR_CODE_MAP,
    A2AError,
    ContentTypeNotSupportedError,
    InternalError,
    InvalidParamsError,
    InvalidRequestError,
    TaskNotFoundError,
    UnsupportedOperationError,
)
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message as ProtoMessage
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials, AuthenticationError
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Mount, get_route_path
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from a2agw._ddl import retry_ddl
from a2agw.adapters.stdio import StdioAdapter
from a2agw.adapters.webhook import WebhookAdapter
from a2agw.consult.client import MAX_CONSULTS_PER_TASK, PartnerClient
from a2agw.consult.credentials import CredentialProvider
from a2agw.consult.guarded_net import is_guarded_client
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.netguard import Tier, UnsafeURL
from a2agw.consult.registry import CardFetchError, PartnerRecord, PartnerRegistry
from a2agw.consult.tls import TlsClientConfig
from a2agw.consult.tools import PartnerTool, partner_tools
from a2agw.context.signing import CallContextSigner, CallContextVerifier
from a2agw.core.spi import LifecycleAdapter
from a2agw.gateway.auth import MCP_PREFIX
from a2agw.gateway.calls import SidecarCalls
from a2agw.gateway.rest import REST_PREFIX, rest_routes
from a2agw.gateway.tokens import ConsultTokens, GrantIssuer
from a2agw.ops.admin import ADMIN_PREFIX, HEALTH_PATH, admin_routes
from a2agw.ops.audit import AuditEvent, AuditLog, registry_audit_event
from a2agw.ops.bus import EventBus
from a2agw.security.auth import (
    AuthConfig,
    GatewayAuthBackend,
    GatewayCallContextBuilder,
    PermissionDenied,
    authorize,
    on_auth_error,
)
from a2agw.security.cardsign import CardSigner, CardVerifier
from a2agw.security.policy import PolicyEngine
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.agent import AgentSpec, build_card
from a2agw.serve.executor import AdapterExecutor
from a2agw.serve.limits import (
    DEFAULT_MAX_CONCURRENT_TASKS_PER_CALLER,
    CallerLimiter,
    CallerSlot,
    current_slot,
)
from a2agw.serve.push import (
    DRAIN_TIMEOUT_S,
    GatewayPushConfigStore,
    GuardedPushSender,
    PushSettings,
    make_push_url_validator,
    push_config_store_for,
    push_http_client,
)
from a2agw.serve.reap import (
    OUTBOUND_TTL_S,
    AgentServedError,
    ExpireReport,
    ReapResult,
    RecentActivityError,
    expire_outbound,
    make_cancel_outbound,
    reap_agent,
)
from a2agw.serve.store import (
    MessageKey,
    MessageLedger,
    RecoveryReport,
    TaskIndex,
    create_engine,
    recover_on_startup,
    task_store_for,
)

if TYPE_CHECKING:
    from a2agw.gateway.mcp_server import McpHttpApp

CARD_PATH = "/.well-known/agent-card.json"
logger = logging.getLogger(__name__)
_AGENT_ID = re.compile(r"^[A-Za-z0-9_-]+$")
REFRESH_MAX_PER_PASS = 20  # partner cards refreshed per maintenance pass
REFRESH_CONCURRENCY = 4
PARTNERS_LOCK_TIMEOUT_S = 0.25  # longest a save on the event loop waits for the file lock
_EARLY_AUDIT_MAX = 1000  # registry changes kept for the audit log until startup
_EXIT_SIGNALS = (signal.SIGINT, signal.SIGTERM)
# Default bound on uvicorn's wait for open requests at shutdown.
GRACEFUL_TIMEOUT_S = 10.0
DEFAULT_MAX_OPEN_SIDECAR_TASKS = 64


@contextmanager
def _on_exit_signal(callback: Callable[[], None]) -> Iterator[None]:
    """Run ``callback`` on the event loop when SIGINT/SIGTERM arrives, then hand the signal
    to whatever handler was installed before (uvicorn's, under ``uvicorn.run``).

    Uvicorn waits for open responses to finish *before* the lifespan shutdown runs, so
    endless streams (admin ``/events``) must be ended as soon as the signal is seen.
    Only possible in the main thread; elsewhere this does nothing.

    After the host stops, each signal's previous handler is restored, except a ``None``
    previous handler (one installed outside Python), which cannot be reinstalled: our handler
    stays and emulates it. SIGINT then still raises ``KeyboardInterrupt``, but SIGTERM is
    swallowed (it no longer terminates the process). Embedders in that situation should
    install their own SIGTERM handler after the host exits."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    loop = asyncio.get_running_loop()
    previous: dict[int, Any] = {sig: signal.getsignal(sig) for sig in _EXIT_SIGNALS}

    def handler(sig: int, frame: Any) -> None:
        try:
            loop.call_soon_threadsafe(callback)
        except RuntimeError:  # the loop is already closed: nothing left to end
            pass
        prev = previous[sig]
        if prev == signal.SIG_IGN:
            return  # ignored before: stay ignored, whatever the signal
        if prev is None:
            # Installed outside Python: SIGINT still raises KeyboardInterrupt, the others
            # only end the streams.
            if sig == signal.SIGINT:
                signal.default_int_handler(sig, frame)
            return
        if prev == signal.SIG_DFL:
            if sig == signal.SIGINT:
                signal.default_int_handler(sig, frame)  # KeyboardInterrupt
            else:  # the default action: terminate by this signal
                signal.signal(sig, signal.SIG_DFL)
                signal.raise_signal(sig)
            return
        if callable(prev):
            prev(sig, frame)

    for sig in _EXIT_SIGNALS:
        signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, prev in previous.items():
            # None (installed outside Python) cannot be reinstalled from Python: ours stays,
            # and it emulates that default (its loop callback is then a no-op).
            if prev is not None and signal.getsignal(sig) is handler:
                signal.signal(sig, prev)


_PROXY_VARS = frozenset({"http_proxy", "https_proxy", "all_proxy"})


def _warn_env_proxies() -> None:
    """One WARNING when proxy env vars are set: guarded outbound clients connect directly
    (a proxy would resolve names itself, defeating the address checks). Names only: proxy
    URLs can carry credentials."""
    names = sorted(k for k, v in os.environ.items() if k.lower() in _PROXY_VARS and v.strip())
    if names:
        logger.warning(
            "%s set: guarded outbound clients (partners, cards, JWKS, OAuth, push) ignore "
            "environment proxies and connect directly",
            "/".join(names),
        )


def _loopback(bind: str) -> bool:
    """Whether a bind address only accepts connections from this machine."""
    if bind == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind.strip("[]")).is_loopback
    except ValueError:
        return False


__all__ = [
    "ADMIN_PREFIX",
    "HEALTH_PATH",
    "AgentHost",
    "AgentServedError",
    "PartnersInUse",
    "RecentActivityError",
]


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _reject_nul(arg: Any) -> None:
    """NUL cannot be stored by PostgreSQL text/JSON columns: refuse it at the boundary."""
    if isinstance(arg, str):
        found = "\x00" in arg
    elif isinstance(arg, ProtoMessage):
        found = any("\x00" in s for s in _strings(MessageToDict(arg)))
    else:
        found = False
    if found:
        raise InvalidParamsError(message="invalid characters")


def _guard_handler_method(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a request handler method: NUL-free params, and no exception detail (SQL, bound
    parameters, message text) leaves the gateway. Non-A2A exceptions become a generic
    InternalError; the class name is logged."""

    def internal(exc: Exception) -> InternalError:
        logger.error("request failed: %s", type(exc).__name__)
        return InternalError(message="internal error")

    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            for arg in (*args, *kwargs.values()):
                _reject_nul(arg)
            result = fn(self, *args, **kwargs)
        except A2AError:
            raise
        except Exception as exc:  # noqa: BLE001 - nothing but A2A errors may reach callers
            raise internal(exc) from None
        if inspect.isasyncgen(result):

            async def stream() -> AsyncGenerator[Any, None]:
                try:
                    async for item in result:
                        yield item
                except A2AError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    raise internal(exc) from None

            return stream()

        async def call() -> Any:
            try:
                return await result
            except A2AError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise internal(exc) from None

        return call()

    wrapper.__name__ = getattr(fn, "__name__", "handler")
    return wrapper


def part_media_type(part: Any) -> str:
    """The media type a part is checked as (spec 8.8): its declared ``media_type``, else
    text/plain for text, application/json for data and application/octet-stream for a file."""
    if part.media_type:
        return str(part.media_type)
    kind = part.WhichOneof("content")
    if kind == "text":
        return "text/plain"
    if kind == "data":
        return "application/json"
    return "application/octet-stream"


def _bare(media_type: str) -> str:
    return media_type.split(";", 1)[0].strip().lower()


_MEDIA_TYPE = re.compile(r"[^\s/;*]+/[^\s/;*]+")


def media_type_accepted(media_type: str, modes: list[str] | None) -> bool:
    """True when ``media_type`` matches one of ``modes`` (``*/*`` and ``type/*`` wildcards;
    parameters and case ignored). ``None`` accepts everything well formed. A malformed type
    (not exactly ``type/subtype``, e.g. ``text`` or ``a/b/c``) is never accepted, so it
    cannot slip through a ``type/*`` wildcard."""
    mt = _bare(media_type)
    if not _MEDIA_TYPE.fullmatch(mt):
        return False
    if modes is None:
        return True
    major = mt.split("/", 1)[0]
    for mode in modes:
        m = _bare(mode)
        if m in ("*/*", "*", mt) or (m.endswith("/*") and m[:-2] == major):
            return True
    return False


def accepted_input_modes(spec: AgentSpec) -> list[str] | None:
    """The media types the agent takes: every skill's ``input_modes`` (a skill without its
    own falls back to the agent's ``input_modes``). A message names no skill, so this is the
    union. An empty list anywhere means "accept all" (None)."""
    out: list[str] = []
    lists = [s.input_modes if s.input_modes is not None else spec.input_modes for s in spec.skills]
    for modes in lists or [spec.input_modes]:
        if not modes:
            return None
        out.extend(m for m in modes if m not in out)
    return out


_TERMINAL_TASK_STATES = {
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_REJECTED,
}


_INTERRUPTED_TASK_STATES = {
    TaskState.TASK_STATE_INPUT_REQUIRED,
    TaskState.TASK_STATE_AUTH_REQUIRED,
}


def _owner_of(context: ServerCallContext) -> str:
    user = context.user if context is not None else None
    if isinstance(user, PrincipalUser):
        return user.principal.id
    return "anonymous"


DUPLICATE_WAIT_S = 10.0  # how long a duplicate waits for the first send's task id


def _fingerprint(params: SendMessageRequest) -> str:
    return hashlib.sha256(params.SerializeToString(deterministic=True)).hexdigest()


class LimitedRequestHandler(DefaultRequestHandler):
    """DefaultRequestHandler with the gateway's input checks and inbound idempotency.

    - Too many parts, a part with no content (empty, or only fields the parser does not know
      and dropped), or a part whose media type the agent does not take
      (``accepted_input_modes``) is ``InvalidParamsError`` before anything runs.
    - Spec 8.5, with a ``ledger``: a request re-sent unchanged (same messageId, same
      content and configuration) by the same owner in the same tenant (within the ledger's
      retention) while the task it created is
      still open (submitted, working, input- or auth-required) does not run the agent again:
      ``SendMessage`` answers with that task and ``SendStreamingMessage`` resubscribes to it.
      Once that task is terminal the id is free again: A2A makes send idempotency optional
      ("MAY") and the A2A TCK re-uses message ids across tasks, expecting a new task each
      time; for the same reason a *different* request under a known id is a new message.
      A send answered with a bare Message (direct reply) is forgotten too.
    """

    def __init__(
        self,
        *args: Any,
        max_parts: int,
        input_modes: list[str] | None = None,
        ledger: MessageLedger | None = None,
        agent_id: str = "",
        caller_limiter: CallerLimiter | None = None,
        audit: AuditLog | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._max_parts = max_parts
        self._input_modes = input_modes
        self._ledger = ledger
        self._agent_id = agent_id
        self._limiter = caller_limiter
        self._audit = audit
        # Each send being set up, by id() of its params: its ledger key and its request
        # fingerprint, taken before the SDK fills in ids (read by ``_setup_active_task``).
        self._pending: dict[int, tuple[MessageKey, str]] = {}

    def _check_parts(self, params: SendMessageRequest) -> None:
        if len(params.message.parts) > self._max_parts:
            raise InvalidParamsError(message="too many parts")
        if any(p.WhichOneof("content") is None for p in params.message.parts):
            raise InvalidParamsError(message="unsupported part")
        for p in params.message.parts:
            mt = part_media_type(p)
            if not media_type_accepted(mt, self._input_modes):
                shown = _bare(mt)[:100]
                # A2A's error for this (TCK CORE-SEND-003): -32005, HTTP 415 on REST.
                raise ContentTypeNotSupportedError(message=f"media type {shown} is not accepted")

    def _key(self, params: SendMessageRequest, context: ServerCallContext) -> MessageKey | None:
        mid = params.message.message_id
        if self._ledger is None or not mid:
            return None
        tenant = params.tenant or str(getattr(context, "tenant", "") or "")
        return MessageKey(self._agent_id, tenant, _owner_of(context), mid)

    async def _resolve(
        self, key: MessageKey, fingerprint: str, context: ServerCallContext
    ) -> Task | None:
        """None when this send now owns ``key`` and must run; else the task to answer with.

        Only an identical request (same fingerprint) is a duplicate. A duplicate of an open
        task gets that task. A duplicate of an ended (or vanished) task takes the key over
        with a compare-and-set: one of several concurrent re-sends wins and runs, the rest
        wait for the winner's task and get it, whatever its state by then."""
        assert self._ledger is not None
        loop = asyncio.get_running_loop()
        until = loop.time() + DUPLICATE_WAIT_S
        saw_other = False  # another send held the key while we waited: share its task
        while True:
            row = await self._ledger.reserve(key, fingerprint=fingerprint)
            if row is None:
                return None
            task_id = row["task_id"]
            if task_id is not None:
                task = await self._existing(str(task_id), context, key)
                if task is not None and (
                    saw_other or task.status.state not in _TERMINAL_TASK_STATES
                ):
                    return task
                if await self._ledger.supersede(key, str(task_id), row["fingerprint"]):
                    return None
            saw_other = True
            if loop.time() >= until:  # the first send is still setting up: refuse, not rerun
                raise InvalidParamsError(message="duplicate message is still being processed")
            await asyncio.sleep(0.05)

    async def _setup_active_task(self, params: SendMessageRequest, call_context: Any) -> Any:
        active, request_context = await super()._setup_active_task(params, call_context)
        pending = self._pending.get(id(params))
        if pending is not None and self._ledger is not None and request_context.task_id:
            key, fingerprint = pending
            await self._ledger.fill(key, request_context.task_id, fingerprint=fingerprint)
        return active, request_context

    async def _existing(
        self, task_id: str, context: ServerCallContext, key: MessageKey | None = None
    ) -> Task | None:
        """The first send's task. With ``key``, wait (up to ``DUPLICATE_WAIT_S``) for a task
        that is still being stored, unless the first send gave up its key (a direct reply)."""
        loop = asyncio.get_running_loop()
        until = loop.time() + DUPLICATE_WAIT_S
        while True:
            try:
                return await self.on_get_task(GetTaskRequest(id=task_id), context)
            except TaskNotFoundError:
                if key is None or self._ledger is None or loop.time() >= until:
                    return None
                row = await self._ledger.get(key)
                if row is None or row["task_id"] != task_id:
                    return None
            await asyncio.sleep(0.05)

    async def _reserve(self, context: ServerCallContext) -> CallerSlot | None:
        """The caller's concurrency slot for a send that will run the agent (spec 7.2):
        ``InvalidRequestError`` (JSON-RPC -32600, HTTP 400) and a ``limit.exceeded`` audit
        row when the principal already has ``max_concurrent_tasks_per_caller`` running."""
        if self._limiter is None:
            return None
        owner = _owner_of(context)
        slot = self._limiter.reserve(owner)
        if slot is not None:
            return slot
        if self._audit is not None:
            ev = AuditEvent(
                actor=owner,
                action="limit.exceeded",
                agent_id=self._agent_id,
                outcome="rejected",
                detail={
                    "limit": "max_concurrent_tasks_per_caller",
                    "count": self._limiter.max_per_caller,
                },
            )
            if owner == "anonymous":
                await self._audit.emit_coalesced(ev, f"limit:{self._agent_id}")
            else:
                await self._audit.emit(ev)
        raise InvalidRequestError(message="too many concurrent tasks for this caller")

    @asynccontextmanager
    async def _slot(self, context: ServerCallContext) -> AsyncIterator[None]:
        """Hold the caller's slot for the agent turn this send starts; the executor adopts
        it (see ``a2agw.serve.limits``). Always sets the context variable, so a turn started
        from inside another turn never adopts the outer turn's slot."""
        slot = await self._reserve(context)
        token = current_slot.set(slot)
        try:
            yield
        finally:
            try:
                current_slot.reset(token)
            except ValueError:  # a stream resumed in another context than it started in
                current_slot.set(None)
            if slot is not None and not slot.adopted:
                slot.release()

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):  # type: ignore[override]
        self._check_parts(params)
        key = self._key(params, context)
        if key is None:
            async with self._slot(context):
                return await super().on_message_send(params, context)
        fingerprint = _fingerprint(params)
        task = await self._resolve(key, fingerprint, context)
        if task is not None:
            return task
        self._pending[id(params)] = (key, fingerprint)
        try:
            async with self._slot(context):
                result = await super().on_message_send(params, context)
        except BaseException:
            await self._ledger.release(key, fingerprint=fingerprint)  # type: ignore[union-attr]
            raise
        finally:
            self._pending.pop(id(params), None)
        if not isinstance(result, Task):  # a bare Message: no task to return to a re-send
            await self._ledger.release(  # type: ignore[union-attr]
                key, only_unfilled=False, fingerprint=fingerprint
            )
        return result

    async def on_message_send_stream(  # type: ignore[override]
        self, params: SendMessageRequest, context: ServerCallContext
    ) -> AsyncGenerator[Any, None]:
        self._check_parts(params)
        key = self._key(params, context)
        if key is None:
            async with self._slot(context):
                async for event in super().on_message_send_stream(params, context):
                    yield event
            return
        fingerprint = _fingerprint(params)
        task = await self._resolve(key, fingerprint, context)
        if task is not None:
            if task.status.state in _TERMINAL_TASK_STATES | _INTERRUPTED_TASK_STATES:
                # Nothing more will happen until the caller acts: the snapshot is the answer
                # (subscribing to an input-required task would wait for the next turn).
                yield task
                return
            try:
                async for event in self.on_subscribe_to_task(
                    SubscribeToTaskRequest(id=task.id), context
                ):
                    yield event
            except UnsupportedOperationError:  # it ended meanwhile
                final = await self._existing(task.id, context)
                if final is not None:
                    yield final
            return
        self._pending[id(params)] = (key, fingerprint)
        task_seen = False
        try:
            async with self._slot(context):
                async for event in super().on_message_send_stream(params, context):
                    if isinstance(event, A2AMessage) and not task_seen:
                        await self._ledger.release(  # type: ignore[union-attr]
                            key, only_unfilled=False, fingerprint=fingerprint
                        )
                    else:
                        task_seen = True
                    yield event
        except BaseException:
            if not task_seen:
                await self._ledger.release(key, fingerprint=fingerprint)  # type: ignore[union-attr]
            raise
        finally:
            self._pending.pop(id(params), None)


for _method in dir(RequestHandler):
    if _method.startswith("on_") and callable(getattr(LimitedRequestHandler, _method, None)):
        setattr(
            LimitedRequestHandler,
            _method,
            _guard_handler_method(getattr(LimitedRequestHandler, _method)),
        )


class _Compat03Adapter(JSONRPC03Adapter):
    """The SDK's 0.3 JSON-RPC adapter, but an A2A error raised by the handler keeps its
    JSON-RPC code (the SDK turns every one into -32603 internal error on 0.3 requests)."""

    async def _process_non_streaming_request(  # type: ignore[override]
        self, request_id: Any, request_obj: Any, context: ServerCallContext
    ) -> Any:
        try:
            return await super()._process_non_streaming_request(request_id, request_obj, context)
        except A2AError as exc:
            code = JSON_RPC_ERROR_CODE_MAP.get(type(exc))
            if code is None:
                raise
            message = getattr(exc, "message", None) or str(exc)
            return self._generate_error_response(
                request_id, JSONRPCError(code=code, message=message)
            )


def _with_v03_error_codes(routes: list[BaseRoute], handler: Any) -> list[BaseRoute]:
    """Swap the dispatcher's 0.3 adapter for ``_Compat03Adapter``. Fails loudly if the SDK's
    layout changes, rather than silently keeping the -32603 mapping."""
    for route in routes:
        dispatcher = getattr(getattr(route, "endpoint", None), "__self__", None)
        old = getattr(dispatcher, "_v03_adapter", None)
        if not isinstance(old, JSONRPC03Adapter):
            raise RuntimeError(  # noqa: TRY004 - an SDK layout change, not a caller error
                "unsupported a2a-sdk version: no v0.3 JSON-RPC adapter found"
            )
        dispatcher._v03_adapter = _Compat03Adapter(  # type: ignore[union-attr]
            http_handler=handler,
            context_builder=dispatcher._context_builder,  # type: ignore[union-attr]
            shutdown_grace_period=dispatcher._shutdown_grace_period,  # type: ignore[union-attr]
        )
    return routes


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


class PartnersInUse(Exception):
    """A partner reload would remove partners that still have open outbound tasks."""

    def __init__(self, open_handles: int) -> None:
        super().__init__(f"{open_handles} open outbound task(s)")
        self.open_handles = open_handles


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


def _is_sidecar(scope: Scope) -> bool:
    """The outbound REST API and MCP server: they accept a consult token instead of the
    gateway's auth, so they decide who is calling (``a2agw.gateway.auth``)."""
    path = get_route_path(scope)
    return any(path == p or path.startswith(p + "/") for p in (REST_PREFIX, MCP_PREFIX))


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
            if _is_sidecar(scope):
                # A consult token is no gateway credential: the sidecar routes check it, and
                # refuse everything else with 401 themselves.
                result = None
            else:
                await on_auth_error(conn, exc)(scope, receive, send)  # type: ignore[arg-type,misc]
                return
        # The backend returns None only if no credential is accepted; treat that as anonymous.
        scope["auth"], scope["user"] = result or (AuthCredentials(), _anonymous_user())
        await self.app(scope, receive, send)


class _AgentAuthorizer:
    """Wraps one agent's sub-app: enforces that agent's AgentAccess (when auth is configured)
    and then the policy's authz rules (whenever a policy is set) on everything but its card.
    Both must allow. A denial is a bare 403 ``{"error": "forbidden"}``; the reason is only
    audited (``authz.deny``).

    Bound to the agent at mount time, so no path parsing decides *which* agent is checked.
    """

    def __init__(
        self,
        app: ASGIApp,
        spec: AgentSpec,
        enforce: bool,
        *,
        policy: PolicyEngine | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.app = app
        self.spec = spec
        self.enforce = enforce
        self.policy = policy
        self.audit = audit

    async def _deny(
        self, scope: Scope, receive: Receive, send: Send, principal: Principal | None, **detail: Any
    ) -> None:
        if self.audit is not None:
            ev = AuditEvent(
                actor=principal.id if principal is not None else "anonymous",
                action="authz.deny",
                agent_id=self.spec.id,
                outcome="forbidden",
                detail={
                    "principal_kind": principal.kind if principal is not None else "anonymous",
                    **detail,
                },
            )
            if principal is None or principal.kind == "anonymous":
                # Unauthenticated callers cannot flood the log: one row per agent per window.
                await self.audit.emit_coalesced(ev, f"agent:{self.spec.id}")
            else:
                await self.audit.emit(ev)
        await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        is_card = scope["method"] in ("GET", "HEAD") and get_route_path(scope) == CARD_PATH
        if not is_card and (self.enforce or self.policy is not None):
            user = scope.get("user")
            principal = user.principal if isinstance(user, PrincipalUser) else None
            if self.enforce:
                try:
                    authorize(principal, self.spec.access)
                except PermissionDenied as exc:
                    await self._deny(scope, receive, send, principal, reason=f"agent access: {exc}")
                    return
            if self.policy is not None:
                decision = self.policy.authorize(principal, self.spec.id, None)
                if not decision.allowed:
                    await self._deny(
                        scope, receive, send, principal, reason=decision.reason, rule=decision.rule
                    )
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
        card_signer: CardSigner | None = None,
        policy: PolicyEngine | None = None,
        audit: bool = True,
        push: PushSettings | None = None,
        context_signer: CallContextSigner | None = None,
        context_verifier: CallContextVerifier | None = None,
        outbound_ttl_s: float = OUTBOUND_TTL_S,
        maintenance_interval_s: float = 300.0,
        card_verifier: CardVerifier | None = None,
        require_signed: Iterable[Tier] = (),
        tls: Mapping[str, TlsClientConfig] | None = None,
        max_concurrent_tasks_per_caller: int = DEFAULT_MAX_CONCURRENT_TASKS_PER_CALLER,
        max_consults_per_task: int = MAX_CONSULTS_PER_TASK,
        sidecar_clients: Mapping[str, Iterable[str]] | None = None,
        sidecar_agents: Iterable[str] = (),
        max_open_sidecar_tasks_per_caller: int = DEFAULT_MAX_OPEN_SIDECAR_TASKS,
        mcp_agents: Iterable[str] | None = None,
    ) -> None:
        self.base_url = base_url
        # Sidecar agents (spec 7.7) consult partners through the outbound REST API
        # (``/a2agw/v1``): with a consult token issued for one turn of a webhook or stdio agent
        # (``consult_tokens``; ``consult_issuer`` is the adapters' ``consult`` callable), or,
        # standalone, as a principal with the ``a2agw:sidecar`` scope acting as one of the
        # agent ids ``sidecar_clients`` maps it to ({principal id: agent ids}).
        # ``sidecar_agents`` names further sidecar identities (MCP clients), whose unlinked
        # partner tasks this host's TTL expiry also covers (``sidecar_agent_ids``).
        self.consult_tokens = ConsultTokens(url=f"{base_url.rstrip('/')}{REST_PREFIX}")
        self.consult_issuer = GrantIssuer(self.consult_tokens)
        self.sidecar_clients: dict[str, frozenset[str]] = {
            principal: frozenset(agents) for principal, agents in (sidecar_clients or {}).items()
        }
        # The outbound MCP server (``a2agw.gateway.mcp_server``, imported only when this is
        # set): the agent ids whose partner tools are served at ``/a2agw/mcp/{agent_id}``.
        # None: no MCP server. These ids are sidecar agents too.
        self.mcp_agents = frozenset(mcp_agents) if mcp_agents is not None else None
        self._mcp: McpHttpApp | None = None
        self.sidecar_agents = frozenset(sidecar_agents) | (self.mcp_agents or frozenset())
        # A standalone sidecar principal's open partner tasks with no inbound task, per agent
        # id it acts as (over it a new consult is ``unavailable``, audited
        # ``limit.exceeded``); linked calls are bounded by ``max_consults_per_task``.
        if max_open_sidecar_tasks_per_caller < 1:
            raise ValueError("max_open_sidecar_tasks_per_caller must be at least 1")
        self.max_open_sidecar_tasks_per_caller = max_open_sidecar_tasks_per_caller
        # The partner-tool call path of the REST API and the MCP server (one per host: the
        # open-task cap counts the consults in flight through either).
        self.sidecar_calls = SidecarCalls(self)
        # Adapters given this host's ``consult_issuer`` at startup (reset at shutdown).
        self._issued_adapters: list[WebhookAdapter | StdioAdapter] = []
        # Spec 7.2 / 11a.4 per-caller caps: agent turns running at once per principal
        # (across all agents; over it a send is InvalidRequestError, audited
        # ``limit.exceeded``) and new partner tasks per inbound task (over it a consult is
        # ``unavailable``).
        self.caller_limiter = CallerLimiter(max_concurrent_tasks_per_caller)
        if max_consults_per_task < 1:
            raise ValueError("max_consults_per_task must be at least 1")
        self.max_consults_per_task = max_consults_per_task
        # Spec 8.2: outbound partner tasks still open after this long are cancelled by the
        # maintenance loop (every ``maintenance_interval_s``), which also forgets inbound
        # message ids past their retention (spec 8.5). See ``maintain``.
        if outbound_ttl_s <= 0 or maintenance_interval_s <= 0:
            raise ValueError("outbound_ttl_s and maintenance_interval_s must be positive")
        self.outbound_ttl_s = outbound_ttl_s
        self.maintenance_interval_s = maintenance_interval_s
        self.ledger: MessageLedger | None = None  # created at startup
        self._maintenance: asyncio.Task[None] | None = None
        # Adapters with a lifecycle (``LifecycleAdapter``) started at startup, in order.
        self._started_adapters: list[tuple[str, LifecycleAdapter]] = []
        # Signed call contexts between gateways (a2agw.context.signing): the signer signs the
        # call context of every outbound consult; the verifier lets agents trust a signed one.
        # With both set, the host trusts its own key: a token it signed and a partner forwarded
        # back must verify for the loop to show as a cycle. ValueError on a kid conflict.
        if context_signer is not None and context_verifier is not None:
            context_verifier = context_verifier.with_trusted(
                context_signer.kid, context_signer.issuer, context_signer.public_jwk()
            )
        self.context_signer = context_signer
        self.context_verifier = context_verifier
        # Push notifications (A2A webhooks). None: not offered, and the card says so.
        self.push = push
        self.push_http: httpx.AsyncClient | None = None  # created at startup when push is set
        self.push_senders: dict[str, GuardedPushSender] = {}
        self.push_stores: dict[str, GatewayPushConfigStore] = {}
        # Authz (authorizer and executor), egress (partner client) and routing (tools).
        self.policy = policy
        # audit=False disables the audit log entirely (no table, no events).
        self.audit_enabled = audit
        self.audit: AuditLog | None = None  # created at startup
        # Signs every card built at startup (per-agent and the single-agent root card).
        self.card_signer = card_signer
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
        # Partner card signatures (``card_verifier``, ``require_signed`` tiers) and per-partner
        # mTLS client configs (``tls``, by ``tls_ref``): one mapping, shared by the registry
        # (card fetches) and the partner client (calls).
        self.tls: dict[str, TlsClientConfig] = dict(tls or {})
        self.partners = PartnerRegistry(
            Path(partners_path) if partners_path is not None else None,
            http=partner_http,
            verifier=card_verifier,
            require_signed=frozenset(require_signed),
            tls=self.tls,
            # Saves run on the event loop: never wait long for another process's lock on
            # the partners file; keep the change unsaved instead (``maintain`` retries it).
            lock_timeout_s=PARTNERS_LOCK_TIMEOUT_S,
            defer_busy_saves=True,
        )
        self.credentials = credentials
        # Injected for tests: used as given, bypassing the guarded outbound clients.
        self.partner_http = partner_http
        if partner_http is not None and not is_guarded_client(partner_http):
            logger.warning(
                "AgentHost(partner_http=...) is not a guarded client: partner calls and card "
                "fetches bypass the connect-time address checks (use guarded_async_client)"
            )
        self.default_deadline_s = default_deadline_s
        self.handles: OutboundHandleStore | None = None
        self.client: PartnerClient | None = None
        self._inner: Starlette | None = None
        # Registry changes are audited from construction on: changes made before startup
        # (``register_partners`` on the ``a2agw serve`` path) are kept here and written once
        # the audit log exists.
        self._early_audit: list[AuditEvent] = []
        if audit:
            self.partners.add_listener(self._audit_registry_change)
        self._app_built = False
        self._app: Starlette | None = None

    def add(self, spec: AgentSpec) -> None:
        if spec.id in self.specs:
            raise ValueError(f"duplicate agent id: {spec.id}")
        if self._app_built or self._inner is not None:
            raise RuntimeError("cannot add agents after app() or startup()")
        self.specs[spec.id] = spec

    async def startup(self) -> None:
        """Open the engine, load partners, build the agents and run restart recovery.

        If any step fails (e.g. an unreadable partners file), whatever was opened so far is
        closed again before the error propagates."""
        try:
            await self._startup()
        except BaseException:
            if self._mcp is not None:
                await self._mcp.stop()
            await self._stop_adapters()
            if self.audit is not None:
                # Registry changes submitted during startup are written before the engine
                # goes (and never left running against a disposed engine).
                await self.audit.drain()
            if self.push_http is not None:
                await self.push_http.aclose()
                self.push_http = None
            if self.client is not None:
                await self.client.aclose()
                self.client = None
            if self.engine is not None:
                await self.engine.dispose()
                self.engine = None
            raise

    async def _startup(self) -> None:
        _warn_env_proxies()
        push = self.push
        push_fernet = push.fernet() if push is not None else None  # fail before opening
        self.bus.reopen()
        engine = self.engine = await create_engine(self.db_url)
        index = self.index = TaskIndex(engine)
        await index.initialize()
        ledger = self.ledger = MessageLedger(engine)
        await ledger.initialize()
        audit: AuditLog | None = None
        if self.audit_enabled:
            audit = self.audit = AuditLog(engine)
            await audit.initialize()
            early, self._early_audit = self._early_audit, []
            for ev in early:
                await audit.emit(ev)
        self.partners.load()
        self._warn_unknown_routing_partners()
        handles = self.handles = OutboundHandleStore(engine)
        await handles.initialize()
        self.client = PartnerClient(
            self.partners,
            credentials=self.credentials,
            handles=handles,
            bus=self.bus,
            http=self.partner_http,
            default_deadline_s=self.default_deadline_s,
            agent_id="host",
            tls=self.tls,
            policy=self.policy,
            audit=audit,
            context_signer=self.context_signer,
            max_consults_per_task=self.max_consults_per_task,
        )
        stores: dict[str, TaskStore] = {}
        routes: list[BaseRoute] = []
        push_validator = None
        if push is not None:
            push_validator = make_push_url_validator(push.allow_private)
            # Each agent's sender caps its POSTs at max_concurrent_deliveries; size the pool so
            # one agent's slow webhooks cannot exhaust the connections of the others.
            slots = push.max_concurrent_deliveries * max(1, len(self.specs))
            self.push_http = push_http_client(push, slots=slots)
        for agent_id, spec in self.specs.items():
            store = task_store_for(engine, agent_id)
            await retry_ddl(store.initialize)
            stores[agent_id] = store
            executor = AdapterExecutor(
                spec,
                index,
                self.bus,
                policy=self.policy,
                audit=audit,
                context_verifier=self.context_verifier,
            )
            # Cancelling an inbound task cancels the partner tasks it started (and ends the
            # consult tokens of its runs, with their REST calls in flight).
            executor.on_cancel = self._end_inbound
            card = build_card(spec, self.base_url, security=self.auth, push=push is not None)
            if self.card_signer is not None:
                card = self.card_signer.sign(card)
            push_kwargs: dict[str, Any] = {}
            if push is not None:
                assert self.push_http is not None
                push_store = push_config_store_for(
                    engine,
                    agent_id,
                    fernet=push_fernet,
                    max_configs_per_task=push.max_configs_per_task,
                )
                await retry_ddl(push_store.initialize)
                sender = GuardedPushSender(
                    self.push_http,
                    push_store,
                    settings=push,
                    agent_id=agent_id,
                    base_url=self.base_url,
                    validator=push_validator,
                )
                self.push_stores[agent_id] = push_store
                self.push_senders[agent_id] = sender
                # The handler checks the URL when a config is created; the sender again at
                # every delivery. Config CRUD is owner-scoped by the store's owner resolver.
                push_kwargs = {
                    "push_config_store": push_store,
                    "push_sender": sender,
                    "push_url_validator": push_validator,
                }
            handler = LimitedRequestHandler(
                agent_executor=executor,
                task_store=store,
                agent_card=card,
                max_parts=self.max_parts,
                input_modes=accepted_input_modes(spec),
                ledger=ledger,
                agent_id=agent_id,
                caller_limiter=self.caller_limiter,
                audit=audit,
                **push_kwargs,
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
            sub_routes += _with_v03_error_codes(
                create_jsonrpc_routes(
                    handler, rpc_url="/", context_builder=builder, enable_v0_3_compat=True
                ),
                handler,
            )
            # REST under "/rest": the card's interface URL is ".../rest" with its ``tenant``
            # field, so SDK clients call ".../rest/{tenant}/...". The SDK's own "/{tenant}"
            # mount inside this one serves that; the routes after it keep the earlier
            # "/{tenant}/rest/..." form working.
            sub_routes.append(
                Mount(
                    "/rest",
                    routes=create_rest_routes(
                        handler, context_builder=builder, enable_v0_3_compat=True
                    ),
                )
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
                        policy=self.policy,
                        audit=audit,
                    ),
                )
            )
        routes.append(Mount("/agents", app=_agent_not_found))
        # External agents consult partners with a grant this host issues for each turn. An
        # issuer another host installed (the adapter is shared) is replaced; a consult
        # callable of the user's own is kept.
        for spec in self.specs.values():
            adapter = spec.adapter
            if isinstance(adapter, WebhookAdapter | StdioAdapter) and (
                adapter.consult is None or isinstance(adapter.consult, GrantIssuer)
            ):
                adapter.consult = self.consult_issuer
                self._issued_adapters.append(adapter)
        # Adapters that own resources (e.g. a supervised agent process) start once the stores
        # are ready, before the first request can reach them.
        for agent_id, spec in self.specs.items():
            if isinstance(spec.adapter, LifecycleAdapter):
                self._started_adapters.append((agent_id, spec.adapter))
                await spec.adapter.start()
        if len(self.cards) == 1:
            routes += create_agent_card_routes(
                next(iter(self.cards.values())), cache_control=self.card_cache_control
            )
        self._inner = Starlette(routes=routes)
        if self.mcp_agents is not None:
            await self._mcp_app().start()
        self.last_recovery = await recover_on_startup(
            index,
            stores,
            durable={i: s.adapter.durable_sessions for i, s in self.specs.items()},
            handles=handles,
            cancel_outbound=self._cancel_outbound,
            cancel_timeout_s=self.default_deadline_s,
            on_failed=self._push_failed,
        )
        foreign = await index.count_active_outside(set(self.specs))
        if foreign:
            logger.warning(
                "%d non-terminal task(s) belong to agents this gateway does not serve; if no "
                "other gateway serves them, run `a2agw tasks reap --agent <id>`",
                foreign,
            )
        self._maintenance = asyncio.create_task(self._maintenance_loop(), name="a2agw:maint")

    async def maintain(self, *, now: float | None = None) -> ExpireReport:
        """One maintenance pass: end outbound handles older than ``outbound_ttl_s`` (their
        partner tasks cancelled, a failed cancel retried by later passes; each attempt
        audited as ``outbound.expire``) and purge inbound message ids past retention.

        Scoped to this gateway: only handles of partners in this host's registry whose
        inbound task belongs to one of this host's agents, or that have no inbound task and
        are owned by one of its sidecar agents (``sidecar_owner``), so several gateways can
        share one database (other handles with no inbound task are not expired by any
        host)."""
        if self.handles is None or self.ledger is None:
            raise RuntimeError("host not started")
        report = await expire_outbound(
            self.handles,
            self._cancel_outbound,
            self.audit,
            ttl_s=self.outbound_ttl_s,
            now=now,
            cancel_timeout_s=self.default_deadline_s,
            partner_ids={r.id for r in self.partners.all()},
            agent_ids=set(self.specs),
            owners={self.sidecar_owner(a) for a in self.sidecar_agent_ids()},
        )
        await self.ledger.purge(now)
        await self.refresh_due_partners(now=now)
        self.partners.flush()  # changes a busy partners file lock kept unsaved
        return report

    async def refresh_due_partners(self, *, now: float | None = None) -> dict[str, str]:
        """Spec 7.3 / 8.7: refresh the cards of URL partners whose ``fetched_at + ttl_s`` has
        passed (active or quarantined; oldest first), at most ``REFRESH_MAX_PER_PASS`` per
        call, ``REFRESH_CONCURRENCY`` at a time. A changed card, a signature that no longer
        verifies or a changed signing key quarantines the partner (audited like every
        registry change). A fetch failure leaves the partner as it was and logs a WARNING.
        Returns {partner id: "unchanged" | "quarantined" | "error"}."""
        t = time.time() if now is None else now
        due = sorted(
            (
                r
                for r in self.partners.all()
                if r.card_url and r.status != "disabled" and r.fetched_at + r.ttl_s <= t
            ),
            key=lambda r: r.fetched_at,
        )[:REFRESH_MAX_PER_PASS]
        gate = asyncio.Semaphore(REFRESH_CONCURRENCY)
        out: dict[str, str] = {}

        async def one(pid: str) -> None:
            async with gate:
                try:
                    out[pid] = await self.partners.refresh(pid)
                except KeyError:
                    return  # removed meanwhile (a reload)
                except Exception as exc:  # noqa: BLE001 - one partner never stops the pass
                    out[pid] = "error"
                    logger.warning(
                        "partner %s: card refresh failed (%s); state unchanged",
                        pid,
                        exc if isinstance(exc, (CardFetchError, UnsafeURL)) else type(exc).__name__,
                    )

        await asyncio.gather(*(one(r.id) for r in due))
        return out

    async def _maintenance_loop(self) -> None:
        while True:
            await asyncio.sleep(self.maintenance_interval_s)
            try:
                report = await self.maintain()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive; retried next pass
                logger.warning("maintenance pass failed: %s", type(exc).__name__)
                continue
            if report.expired:
                logger.info(
                    "expired %d outbound task(s) past the TTL (%d not confirmed canceled)",
                    report.expired,
                    report.cancel_failed,
                )

    async def reap(
        self, agent_id: str, *, confirm: bool = False, force: bool = False, actor: str = "system"
    ) -> ReapResult:
        """Fail the open tasks of an agent nobody serves and cancel their outbound partner
        tasks (see ``a2agw.serve.reap``). Without ``confirm`` it only counts what would be
        reaped. Raises ``AgentServedError`` for an agent of this host and
        ``RecentActivityError`` for tasks touched recently (unless ``force``). Audited."""
        if self.index is None or self.engine is None:
            raise RuntimeError("host not started")
        store: TaskStore | None = None
        sender: GuardedPushSender | None = None
        if confirm and agent_id not in self.specs and _AGENT_ID.fullmatch(agent_id):
            # The reaped agent's own SDK task table (and push configs): its tasks are failed
            # there too, and their webhooks get the FAILED update (M2, I6).
            store = task_store_for(self.engine, agent_id)
            if self.push is not None and self.push_http is not None:
                push_store = push_config_store_for(
                    self.engine,
                    agent_id,
                    fernet=self.push.fernet(),
                    max_configs_per_task=self.push.max_configs_per_task,
                )
                sender = GuardedPushSender(
                    self.push_http,
                    push_store,
                    settings=self.push,
                    agent_id=agent_id,
                    base_url=self.base_url,
                )

        async def notify(aid: str, task: Task) -> None:
            if sender is not None:
                await sender.send_notification(task.id, task)

        try:
            return await reap_agent(
                self.index,
                self.handles,
                self._cancel_outbound,
                self.audit,
                agent_id,
                served=set(self.specs),
                confirm=confirm,
                force=force,
                actor=actor,
                cancel_timeout_s=self.default_deadline_s,
                store=store,
                on_failed=notify,
            )
        finally:
            if sender is not None:
                await sender.aclose(DRAIN_TIMEOUT_S)

    async def _push_failed(self, agent_id: str, task: Task) -> None:
        """Queue a task's FAILED state on its agent's push sender (restart recovery). The
        sender deletes the task's webhook configs once that terminal update is delivered
        (at once when it has none)."""
        sender = self.push_senders.get(agent_id)
        if sender is not None:
            await sender.send_notification(task.id, task)

    def _audit_registry_change(self, rec: PartnerRecord, event: str) -> None:
        """Registry listener: one audit row per partner lifecycle change."""
        ev = registry_audit_event(rec, event, self.partners.change_info)
        if ev is None:
            return
        if self.audit is not None:
            self.audit.submit(ev)
        elif len(self._early_audit) < _EARLY_AUDIT_MAX:
            self._early_audit.append(ev)
        else:
            logger.warning("partner change before startup not audited (buffer full)")

    def _warn_unknown_routing_partners(self) -> None:
        if self.policy is None:
            return
        known = {r.id for r in self.partners.all()}
        named = {p for rule in self.policy.policy.routing for p in rule.partners}
        unknown = sorted(named - known)
        if unknown:
            logger.warning("policy routing rules name unknown partner ids: %s", ", ".join(unknown))

    async def reload_partners(self, *, force: bool = False) -> dict[str, Any]:
        """Re-read the partners file into the running registry, so partners added with the
        CLI are usable without a restart (``PartnerRegistry.prepare_reload``/``apply_reload``).

        Removing a partner that still has non-terminal outbound tasks (handles) would orphan
        them: that is refused with ``PartnersInUse`` unless ``force``. The result has the ids
        per change and ``open_handles``, the open handles of removed partners (logged when
        not zero). ValueError if there is no partners file or it is invalid; ReloadConflict
        if the registry changed meanwhile. In every failure case the registry is unchanged.

        Known window: the open handles are counted while awaiting ``count_open``; a partner
        task started for a removed partner during that await is not counted, so the removal
        can still orphan it."""
        plan = self.partners.prepare_reload()
        open_handles = 0
        if plan.removed and self.handles is not None:
            open_handles = sum((await self.handles.count_open(plan.removed)).values())
        if open_handles and not force:
            raise PartnersInUse(open_handles)
        changes: dict[str, Any] = self.partners.apply_reload(plan)
        if open_handles:
            logger.warning(
                "partner reload removed partners with %d open outbound task(s)", open_handles
            )
        self._warn_unknown_routing_partners()
        return {**changes, "open_handles": open_handles}

    @staticmethod
    def sidecar_owner(agent_id: str) -> str:
        """The handle owner of a partner task a sidecar agent started outside any inbound
        task (a standalone REST or MCP call)."""
        return f"sidecar:{agent_id}"

    def sidecar_agent_ids(self) -> set[str]:
        """This host's sidecar agents: the external (webhook, stdio) agents it serves, every
        agent id in ``sidecar_clients``, and ``sidecar_agents`` (``mcp_agents`` included)."""
        served = {
            i for i, s in self.specs.items() if isinstance(s.adapter, WebhookAdapter | StdioAdapter)
        }
        return served.union(*self.sidecar_clients.values(), self.sidecar_agents)

    async def _end_inbound(self, task_id: str) -> int:
        """An inbound task was cancelled or ended: its consult tokens stop working (their
        REST calls in flight are cancelled) and its open partner tasks are cancelled."""
        self.consult_tokens.revoke_task(task_id)
        assert self.client is not None
        return await self.client.cancel_for_inbound(task_id)

    def partner_tools(self, agent_id: str, **kwargs: Any) -> list[PartnerTool]:
        """``partner_tools`` for one of this host's agents, filtered by the host's policy."""
        return partner_tools(self.partners, policy=self.policy, agent_id=agent_id, **kwargs)

    async def _cancel_outbound(self, handle: dict[str, Any]) -> None:
        """Recovery: cancel one partner task, as the caller it was started for; raise unless
        the partner reports it canceled."""
        assert self.client is not None
        await make_cancel_outbound(self.client)(handle)

    def push_stats(self, agent_id: str) -> dict[str, int]:
        """Delivery counters of one agent's push sender (delivered, failed, retries,
        skipped_unsafe, dropped, pending)."""
        return self.push_senders[agent_id].counters()

    async def shutdown(self) -> None:
        # Order matters: end event streams, stop the executors and the adapters with a
        # lifecycle, flush pending push deliveries (bounded), let the partner client drain its
        # cancellation cleanups (they need the engine), then dispose the engine.
        self.bus.close_all()
        if self._maintenance is not None:
            self._maintenance.cancel()
            await asyncio.gather(self._maintenance, return_exceptions=True)
            self._maintenance = None
        if self._mcp is not None:
            await self._mcp.stop()  # its sessions' calls in flight end here
        for handler in self.handlers.values():
            await handler.aclose()
        await self._stop_adapters()
        if self.push_senders:
            await asyncio.gather(*(s.aclose(DRAIN_TIMEOUT_S) for s in self.push_senders.values()))
        if self.push_http is not None:
            await self.push_http.aclose()
            self.push_http = None
        if self.client is not None:
            await self.client.aclose()
        if self.audit is not None:
            await self.audit.flush_coalesced()
            await self.audit.drain()  # registry events still being written
        if self.engine is not None:
            await self.engine.dispose()
            self.engine = None

    async def _stop_adapters(self) -> None:
        """Stop the adapters started at startup, concurrently (one slow shutdown does not
        hold up the others). One that fails to stop is logged (its error class only). The
        grant issuer this host gave its adapters is taken back (unless replaced since)."""
        issued, self._issued_adapters = self._issued_adapters, []
        for adapter in issued:
            if adapter.consult is self.consult_issuer:
                adapter.consult = None
        started, self._started_adapters = self._started_adapters, []
        started.reverse()
        results = await asyncio.gather(*(a.stop() for _, a in started), return_exceptions=True)
        for (agent_id, _), result in zip(started, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("agent %s: adapter stop failed: %s", agent_id, type(result).__name__)

    def _mcp_app(self) -> McpHttpApp:
        """The MCP server's ASGI app (imports ``mcp``: only when ``mcp_agents`` is set)."""
        if self._mcp is None:
            from a2agw.gateway.mcp_server import mcp_asgi_app

            self._mcp = mcp_asgi_app(self)
        return self._mcp

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
                with _on_exit_signal(self.bus.close_all):
                    yield
            finally:
                await self.shutdown()

        app = Starlette(
            routes=[
                *self.extra_routes,
                *(admin_routes(self) if self.admin else []),
                *rest_routes(self),
                *([Mount(MCP_PREFIX, app=self._mcp_app())] if self.mcp_agents is not None else []),
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

    def run(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        *,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
        ssl_ca_certs: str | None = None,
        require_client_cert: bool = False,
        graceful_timeout_s: float | None = GRACEFUL_TIMEOUT_S,
    ) -> None:
        """Serve the app with uvicorn.

        On shutdown uvicorn waits at most ``graceful_timeout_s`` seconds for open requests
        (``None``: no bound) before the lifespan shutdown runs. Signal handling after the
        host exits: see ``_on_exit_signal`` (a SIGTERM handler that was installed outside
        Python cannot be restored, so later SIGTERMs are swallowed).

        Binds ``127.0.0.1`` (this machine only) by default. Pass ``host="0.0.0.0"`` to accept
        connections from other machines, and configure ``auth`` before doing so.

        TLS: give ``ssl_certfile`` (and ``ssl_keyfile``) to serve HTTPS. With
        ``require_client_cert=True`` the TLS handshake demands a client certificate signed by
        ``ssl_ca_certs`` (required in that case). The certificate is checked at the TLS layer
        only: ASGI servers do not expose the peer certificate, so a caller's identity still
        comes from its API key or JWT, never from the certificate.
        """
        import ssl

        import uvicorn

        if self.admin and self.auth is None and self.admin_without_auth and not _loopback(host):
            logger.warning(
                "admin_without_auth with a non-loopback bind (%s): the admin API is open to "
                "anyone who can reach this port; configure auth",
                host,
            )
        kwargs: dict[str, Any] = {}
        if require_client_cert and not ssl_ca_certs:
            raise ValueError("require_client_cert needs ssl_ca_certs")
        if require_client_cert and not ssl_certfile:
            raise ValueError("require_client_cert needs ssl_certfile")
        if ssl_certfile:
            kwargs.update(
                ssl_certfile=ssl_certfile,
                ssl_keyfile=ssl_keyfile,
                ssl_ca_certs=ssl_ca_certs,
                ssl_cert_reqs=ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE,
            )
        elif ssl_keyfile or ssl_ca_certs:
            raise ValueError("ssl_keyfile / ssl_ca_certs need ssl_certfile")
        uvicorn.run(
            self.app(),
            host=host,
            port=port,
            timeout_graceful_shutdown=graceful_timeout_s,
            **kwargs,
        )
