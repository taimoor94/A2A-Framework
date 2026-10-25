"""AgentHost: one Starlette app serving N agents over A2A JSON-RPC and REST."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import threading
from collections.abc import AsyncGenerator, AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
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

from a2agw._ddl import retry_ddl
from a2agw.consult.client import PartnerClient
from a2agw.consult.credentials import CredentialProvider
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import PartnerRecord, PartnerRegistry
from a2agw.consult.tools import PartnerTool, partner_tools
from a2agw.context.call_context import use_maintenance
from a2agw.ops.admin import ADMIN_PREFIX, HEALTH_PATH, admin_routes
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.ops.bus import EventBus
from a2agw.security.auth import (
    AuthConfig,
    GatewayAuthBackend,
    GatewayCallContextBuilder,
    PermissionDenied,
    authorize,
    on_auth_error,
)
from a2agw.security.cardsign import CardSigner
from a2agw.security.policy import PolicyEngine
from a2agw.security.principal import Principal, PrincipalUser
from a2agw.serve.agent import AgentSpec, build_card
from a2agw.serve.executor import AdapterExecutor
from a2agw.serve.push import (
    DRAIN_TIMEOUT_S,
    GatewayPushConfigStore,
    GuardedPushSender,
    PushSettings,
    make_push_url_validator,
    push_config_store_for,
)
from a2agw.serve.store import (
    RecoveryReport,
    TaskIndex,
    create_engine,
    recover_on_startup,
    task_store_for,
)

CARD_PATH = "/.well-known/agent-card.json"
logger = logging.getLogger(__name__)
# Registry on_change events -> audit actions.
_REGISTRY_ACTIONS = {
    "added": "partner.add",
    "quarantined": "partner.quarantine",
    "approved": "partner.approve",
    "disabled": "partner.disable",
    "enabled": "partner.enable",
    "updated": "partner.update",
}
_EXIT_SIGNALS = (signal.SIGINT, signal.SIGTERM)


@contextmanager
def _on_exit_signal(callback: Callable[[], None]) -> Iterator[None]:
    """Run ``callback`` on the event loop when SIGINT/SIGTERM arrives, then hand the signal
    to whatever handler was installed before (uvicorn's, under ``uvicorn.run``).

    Uvicorn waits for open responses to finish *before* the lifespan shutdown runs, so
    endless streams (admin ``/events``) must be ended as soon as the signal is seen.
    Only possible in the main thread; elsewhere this does nothing."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    loop = asyncio.get_running_loop()
    previous: dict[int, Any] = {sig: signal.getsignal(sig) for sig in _EXIT_SIGNALS}

    def handler(sig: int, frame: Any) -> None:
        loop.call_soon_threadsafe(callback)
        prev = previous[sig]
        if callable(prev):
            prev(sig, frame)
        elif prev == signal.SIG_DFL and sig == signal.SIGINT:
            signal.default_int_handler(sig, frame)
        elif prev == signal.SIG_DFL:
            signal.signal(sig, signal.SIG_DFL)
            signal.raise_signal(sig)

    for sig in _EXIT_SIGNALS:
        signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, prev in previous.items():
            if signal.getsignal(sig) is handler:
                signal.signal(sig, prev)


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
    ) -> None:
        self.base_url = base_url
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
        self.partners = PartnerRegistry(
            Path(partners_path) if partners_path is not None else None, http=partner_http
        )
        self.credentials = credentials
        self.partner_http = partner_http
        self.default_deadline_s = default_deadline_s
        self.handles: OutboundHandleStore | None = None
        self.client: PartnerClient | None = None
        self._inner: Starlette | None = None
        self._audit_hooked = False
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
        push = self.push
        push_fernet = push.fernet() if push is not None else None  # fail before opening
        self.bus.reopen()
        engine = self.engine = await create_engine(self.db_url)
        index = self.index = TaskIndex(engine)
        await index.initialize()
        audit: AuditLog | None = None
        if self.audit_enabled:
            audit = self.audit = AuditLog(engine)
            await audit.initialize()
            self._hook_registry_audit()
        self.partners.load()
        self._warn_unknown_routing_partners()
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
            policy=self.policy,
            audit=audit,
        )
        stores: dict[str, TaskStore] = {}
        routes: list[BaseRoute] = []
        push_validator = None
        if push is not None:
            push_validator = make_push_url_validator(push.allow_private)
            # Each agent's sender caps its POSTs at max_concurrent_deliveries; size the pool so
            # one agent's slow webhooks cannot exhaust the connections of the others.
            slots = push.max_concurrent_deliveries * max(1, len(self.specs))
            self.push_http = httpx.AsyncClient(
                follow_redirects=False,
                timeout=push.timeout_s,
                limits=httpx.Limits(max_connections=slots, max_keepalive_connections=slots),
            )
        for agent_id, spec in self.specs.items():
            store = task_store_for(engine, agent_id)
            await retry_ddl(store.initialize)
            stores[agent_id] = store
            executor = AdapterExecutor(spec, index, self.bus, policy=self.policy, audit=audit)
            # Cancelling an inbound task cancels the partner tasks it started.
            executor.on_cancel = client.cancel_for_inbound
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
                        policy=self.policy,
                        audit=audit,
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

    def _hook_registry_audit(self) -> None:
        """Chain an audit callback onto the registry's ``on_change`` (once per host)."""
        if self._audit_hooked:
            return
        self._audit_hooked = True
        previous = self.partners.on_change

        def on_change(rec: PartnerRecord, event: str) -> None:
            if previous is not None:
                previous(rec, event)
            action = _REGISTRY_ACTIONS.get(event)
            if self.audit is None or action is None:
                return
            self.audit.submit(
                AuditEvent(
                    actor="system",
                    action=action,  # type: ignore[arg-type]
                    partner_id=rec.id,
                    outcome=rec.status,
                    detail={"tier": rec.tier, "state": rec.status, "key_id": rec.signed_key_id},
                )
            )

        self.partners.on_change = on_change

    def _warn_unknown_routing_partners(self) -> None:
        if self.policy is None:
            return
        known = {r.id for r in self.partners.all()}
        named = {p for rule in self.policy.policy.routing for p in rule.partners}
        unknown = sorted(named - known)
        if unknown:
            logger.warning("policy routing rules name unknown partner ids: %s", ", ".join(unknown))

    def partner_tools(self, agent_id: str, **kwargs: Any) -> list[PartnerTool]:
        """``partner_tools`` for one of this host's agents, filtered by the host's policy."""
        return partner_tools(self.partners, policy=self.policy, agent_id=agent_id, **kwargs)

    async def _cancel_outbound(self, handle: dict[str, Any]) -> None:
        """Recovery: cancel one partner task, as the caller it was started for; raise unless
        the partner reports it canceled."""
        assert self.client is not None
        caller_id = handle.get("caller_id")
        caller = Principal.from_id(caller_id) if caller_id else None
        with use_maintenance():
            result = await self.client.cancel(
                handle["partner_id"], handle["task_id"], caller=caller
            )
        if result.state != "canceled":
            raise RuntimeError("not canceled")

    def push_stats(self, agent_id: str) -> dict[str, int]:
        """Delivery counters of one agent's push sender (delivered, failed, retries,
        skipped_unsafe, dropped, pending)."""
        return self.push_senders[agent_id].counters()

    async def shutdown(self) -> None:
        # Order matters: end event streams, stop the executors, flush pending push
        # deliveries (bounded), let the partner client drain its cancellation cleanups (they
        # need the engine), then dispose the engine.
        self.bus.close_all()
        for handler in self.handlers.values():
            await handler.aclose()
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
    ) -> None:
        """Serve the app with uvicorn.

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
        uvicorn.run(self.app(), host=host, port=port, **kwargs)
