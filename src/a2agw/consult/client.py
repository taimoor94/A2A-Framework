"""PartnerClient: consult registered partner agents over A2A, with resilience and task handles.

Every call goes through: registry lookup (only ``active`` partners) and a full endpoint check,
the partner's bulkhead, then its circuit breaker. The current call context is sent unchanged
in the message metadata (R6), together with the ``A2A-Version`` and ``A2A-Extensions`` service
parameters and the partner's credential headers.

Failure handling never re-sends a message once a request may have reached the partner:

- connection errors raised before any response are retried (``with_retry``);
- an ambiguous failure (a read error, a 502/503/504, or the deadline passing before any
  response) triggers a lookup of the task by the ``context_id`` this call generated; the task
  is followed if found, otherwise the result is "delivery unknown";
- a broken stream falls back to ``subscribe``, then to polling ``get_task``.

Every call that the breaker admits records an outcome (success on any protocol response,
failure on transport errors, 5xx and timeouts) or, when it ends without one (credential
error, cancellation, delivery unknown), gives a half-open probe back.

Partner responses are untrusted: ids are validated (``results.Track``), text is capped and
the bytes consumed per call are bounded (see ``a2agw.consult.results``).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import math
import ssl
import threading
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from contextvars import ContextVar
from typing import Any, Literal

import httpcore
import httpx
from a2a.client import Client, ClientCallContext, ClientConfig, ClientFactory
from a2a.client.interceptors import AfterArgs, BeforeArgs, ClientCallInterceptor
from a2a.extensions.common import HTTP_EXTENSION_HEADER
from a2a.types import (
    CancelTaskRequest,
    GetTaskRequest,
    ListTasksRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    StreamResponse,
    SubscribeToTaskRequest,
    Task,
    TaskState,
)
from a2a.utils.constants import VERSION_HEADER
from a2a.utils.errors import A2AError, TaskNotCancelableError
from google.protobuf.json_format import ParseError
from opentelemetry.trace import Status as SpanStatus
from opentelemetry.trace import StatusCode

from a2agw.consult.credentials import (
    ChainCredentials,
    CredentialError,
    CredentialInterceptor,
    CredentialProvider,
)
from a2agw.consult.guarded_net import guarded_async_client
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.netguard import Tier, UnsafeURL, check_url_syntax
from a2agw.consult.registry import CardFetchError, PartnerRecord, PartnerRegistry
from a2agw.consult.resilience import Bulkhead, Busy, CircuitBreaker, with_retry
from a2agw.consult.results import (
    TERMINAL,
    TERMINAL_NAMES,
    ProtocolViolation,
    ToolResult,
    Track,
    build_result,
)
from a2agw.consult.tls import TlsClientConfig, build_async_client
from a2agw.context.call_context import (
    EXTENSION_URI,
    CallContext,
    current_agent,
    current_call,
    current_inbound_task,
    current_principal,
    maintenance_call,
    use_maintenance,
)
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.ops.bus import EventBus, GatewayEvent
from a2agw.ops.telemetry import get_tracer, with_current_traceparent
from a2agw.security.classify import Classification
from a2agw.security.policy import Decision, PolicyEngine
from a2agw.security.principal import Principal

__all__ = ["PartnerClient", "ToolResult"]

logger = logging.getLogger(__name__)

# Module-level so tests can shrink them.
POLL_MIN_S = 0.1  # first get_task poll interval; doubles up to POLL_MAX_S
POLL_MAX_S = 1.0
WAIT_ANY_INTERVAL_S = 0.5
RETRY_BASE_S = 0.2
RETRY_CAP_S = 2.0
BULKHEAD_WAIT_S = 1.0  # how long to wait for a free slot before answering "busy"
LOOKUP_FLOOR_S = 0.5  # a lookup after the deadline passed still gets this long
ACLOSE_TIMEOUT_S = 1.0  # bound on closing a partner stream
CANCEL_CLEANUP_S = 3.0  # bound on cancelling partner work when a consult itself is cancelled

BINDINGS = ("JSONRPC", "HTTP+JSON")  # in order of preference
_AMBIGUOUS_STATUS = {502, 503, 504}  # the partner (or a proxy) may have accepted the message
PROTOCOL_ERROR = "partner protocol error"
AUTH_REJECTED = "partner rejected credentials"  # HTTP 401 to the send, after any resend

_STRICTNESS: dict[Tier, int] = {"internal": 0, "partner": 1, "public": 2}

# The inbound caller whose credentials apply to the current outbound call.
_caller: ContextVar[Principal | None] = ContextVar("a2agw_outbound_caller", default=None)
# Per call: the Authorization value the credential interceptor last sent, so a 401 only
# invalidates that token (never a newer one fetched meanwhile by another call). In memory,
# for the duration of one call only.
_sent_auth: ContextVar[dict[str, str] | None] = ContextVar("a2agw_sent_auth", default=None)


class _CallerCredentials(ClientCallInterceptor):
    """Per-partner credentials for whichever inbound caller is making the current call."""

    def __init__(self, provider: CredentialProvider, partner: PartnerRecord) -> None:
        self._provider = provider
        self._partner = partner

    async def before(self, args: BeforeArgs) -> None:
        await CredentialInterceptor(self._provider, self._partner, _caller.get()).before(args)
        sent = _sent_auth.get()
        if sent is not None:
            sent.clear()
            params = args.context.service_parameters if args.context is not None else None
            for name, value in (params or {}).items():
                if name.lower() == "authorization":
                    sent["authorization"] = value

    async def after(self, args: AfterArgs) -> None:
        return None


def _sent_token() -> str | None:
    """The bearer token sent by the current call, if any."""
    value = (_sent_auth.get() or {}).get("authorization")
    if value is None:
        return None
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else value


def _credential_error(partner_id: str | None, exc: CredentialError) -> None:
    # Credential error messages name the credential ref and never contain secret values.
    if partner_id is None:
        logger.warning("credential error on partner send: %s", exc)
    else:
        logger.warning("credential error for partner %s: %s", partner_id, exc)


Reauth = Callable[[], Awaitable[bool]]


def _invalidators(provider: CredentialProvider | None) -> list[Callable[..., Any]]:
    """The ``invalidate(partner)`` methods of a provider, or of the providers in a chain."""
    if provider is None:
        return []
    inv = getattr(provider, "invalidate", None)
    if callable(inv):
        return [inv]
    if isinstance(provider, ChainCredentials):
        return [i for p in provider.providers for i in _invalidators(p)]
    return []


class _ConnectFailed(Exception):
    """Connection-level failure before any response (safe to retry)."""


class _PartnerFault(Exception):
    """An SDK call raised something unexpected (e.g. a malformed body): a partner fault."""


ErrorKind = Literal["connect", "server", "transport", "protocol", "other"]


def _caller_id() -> str | None:
    caller = _caller.get()
    return caller.id if caller is not None else None


def _http_root(exc: BaseException) -> httpx.HTTPError | None:
    seen: BaseException | None = exc
    for _ in range(10):
        if seen is None or isinstance(seen, httpx.HTTPError):
            break
        seen = seen.__cause__ or seen.__context__
    return seen if isinstance(seen, httpx.HTTPError) else None


def _has_ssl_error(exc: BaseException) -> bool:
    """A certificate-verification failure, or an SSL error raised while connecting (under an
    httpx/httpcore ConnectError). An SSL error while reading after the request was written
    is not one: it may follow delivery, so it stays a transport error (lookup, no resend)."""
    seen: BaseException | None = exc
    connecting = False
    for _ in range(10):
        if seen is None:
            return False
        if isinstance(seen, ssl.SSLCertVerificationError):
            return True
        if isinstance(seen, (httpx.ConnectError, httpcore.ConnectError)):
            connecting = True
        if isinstance(seen, ssl.SSLError) and connecting:
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _kind(exc: BaseException) -> ErrorKind:
    """Classify an SDK/transport error by its httpx root cause."""
    if _has_ssl_error(exc):  # handshake rejected (TLS 1.3 may surface it on first read)
        return "connect"
    root = _http_root(exc)
    if isinstance(root, (httpx.ConnectError, httpx.ConnectTimeout)):
        return "connect"
    if isinstance(root, httpx.HTTPStatusError):
        return "server" if root.response.status_code >= 500 else "protocol"
    if isinstance(root, httpx.TransportError):
        return "transport"
    if isinstance(exc, (A2AError, ParseError, ProtocolViolation, _PartnerFault)):
        return "protocol"
    return "other"


def _status(exc: BaseException) -> int | None:
    root = _http_root(exc)
    return root.response.status_code if isinstance(root, httpx.HTTPStatusError) else None


def _reraise_other(exc: Exception, kind: ErrorKind) -> None:
    """Not a partner fault (SDK-call errors are wrapped first): our own bug, so re-raise."""
    if kind == "other":
        logger.exception("internal error during partner call")
        raise exc


def _contain(exc: Exception) -> Exception:
    """Map an exception raised by an SDK call: anything we would not otherwise classify is a
    malformed partner response. Our own credential errors pass through unchanged."""
    if isinstance(exc, CredentialError) or _kind(exc) != "other":
        return exc
    logger.warning("malformed partner response (%s)", type(exc).__name__)
    return _PartnerFault(type(exc).__name__)


async def _sdk(call: Awaitable[Any]) -> Any:
    """Await one SDK client call, containing partner faults (CancelledError passes through)."""
    try:
        return await call
    except Exception as e:
        mapped = _contain(e)
        if mapped is e:
            raise
        raise mapped from None


async def _next(stream: AsyncIterator[StreamResponse]) -> StreamResponse | None:
    """Next event of an SDK stream, or None at its end; partner faults contained."""
    try:
        return await stream.__anext__()
    except StopAsyncIteration:
        return None
    except Exception as e:
        mapped = _contain(e)
        if mapped is e:
            raise
        raise mapped from None


def _protocol_reason(exc: BaseException) -> str:
    if isinstance(exc, (ProtocolViolation, _PartnerFault)):
        return PROTOCOL_ERROR
    return f"partner error: {type(exc).__name__}"


class _Probe:
    """Breaker bookkeeping for one admitted call: every exit records or releases."""

    def __init__(self, breaker: CircuitBreaker, probing: bool) -> None:
        self.breaker = breaker
        self.probing = probing  # this call holds the half-open probe
        self.recorded = False

    def success(self) -> None:
        self.breaker.record_success()
        self.recorded = True

    def failure(self) -> None:
        self.breaker.record_failure()
        self.recorded = True

    def kind(self, kind: ErrorKind) -> None:
        if kind in ("connect", "server", "transport"):
            self.failure()
        elif kind == "protocol":
            self.success()

    def close(self) -> None:
        if self.probing and not self.recorded:
            self.breaker.release_probe()


async def _aclose(stream: Any) -> None:
    """Close a partner stream without letting a stuck partner hold us."""
    try:
        async with asyncio.timeout(ACLOSE_TIMEOUT_S):
            await stream.aclose()
    except (TimeoutError, Exception):  # noqa: BLE001 - closing is best effort
        logger.debug("partner stream did not close cleanly")


Note = Callable[[], Awaitable[None]]

# A send whose first response was still awaited when the call was interrupted: the future
# of that first event and the stream it belongs to.
InFlight = list[tuple["asyncio.Future[StreamResponse | None]", AsyncIterator[StreamResponse]]]


async def _drop_inflight(inflight: InFlight) -> None:
    """Abandon sends still waiting for their first event (e.g. after a timeout)."""
    while inflight:
        fut, agen = inflight.pop()
        fut.cancel()
        await asyncio.gather(fut, return_exceptions=True)
        await _aclose(agen)


class PartnerClient:
    """Outbound A2A client for registered partners (see the module docstring).

    Cancellation: when a ``consult`` is itself cancelled (e.g. its inbound task was
    cancelled), the partner task it targeted is cancelled too, in a bounded background
    cleanup that ``aclose`` drains. For a reply (``task_id`` given) that means the existing
    multi-turn partner task is cancelled, not just the reply. If the call was cancelled
    before the partner answered, the cleanup keeps waiting for that first response (or, as a
    fallback, looks the task up by the context this call generated) to find the task.
    """

    def __init__(
        self,
        registry: PartnerRegistry,
        *,
        credentials: CredentialProvider | None = None,
        handles: OutboundHandleStore | None = None,
        bus: EventBus | None = None,
        http: httpx.AsyncClient | None = None,
        default_deadline_s: float = 60.0,
        agent_id: str = "client",
        tls: Mapping[str, TlsClientConfig] | None = None,
        policy: PolicyEngine | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy  # egress checks in consult(), before any network activity
        self.audit = audit
        self.tls: dict[str, TlsClientConfig] = dict(tls or {})
        for cfg in self.tls.values():  # load certificates now, not on the event loop later
            cfg.ssl_context()
        self._tls_http: dict[str, httpx.AsyncClient] = {}
        self._tls_lock = threading.Lock()
        self.credentials = credentials
        self.handles = handles
        self.bus = bus
        self.http = http
        self.default_deadline_s = default_deadline_s
        self.agent_id = agent_id
        self._own_http: httpx.AsyncClient | None = None
        self._clients: dict[tuple[str, str, str], Client] = {}
        self._breakers: dict[str, CircuitBreaker] = {}
        self._bulkheads: dict[str, Bulkhead] = {}
        self._cleanups: set[asyncio.Task[None]] = set()  # keeps cleanup tasks referenced

    # -- plumbing ----------------------------------------------------------------------

    def _http_client(self) -> httpx.AsyncClient:
        if self.http is not None:
            return self.http
        if self._own_http is None:
            self._own_http = guarded_async_client(
                self._tier_for_host, timeout=httpx.Timeout(30.0, connect=10.0)
            )
        return self._own_http

    def _tier_for_host(self, host: str) -> Tier:
        """The netguard tier the guarded clients vet ``host`` with: the tier of the registered
        partner whose card URL or interface URL names that host (the strictest one if several
        do), and ``public`` for any other host."""
        host = host.lower()
        tiers: set[Tier] = set()
        for rec in self.registry.all():
            ifaces = rec.card.get("supportedInterfaces", [])
            urls = [rec.card_url, *(i.get("url", "") for i in ifaces if isinstance(i, dict))]
            for url in urls:
                if not isinstance(url, str) or not url:
                    continue  # e.g. no card URL (added from a card)
                try:
                    if check_url_syntax(url)[1].lower() == host:
                        tiers.add(rec.tier)
                except UnsafeURL:
                    continue
        found = max(tiers, key=_STRICTNESS.__getitem__, default=None)
        return found if found is not None else "public"

    def _http_for(self, rec: PartnerRecord) -> httpx.AsyncClient:
        """The httpx client for ``rec``: the per-``tls_ref`` mTLS client when it has one
        (even if ``http`` was injected), else the shared client. Both are guarded clients
        (``a2agw.consult.guarded_net``) vetting each host for its partner's tier; an injected
        ``http`` is used as given and bypasses the guard (the test seam). Raises KeyError for
        an unknown ref; callers fail closed."""
        ref = rec.tls_ref
        if ref is None:
            return self._http_client()
        with self._tls_lock:  # one client per ref, built on first use
            hc = self._tls_http.get(ref)
            if hc is None:
                hc = build_async_client(
                    self.tls[ref],
                    httpx.Timeout(30.0, connect=10.0),
                    tier_for_host=self._tier_for_host,
                )
                self._tls_http[ref] = hc
            return hc

    def _client_for(self, rec: PartnerRecord) -> Client | None:
        key = (rec.id, rec.card_hash, rec.tls_ref or "")
        cached = self._clients.get(key)
        if cached is not None:
            return cached
        card = rec.agent_card
        offered = {i.protocol_binding for i in card.supported_interfaces}
        binding = next((b for b in BINDINGS if b in offered), None)
        if binding is None:
            return None
        config = ClientConfig(
            httpx_client=self._http_for(rec),
            streaming=card.capabilities.streaming,
            supported_protocol_bindings=[binding],
        )
        interceptors: list[ClientCallInterceptor] = []
        if self.credentials is not None:
            interceptors.append(_CallerCredentials(self.credentials, rec))
        client = ClientFactory(config).create(card, interceptors)
        # Drop clients built for an older card of this partner (they share our httpx client).
        for old in [k for k in self._clients if k[0] == rec.id]:
            del self._clients[old]
        self._clients[key] = client
        return client

    @staticmethod
    def _ctx(timeout: float) -> ClientCallContext:
        return ClientCallContext(
            timeout=max(timeout, 0.0) + 1.0,  # our own asyncio deadline fires first
            service_parameters={VERSION_HEADER: "1.0", HTTP_EXTENSION_HEADER: EXTENSION_URI},
        )

    @staticmethod
    def _provenance(partner_id: str, rec: PartnerRecord | None) -> dict[str, Any]:
        return {
            "partner": partner_id,
            "tier": rec.tier if rec else None,
            "card_hash": rec.card_hash if rec else None,
            "untrusted": True,
        }

    def _unavailable(
        self,
        partner_id: str,
        rec: PartnerRecord | None,
        reason: str,
        *,
        task_id: str | None = None,
        context_id: str | None = None,
    ) -> ToolResult:
        return ToolResult(
            partner=partner_id,
            task_id=task_id,
            context_id=context_id,
            state="unavailable",
            reason=reason,
            provenance=self._provenance(partner_id, rec),
        )

    def _failed(
        self,
        partner_id: str,
        rec: PartnerRecord,
        reason: str,
        *,
        task_id: str | None,
        context_id: str | None = None,
    ) -> ToolResult:
        return ToolResult(
            partner=partner_id,
            task_id=task_id,
            context_id=context_id,
            state="failed",
            reason=reason,
            provenance=self._provenance(partner_id, rec),
        )

    async def _prepare(
        self, partner_id: str
    ) -> tuple[PartnerRecord | None, Client | None, ToolResult | None]:
        try:
            rec = self.registry.get(partner_id)
        except KeyError:
            return None, None, self._unavailable(partner_id, None, "unknown partner")
        if rec.status != "active":
            return rec, None, self._unavailable(partner_id, rec, f"partner {rec.status}")
        try:
            await self.registry.verify_endpoints(partner_id)
        except CardFetchError:
            return rec, None, self._unavailable(partner_id, rec, "unsafe endpoint")
        if rec.tls_ref is not None and rec.tls_ref not in self.tls:
            return rec, None, self._unavailable(partner_id, rec, "tls config missing")
        client = self._client_for(rec)
        if client is None:
            return rec, None, self._unavailable(partner_id, rec, "no supported binding")
        return rec, client, None

    def _reauth(self, rec: PartnerRecord) -> Reauth | None:
        """A callback dropping ``rec``'s cached credentials, or None if no provider caches."""
        invalidators = _invalidators(self.credentials)
        if not invalidators:
            return None

        async def reauth() -> bool:
            """Whether some provider dropped (or had already replaced) the rejected token."""
            token = _sent_token()
            fresh = False
            try:
                for inv in invalidators:
                    res = inv(rec, token)
                    if inspect.isawaitable(res):
                        res = await res
                    fresh = fresh or res is True
            except Exception:  # no fresh credentials: do not resend
                logger.exception("credential invalidation for partner %s failed", rec.id)
                return False
            return fresh

        return reauth

    def _breaker(self, partner_id: str) -> CircuitBreaker:
        return self._breakers.setdefault(partner_id, CircuitBreaker())

    def _bulkhead(self, partner_id: str) -> Bulkhead:
        return self._bulkheads.setdefault(partner_id, Bulkhead())

    def partner_stats(self, partner_id: str) -> dict[str, Any]:
        """Read-only resilience snapshot for the admin API; creates no per-partner state."""
        breaker = self._breakers.get(partner_id)
        bulkhead = self._bulkheads.get(partner_id)
        return {
            "breaker_state": breaker.state if breaker is not None else "closed",
            "in_flight": bulkhead.in_use if bulkhead is not None else 0,
        }

    def _admit(self, partner_id: str) -> _Probe | None:
        breaker = self._breaker(partner_id)
        probing = breaker.state == "half_open"
        if not breaker.allow():
            return None
        return _Probe(breaker, probing)

    @staticmethod
    def _timeout(limit: float, cc: CallContext) -> float:
        rem = cc.remaining()
        return min(limit, rem if rem is not None else math.inf)

    async def _record_handle(
        self,
        partner_id: str,
        track: Track,
        inbound_task_id: str | None,
        origin: str | None,
    ) -> None:
        state = track.state_name()
        if self.handles is None or track.task_id is None or state is None:
            return
        try:
            await self.handles.record(
                track.task_id,
                partner_id,
                track.context_id,
                inbound_task_id,
                origin,
                state,
                caller_id=_caller_id(),
            )
        except Exception:
            logger.exception("could not record outbound handle for partner %s", partner_id)

    async def _update_handle(self, partner_id: str, track: Track) -> None:
        state = track.state_name()
        if self.handles is None or track.task_id is None or state is None:
            return
        try:
            await self.handles.update_state(partner_id, track.task_id, state)
        except Exception:
            logger.exception("could not update outbound handle for partner %s", partner_id)

    async def _stored_context(self, partner_id: str, task_id: str) -> str | None:
        if self.handles is None:
            return None
        try:
            row = await self.handles.get(partner_id, task_id)
        except Exception:
            logger.exception("could not read outbound handle for partner %s", partner_id)
            return None
        return (row or {}).get("context_id") or None

    def _publish(self, result: ToolResult, started: float) -> None:
        if self.bus is None:
            return
        self.bus.publish(
            GatewayEvent(
                kind="partner.call",
                agent_id=self.agent_id,
                data={
                    "partner_id": result.partner,
                    "task_id": result.task_id,
                    "state": result.state,
                    "duration_ms": round((time.monotonic() - started) * 1000, 1),
                },
            )
        )

    # -- consult -----------------------------------------------------------------------

    async def consult(
        self,
        partner_id: str,
        message: str,
        *,
        files: Iterable[tuple[str, bytes, str]] = (),
        data: dict[str, Any] | None = None,
        task_id: str | None = None,
        context_id: str | None = None,
        wait_seconds: float = 30.0,
        inbound_task_id: str | None = None,
        caller: Principal | None = None,
        classification: Classification | str | None = None,
    ) -> ToolResult:
        """Consult a partner. ``inbound_task_id`` and ``caller`` default to the inbound task
        and principal the executor is currently running an adapter for.

        With a policy, the egress check runs first, for the agent whose adapter is running
        (else this client's ``agent_id``), with ``classification`` as the caller's label. A
        denial returns ``rejected`` ("egress policy: <reason>") and sends nothing."""
        if inbound_task_id is None:
            inbound_task_id = current_inbound_task.get()
        started = time.monotonic()
        principal = caller if caller is not None else current_principal.get()
        agent_id = current_agent.get() or self.agent_id
        token = _caller.set(principal)
        decision: Decision | None = None
        try:
            with get_tracer().start_as_current_span(
                "a2agw.partner_call", record_exception=False, set_status_on_exception=False
            ) as span:
                span.set_attribute("a2agw.partner_id", partner_id)
                if task_id:
                    span.set_attribute("a2a.task_id", task_id)
                denied, decision = self._egress(partner_id, agent_id, message, data, classification)
                if denied is not None:
                    span.set_attribute("a2agw.result_state", denied.state)
                    await self._audit_egress_deny(
                        denied, decision, principal, agent_id, inbound_task_id
                    )
                    self._publish(denied, started)
                    return denied
                try:
                    result = await self._consult(
                        partner_id,
                        message,
                        files=files,
                        data=data,
                        task_id=task_id,
                        context_id=context_id,
                        wait_seconds=wait_seconds,
                        inbound_task_id=inbound_task_id,
                    )
                except BaseException as exc:
                    span.set_status(SpanStatus(StatusCode.ERROR))
                    if self.audit is not None:
                        ev = self._call_event(
                            principal,
                            agent_id,
                            partner_id,
                            inbound_task_id,
                            decision,
                            classification,
                            "error",
                            None,
                        )
                        if isinstance(exc, Exception):
                            await self.audit.emit(ev)
                        else:  # cancellation: never delay it on a database write
                            self.audit.submit(ev)
                    raise
                if result.provenance and result.provenance.get("tier"):
                    span.set_attribute("a2agw.tier", str(result.provenance["tier"]))
                if result.task_id:
                    span.set_attribute("a2a.task_id", result.task_id)
                span.set_attribute("a2agw.result_state", result.state)
        finally:
            _caller.reset(token)
        self._publish(result, started)
        if self.audit is not None:
            await self.audit.emit(
                self._call_event(
                    principal,
                    agent_id,
                    partner_id,
                    inbound_task_id,
                    decision,
                    classification,
                    result.state,
                    (result.provenance or {}).get("tier"),
                )
            )
        return result

    @staticmethod
    def _call_event(
        principal: Principal | None,
        agent_id: str,
        partner_id: str,
        inbound_task_id: str | None,
        decision: Decision | None,
        classification: Classification | str | None,
        outcome: str,
        tier: Any,
    ) -> AuditEvent:
        label = decision.classification if decision is not None else classification
        return AuditEvent(
            actor=principal.id if principal is not None else "system",
            action="partner.call",
            agent_id=agent_id,
            partner_id=partner_id,
            task_id=inbound_task_id,
            classification=label if isinstance(label, Classification) else None,
            outcome=outcome,
            detail={"state": outcome, "tier": tier},
        )

    def _egress(
        self,
        partner_id: str,
        agent_id: str,
        text: str,
        data: dict[str, Any] | None,
        classification: Classification | str | None,
    ) -> tuple[ToolResult | None, Decision | None]:
        """(rejected result, decision) on a denial; (None, decision or None) otherwise."""
        label: Classification | None
        if classification is None or isinstance(classification, Classification):
            label = classification
        else:
            try:
                label = Classification.parse(str(classification))
            except (ValueError, AttributeError):
                rec = self._record_or_none(partner_id)
                return ToolResult(
                    partner=partner_id,
                    state="rejected",
                    reason="egress policy: invalid classification",
                    provenance=self._provenance(partner_id, rec),
                ), None
        if self.policy is None:
            return None, Decision(True, "no policy", None, label) if label is not None else None
        rec = self._record_or_none(partner_id)
        if rec is None:
            return None, None  # _consult answers "unknown partner"
        decision = self.policy.egress(agent_id, rec, label, text, data)
        if decision.allowed:
            return None, decision
        return ToolResult(
            partner=partner_id,
            state="rejected",
            reason=f"egress policy: {decision.reason}",
            provenance=self._provenance(partner_id, rec),
        ), decision

    def _record_or_none(self, partner_id: str) -> PartnerRecord | None:
        try:
            return self.registry.get(partner_id)
        except KeyError:
            return None

    async def _audit_egress_deny(
        self,
        result: ToolResult,
        decision: Decision | None,
        principal: Principal | None,
        agent_id: str,
        inbound_task_id: str | None,
    ) -> None:
        if self.audit is None:
            return
        await self.audit.emit(
            AuditEvent(
                actor=principal.id if principal is not None else "system",
                action="egress.deny",
                agent_id=agent_id,
                partner_id=result.partner,
                task_id=inbound_task_id,
                classification=decision.classification if decision is not None else None,
                outcome="rejected",
                detail={
                    "reason": decision.reason if decision is not None else result.reason,
                    "rule": decision.rule if decision is not None else None,
                    "tier": (result.provenance or {}).get("tier"),
                },
            )
        )

    async def _consult(
        self,
        partner_id: str,
        text: str,
        *,
        files: Iterable[tuple[str, bytes, str]],
        data: dict[str, Any] | None,
        task_id: str | None,
        context_id: str | None,
        wait_seconds: float,
        inbound_task_id: str | None,
    ) -> ToolResult:
        rec, client, early = await self._prepare(partner_id)
        if early is not None:
            return early
        assert rec is not None and client is not None
        cc = with_current_traceparent(current_call.get() or CallContext.new(self.agent_id))
        timeout = self._timeout(min(wait_seconds, self.default_deadline_s), cc)
        if not timeout > 0:
            return self._unavailable(partner_id, rec, "deadline exceeded")

        if task_id and context_id is None:
            # A reply must stay in the task's context: use the one we stored, else send none.
            context_id = await self._stored_context(partner_id, task_id)
        generated_context = context_id is None and not task_id
        ctx_id = uuid.uuid4().hex if generated_context else context_id
        request = self._request(text, files, data, task_id, ctx_id, cc)
        streaming = rec.agent_card.capabilities.streaming
        if not streaming:
            request.configuration.return_immediately = True  # then poll get_task

        track = Track(task_id, ctx_id)
        recorded = False
        inflight: InFlight = []

        async def note() -> None:
            nonlocal recorded
            if not recorded and track.task_id is not None:
                recorded = True
                await self._record_handle(partner_id, track, inbound_task_id, cc.origin)

        deadline = asyncio.get_running_loop().time() + timeout
        sent = _sent_auth.set({})
        try:
            outcome = await self._send_admitted(
                partner_id,
                rec,
                client,
                request,
                track,
                timeout,
                deadline,
                streaming,
                reply=bool(task_id),
                generated_context=generated_context,
                note=note,
                inflight=inflight,
                reauth=self._reauth(rec),
            )
            if isinstance(outcome, ToolResult):
                return outcome
            return await self._finish(partner_id, rec, track, outcome, task_id, ctx_id, note)
        except asyncio.CancelledError:
            # The inbound task was cancelled mid-call, possibly before the partner task's
            # handle was recorded: cancel_for_inbound could not find it, so clean up here.
            await self._cleanup_cancelled(
                partner_id, client, track, generated_context, inbound_task_id, cc.origin, inflight
            )
            raise
        finally:
            _sent_auth.reset(sent)

    async def _send_admitted(
        self,
        partner_id: str,
        rec: PartnerRecord,
        client: Client,
        request: SendMessageRequest,
        track: Track,
        timeout: float,
        deadline: float,
        streaming: bool,
        *,
        reply: bool,
        generated_context: bool,
        note: Note,
        inflight: InFlight,
        reauth: Reauth | None = None,
    ) -> str | None | ToolResult:
        """Bulkhead, breaker and drive. Returns the drive outcome, or an early result."""
        try:
            async with self._bulkhead(partner_id).acquire(min(BULKHEAD_WAIT_S, timeout)):
                probe = self._admit(partner_id)
                if probe is None:
                    return self._unavailable(partner_id, rec, "circuit open")
                try:
                    outcome = await self._drive(
                        client,
                        request,
                        track,
                        probe,
                        deadline,
                        streaming=streaming,
                        reply=reply,
                        generated_context=generated_context,
                        note=note,
                        inflight=inflight,
                        reauth=reauth,
                    )
                except ProtocolViolation:
                    probe.success()  # the partner answered, wrongly
                    outcome = PROTOCOL_ERROR
                finally:
                    probe.close()
        except Busy:
            return self._unavailable(partner_id, rec, "busy")
        return outcome

    async def _finish(
        self,
        partner_id: str,
        rec: PartnerRecord,
        track: Track,
        outcome: str | None,
        task_id: str | None,
        ctx_id: str | None,
        note: Note,
    ) -> ToolResult:
        if outcome == PROTOCOL_ERROR:
            return self._failed(partner_id, rec, outcome, task_id=task_id, context_id=ctx_id)
        if outcome == AUTH_REJECTED:
            return ToolResult(
                partner=partner_id,
                task_id=task_id,
                context_id=ctx_id,
                state="auth_required",
                reason=outcome,
                provenance=self._provenance(partner_id, rec),
            )
        if outcome is not None and outcome.startswith("partner error:"):
            if track.task is None:
                return self._failed(
                    partner_id, rec, outcome, task_id=track.task_id, context_id=track.context_id
                )
            await note()
            res = build_result(partner_id, self._provenance(partner_id, rec), track)
            res.state, res.reason = "failed", outcome
            await self._update_handle(partner_id, track)
            return res
        if outcome is not None:
            return self._unavailable(
                partner_id, rec, outcome, task_id=track.task_id, context_id=track.context_id
            )
        await note()
        await self._update_handle(partner_id, track)
        return build_result(partner_id, self._provenance(partner_id, rec), track)

    async def _cleanup_cancelled(
        self,
        partner_id: str,
        client: Client,
        track: Track,
        generated_context: bool,
        inbound_task_id: str | None,
        origin: str | None,
        inflight: InFlight,
    ) -> None:
        """Cancel partner work started by a consult that is itself being cancelled.

        Runs in its own task, bounded by ``CANCEL_CLEANUP_S``, so the caller's cancellation
        cannot interrupt it; never raises (the caller re-raises its CancelledError).
        ``aclose`` drains these tasks before closing the HTTP clients."""
        work = asyncio.create_task(
            self._cancel_orphans(
                partner_id, client, track, generated_context, inbound_task_id, origin, inflight
            )
        )
        self._cleanups.add(work)
        work.add_done_callback(self._cleanups.discard)
        try:
            # The body bounds itself; the margin covers closing a stream after its timeout.
            _, pending = await asyncio.wait({work}, timeout=CANCEL_CLEANUP_S + ACLOSE_TIMEOUT_S)
        except asyncio.CancelledError:
            return  # cancelled again while waiting: the cleanup carries on in the background
        if pending:
            logger.warning("cleanup of cancelled call to partner %s timed out", partner_id)
            work.cancel()

    async def _cancel_orphans(
        self,
        partner_id: str,
        client: Client,
        track: Track,
        generated_context: bool,
        inbound_task_id: str | None,
        origin: str | None,
        inflight: InFlight,
    ) -> None:
        maintenance_call.set(True)  # this cleanup runs in its own task (its own context)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + CANCEL_CLEANUP_S
        try:
            async with asyncio.timeout_at(deadline):
                answered = False
                if track.task_id is None and inflight:
                    # The send was still waiting for its first event: keep waiting (for at
                    # most half the budget) so the partner's own response names the task.
                    answered = await self._await_first(
                        track, inflight, loop.time() + CANCEL_CLEANUP_S / 2
                    )
                if track.task_id is not None:
                    ids = [track.task_id]
                elif answered:
                    ids = []  # the partner answered without a task (a direct message)
                elif generated_context and track.context_id is not None:
                    # Only a context this call generated: a shared one may hold unrelated tasks.
                    ids = await self._orphans_by_context(client, track.context_id, deadline)
                else:
                    ids = []
                for tid in ids:
                    try:
                        task = await self._fetch(
                            client, tid, max(deadline - loop.time(), 0.0), cancel=True
                        )
                        state = TaskState.Name(task.status.state)
                    except Exception:  # noqa: BLE001 - best effort; the handle stays non-terminal
                        logger.warning(
                            "cancel of partner %s task after cancelled call failed", partner_id
                        )
                        state = TaskState.Name(TaskState.TASK_STATE_WORKING)
                    if self.handles is not None:
                        await self.handles.record(
                            tid,
                            partner_id,
                            track.context_id,
                            inbound_task_id,
                            origin,
                            state,
                            caller_id=_caller_id(),
                        )
        except TimeoutError:
            logger.warning("cleanup of cancelled call to partner %s timed out", partner_id)
        except Exception:  # cleanup must never raise
            logger.exception("cleanup of cancelled call to partner %s failed", partner_id)
        finally:
            await _drop_inflight(inflight)

    @staticmethod
    async def _await_first(track: Track, inflight: InFlight, until: float) -> bool:
        """Wait (until ``until``) for the first event of an interrupted send and apply it.
        Returns whether a valid first event arrived."""
        fut, agen = inflight.pop()
        try:
            async with asyncio.timeout_at(until):
                first = await asyncio.shield(fut)
            if first is None:
                return False
            track.apply(first)
            return True
        except (TimeoutError, Exception):  # noqa: BLE001 - fall back to the context lookup
            logger.debug("no first event from interrupted send")
            return False
        finally:
            inflight.append((fut, agen))  # closed by _drop_inflight

    async def _orphans_by_context(
        self, client: Client, context_id: str, deadline: float
    ) -> list[str]:
        """Non-terminal tasks in a context this call generated. The partner may persist its
        task after we gave up on the send, so an empty or failed lookup is retried with
        backoff until ``deadline``."""
        loop = asyncio.get_running_loop()
        delay = 0.05
        while True:
            try:
                page = await _sdk(
                    client.list_tasks(
                        ListTasksRequest(context_id=context_id, page_size=20),
                        context=self._ctx(max(deadline - loop.time(), 0.0)),
                    )
                )
                tasks = [t for t in page.tasks if t.id and t.context_id == context_id]
                if tasks:
                    return [t.id for t in tasks if t.status.state not in TERMINAL]
            except CredentialError:
                raise
            except Exception as e:  # noqa: BLE001 - retried until the deadline
                logger.debug("orphan lookup failed: %s", type(e).__name__)
            await asyncio.sleep(min(delay, max(deadline - loop.time(), 0.0)))
            delay = min(delay * 2, 0.5)

    @staticmethod
    def _request(
        text: str,
        files: Iterable[tuple[str, bytes, str]],
        data: dict[str, Any] | None,
        task_id: str | None,
        context_id: str | None,
        cc: CallContext,
    ) -> SendMessageRequest:
        files = list(files)
        msg = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER)  # reused by retries
        if context_id:
            msg.context_id = context_id
        if task_id:
            msg.task_id = task_id
        if text or (not files and data is None):
            msg.parts.append(Part(text=text))
        for name, content, media_type in files:
            msg.parts.append(Part(raw=content, filename=name, media_type=media_type))
        if data is not None:
            part = Part()
            part.data.struct_value.update(data)
            msg.parts.append(part)
        msg.metadata.update(cc.to_metadata())
        return SendMessageRequest(message=msg)

    async def _drive(
        self,
        client: Client,
        request: SendMessageRequest,
        track: Track,
        probe: _Probe,
        deadline: float,
        *,
        streaming: bool,
        reply: bool,
        generated_context: bool,
        note: Note,
        inflight: InFlight,
        reauth: Reauth | None = None,
    ) -> str | None:
        """Send and follow. Returns None on success, or the failure reason.

        An HTTP 401 to the send (so no event arrived and the partner did not accept the
        message) is answered once: ``reauth`` drops the cached credential and the same
        request, with the same message id, is sent again with fresh credentials."""
        loop = asyncio.get_running_loop()

        async def open_stream() -> tuple[AsyncIterator[StreamResponse], StreamResponse]:
            agen = client.send_message(request, context=self._ctx(deadline - loop.time()))
            # The first event is awaited in its own task, shielded: if this call is
            # interrupted, the send stays registered in ``inflight`` so a timeout can drop it
            # and a cancellation cleanup can still learn the partner's task id from it.
            fut = asyncio.ensure_future(_next(agen))
            slot = (fut, agen)
            inflight.append(slot)
            try:
                first = await asyncio.shield(fut)
            except asyncio.CancelledError:
                raise
            except BaseException as e:
                inflight.remove(slot)
                await _aclose(agen)
                if isinstance(e, Exception) and _kind(e) == "connect":
                    raise _ConnectFailed from e
                raise
            inflight.remove(slot)
            if first is None:
                await _aclose(agen)
                raise StopAsyncIteration
            return agen, first

        async def recover(*, timed_out: bool = False) -> str | None:
            return await self._recover(
                client, track, probe, deadline, streaming, generated_context, note, timed_out
            )

        # Phase 1: send. Only connection errors before any response are retried, plus one
        # resend after a 401 (the partner refused the request, so it was not accepted).
        resent = False
        while True:
            try:
                async with asyncio.timeout_at(deadline):
                    agen, first = await with_retry(
                        open_stream,
                        base=RETRY_BASE_S,
                        cap=RETRY_CAP_S,
                        retry_on=(_ConnectFailed,),
                    )
            except _ConnectFailed:
                probe.failure()
                return "partner unreachable"
            except CredentialError as e:
                _credential_error(None, e)
                return "credential error"
            except TimeoutError:
                await _drop_inflight(inflight)
                return await recover(timed_out=True)
            except StopAsyncIteration:
                probe.success()
                return await recover()
            except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
                kind = _kind(e)
                _reraise_other(e, kind)
                if _status(e) == 401:
                    if not resent and reauth is not None and await reauth():
                        resent = True
                        continue
                    probe.success()  # the partner answered: it is up
                    return AUTH_REJECTED
                probe.kind(kind)
                if kind == "transport" or _status(e) in _AMBIGUOUS_STATUS:
                    return await recover()
                if kind == "server":
                    return "partner error"
                return _protocol_reason(e)
            break
        probe.success()

        # Phase 2: consume the stream (streaming partners only).
        broken = False
        try:
            track.apply(first)
            if reply:
                track.mark_stale()
            await note()
            if streaming and not track.settled:
                async with asyncio.timeout_at(deadline):
                    while (ev := await _next(agen)) is not None:
                        track.apply(ev)
                        await note()
                        if track.settled:
                            break
        except TimeoutError:
            return None  # still working: the caller gets a handle
        except ProtocolViolation:
            raise
        except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
            kind = _kind(e)
            _reraise_other(e, kind)
            probe.kind(kind)
            if kind == "protocol":
                return _protocol_reason(e)
            broken = True
        finally:
            await _aclose(agen)

        if track.settled or track.task_id is None:
            return None
        # Phase 3: follow the task until it settles or the deadline passes.
        await self._follow(client, track, probe, deadline, subscribe=streaming and broken)
        return None

    async def _recover(
        self,
        client: Client,
        track: Track,
        probe: _Probe,
        deadline: float,
        streaming: bool,
        generated_context: bool,
        note: Note,
        timed_out: bool,
    ) -> str | None:
        """Ambiguous failure: the message may have been delivered. Find the task; never re-send."""
        if track.task_id is None:
            found = await self._lookup(client, track, generated_context, deadline)
            if found is None:
                if timed_out:
                    probe.failure()  # no response to the send, none to the lookup
                return "delivery unknown"
            probe.success()
            track.set_task(found)
            await note()
        if not track.settled:
            await self._follow(client, track, probe, deadline, subscribe=streaming)
        return None

    async def _lookup(
        self, client: Client, track: Track, generated_context: bool, deadline: float
    ) -> Task | None:
        if not generated_context or track.context_id is None:
            return None  # a shared context could hold other tasks; we cannot tell which
        bound = max(deadline - asyncio.get_running_loop().time(), LOOKUP_FLOOR_S)
        try:
            async with asyncio.timeout(bound):
                page = await client.list_tasks(
                    ListTasksRequest(
                        context_id=track.context_id, include_artifacts=True, page_size=5
                    ),
                    context=self._ctx(bound),
                )
        except (TimeoutError, Exception) as e:  # noqa: BLE001 - failure leaves delivery unknown
            logger.warning("task lookup after ambiguous failure failed: %s", type(e).__name__)
            return None
        tasks = [t for t in page.tasks if t.context_id == track.context_id and t.id]
        return tasks[0] if tasks else None

    async def _follow(
        self,
        client: Client,
        track: Track,
        probe: _Probe,
        deadline: float,
        *,
        subscribe: bool,
    ) -> None:
        """Re-attach with subscribe (if allowed), else poll get_task, until settled or deadline."""
        assert track.task_id is not None
        loop = asyncio.get_running_loop()
        if subscribe:
            stream = client.subscribe(
                SubscribeToTaskRequest(id=track.task_id),
                context=self._ctx(deadline - loop.time()),
            )
            try:
                async with asyncio.timeout_at(deadline):
                    while (ev := await _next(stream)) is not None:
                        track.apply(ev)
                        if track.settled:
                            break
                probe.success()
                if track.settled:
                    return
            except TimeoutError:
                return
            except ProtocolViolation:
                raise
            except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
                kind = _kind(e)
                _reraise_other(e, kind)
                probe.kind(kind)
            finally:
                await _aclose(stream)
        delay = POLL_MIN_S
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            try:
                async with asyncio.timeout(remaining):
                    task = await _sdk(
                        client.get_task(
                            GetTaskRequest(id=track.task_id), context=self._ctx(remaining)
                        )
                    )
                probe.success()
                track.set_task(task)
                if track.settled:
                    return
            except TimeoutError:
                return
            except ProtocolViolation:
                raise
            except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
                kind = _kind(e)
                _reraise_other(e, kind)
                probe.kind(kind)
            sleep = min(delay, deadline - loop.time())
            if sleep <= 0:
                return
            await asyncio.sleep(sleep)
            delay = min(delay * 2, POLL_MAX_S)

    # -- check / cancel ----------------------------------------------------------------

    async def check(
        self, partner_id: str, task_id: str, *, caller: Principal | None = None
    ) -> ToolResult:
        return await self._task_call(partner_id, task_id, caller, cancel=False)

    async def cancel(
        self, partner_id: str, task_id: str, *, caller: Principal | None = None
    ) -> ToolResult:
        return await self._task_call(partner_id, task_id, caller, cancel=True)

    async def _task_call(
        self, partner_id: str, task_id: str, caller: Principal | None, *, cancel: bool
    ) -> ToolResult:
        rec, client, early = await self._prepare(partner_id)
        if early is not None:
            return early
        assert rec is not None and client is not None
        cc = current_call.get() or CallContext.new(self.agent_id)
        timeout = self._timeout(self.default_deadline_s, cc)
        if not timeout > 0:
            return self._unavailable(partner_id, rec, "deadline exceeded", task_id=task_id)
        track = Track(task_id, None)
        token = _caller.set(caller if caller is not None else current_principal.get())
        try:
            async with self._bulkhead(partner_id).acquire(min(BULKHEAD_WAIT_S, timeout)):
                probe = self._admit(partner_id)
                if probe is None:
                    return self._unavailable(partner_id, rec, "circuit open", task_id=task_id)
                try:
                    async with asyncio.timeout(timeout):
                        task = await self._fetch_reauth(client, rec, task_id, timeout, cancel)
                    probe.success()
                    track.set_task(task)
                except TimeoutError:
                    probe.failure()
                    return self._unavailable(partner_id, rec, "timed out", task_id=task_id)
                except CredentialError as e:
                    _credential_error(partner_id, e)
                    return self._unavailable(partner_id, rec, "credential error", task_id=task_id)
                except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
                    kind = _kind(e)
                    _reraise_other(e, kind)
                    if _status(e) == 401:
                        probe.success()  # the partner answered: it is up
                        return ToolResult(
                            partner=partner_id,
                            task_id=task_id,
                            state="auth_required",
                            reason=AUTH_REJECTED,
                            provenance=self._provenance(partner_id, rec),
                        )
                    probe.kind(kind)
                    if kind == "protocol":
                        return self._failed(partner_id, rec, _protocol_reason(e), task_id=task_id)
                    reason = "partner unreachable" if kind == "connect" else "partner error"
                    return self._unavailable(partner_id, rec, reason, task_id=task_id)
                finally:
                    probe.close()
        except Busy:
            return self._unavailable(partner_id, rec, "busy", task_id=task_id)
        finally:
            _caller.reset(token)
        await self._update_handle(partner_id, track)
        return build_result(partner_id, self._provenance(partner_id, rec), track)

    async def _fetch_reauth(
        self, client: Client, rec: PartnerRecord, task_id: str, timeout: float, cancel: bool
    ) -> Task:
        """``_fetch``, resent once after an HTTP 401 if fresh credentials can be had (get and
        cancel are idempotent, so a resend is always safe)."""
        reauth = self._reauth(rec)
        sent = _sent_auth.set({})
        try:
            try:
                return await self._fetch(client, task_id, timeout, cancel=cancel)
            except Exception as e:
                if _status(e) != 401 or reauth is None or not await reauth():
                    raise
            return await self._fetch(client, task_id, timeout, cancel=cancel)
        finally:
            _sent_auth.reset(sent)

    async def _fetch(self, client: Client, task_id: str, timeout: float, *, cancel: bool) -> Task:
        if cancel:
            try:
                return await _sdk(
                    client.cancel_task(CancelTaskRequest(id=task_id), context=self._ctx(timeout))
                )
            except TaskNotCancelableError:
                pass  # already terminal: report its current state
        return await _sdk(client.get_task(GetTaskRequest(id=task_id), context=self._ctx(timeout)))

    # -- several handles ---------------------------------------------------------------

    async def wait_any(self, handles: list[tuple[str, str]], seconds: float) -> list[ToolResult]:
        """Poll all handles until one is no longer working, or ``seconds`` pass."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + seconds
        while True:
            results = list(await asyncio.gather(*(self.check(p, t) for p, t in handles)))
            if not results or any(r.state != "working" for r in results):
                return results
            remaining = deadline - loop.time()
            if remaining <= 0:
                return results
            await asyncio.sleep(min(WAIT_ANY_INTERVAL_S, remaining))

    async def cancel_for_inbound(self, inbound_task_id: str) -> int:
        """Cancel every non-terminal partner task started for an inbound task, concurrently,
        within ``default_deadline_s`` overall. Returns how many reached ``canceled``.

        Runs as a maintenance call (``maintenance_call``): with no inbound caller token,
        credential providers may fall back to the gateway's service credentials."""
        with use_maintenance():
            return await self._cancel_for_inbound(inbound_task_id)

    async def _cancel_for_inbound(self, inbound_task_id: str) -> int:
        if self.handles is None:
            return 0
        rows = [
            r
            for r in await self.handles.by_inbound(inbound_task_id)
            if r["state"] not in TERMINAL_NAMES
        ]
        if not rows:
            return 0
        # Each partner task is cancelled as the caller it was started for (rows written
        # before the caller was recorded fall back to the current principal).
        tasks = [
            asyncio.create_task(
                self.cancel(
                    r["partner_id"],
                    r["task_id"],
                    caller=Principal.from_id(r["caller_id"]) if r.get("caller_id") else None,
                )
            )
            for r in rows
        ]
        try:
            await asyncio.wait(tasks, timeout=self.default_deadline_s)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        cancelled = 0
        for row, t in zip(rows, tasks, strict=True):
            partner = row["partner_id"]
            if t.cancelled():
                logger.warning("cancel of partner %s task timed out", partner)
            elif (exc := t.exception()) is not None:
                logger.error("cancel of partner %s task failed", partner, exc_info=exc)
            elif t.result().state == "canceled":
                cancelled += 1
            else:
                res = t.result()
                logger.warning(
                    "partner %s task not cancelled: %s", partner, res.reason or res.state
                )
        return cancelled

    # -- lifecycle ---------------------------------------------------------------------

    async def aclose(self) -> None:
        """Drain cancellation cleanups, drop cached SDK clients and close the httpx client
        this object owns.

        Cleanups still cancelling partner work get up to ``CANCEL_CLEANUP_S`` to finish (they
        need the HTTP clients and the handle store); whatever remains is then cancelled.
        SDK clients close their httpx client, so they are only closed (through it) when the
        client is ours; an injected ``http`` client is left open for its owner.
        """
        if self._cleanups:
            pending = set(self._cleanups)
            _, left = await asyncio.wait(pending, timeout=CANCEL_CLEANUP_S)
            for t in left:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        self._clients.clear()
        with self._tls_lock:
            tls_clients, self._tls_http = list(self._tls_http.values()), {}
        for hc in tls_clients:
            await hc.aclose()
        if self._own_http is not None:
            await self._own_http.aclose()
            self._own_http = None
