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
import logging
import math
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextvars import ContextVar
from typing import Any, Literal

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
)
from a2a.utils.constants import VERSION_HEADER
from a2a.utils.errors import A2AError, TaskNotCancelableError
from google.protobuf.json_format import ParseError

from a2agw.consult.credentials import (
    CredentialInterceptor,
    CredentialProvider,
    InvalidCredential,
    MissingCredential,
)
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import CardFetchError, PartnerRecord, PartnerRegistry
from a2agw.consult.resilience import Bulkhead, Busy, CircuitBreaker, with_retry
from a2agw.consult.results import (
    TERMINAL_NAMES,
    ProtocolViolation,
    ToolResult,
    Track,
    build_result,
)
from a2agw.context.call_context import EXTENSION_URI, CallContext, current_call
from a2agw.ops.bus import EventBus, GatewayEvent
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

BINDINGS = ("JSONRPC", "HTTP+JSON")  # in order of preference
_AMBIGUOUS_STATUS = {502, 503, 504}  # the partner (or a proxy) may have accepted the message
PROTOCOL_ERROR = "partner protocol error"

# The inbound caller whose credentials apply to the current outbound call.
_caller: ContextVar[Principal | None] = ContextVar("a2agw_outbound_caller", default=None)


class _CallerCredentials(ClientCallInterceptor):
    """Per-partner credentials for whichever inbound caller is making the current call."""

    def __init__(self, provider: CredentialProvider, partner: PartnerRecord) -> None:
        self._provider = provider
        self._partner = partner

    async def before(self, args: BeforeArgs) -> None:
        await CredentialInterceptor(self._provider, self._partner, _caller.get()).before(args)

    async def after(self, args: AfterArgs) -> None:
        return None


class _ConnectFailed(Exception):
    """Connection-level failure before any response (safe to retry)."""


ErrorKind = Literal["connect", "server", "transport", "protocol", "other"]


def _http_root(exc: BaseException) -> httpx.HTTPError | None:
    seen: BaseException | None = exc
    for _ in range(10):
        if seen is None or isinstance(seen, httpx.HTTPError):
            break
        seen = seen.__cause__ or seen.__context__
    return seen if isinstance(seen, httpx.HTTPError) else None


def _kind(exc: BaseException) -> ErrorKind:
    """Classify an SDK/transport error by its httpx root cause."""
    root = _http_root(exc)
    if isinstance(root, (httpx.ConnectError, httpx.ConnectTimeout)):
        return "connect"
    if isinstance(root, httpx.HTTPStatusError):
        return "server" if root.response.status_code >= 500 else "protocol"
    if isinstance(root, httpx.TransportError):
        return "transport"
    if isinstance(exc, (A2AError, ParseError, ProtocolViolation)):
        return "protocol"
    return "other"


def _status(exc: BaseException) -> int | None:
    root = _http_root(exc)
    return root.response.status_code if isinstance(root, httpx.HTTPStatusError) else None


def _reraise_other(exc: Exception, kind: ErrorKind) -> None:
    """Not a partner fault: an internal error must not be blamed on the partner."""
    if kind == "other":
        logger.exception("internal error during partner call")
        raise exc


def _protocol_reason(exc: BaseException) -> str:
    if isinstance(exc, ProtocolViolation):
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


class PartnerClient:
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
    ) -> None:
        self.registry = registry
        self.credentials = credentials
        self.handles = handles
        self.bus = bus
        self.http = http
        self.default_deadline_s = default_deadline_s
        self.agent_id = agent_id
        self._own_http: httpx.AsyncClient | None = None
        self._clients: dict[tuple[str, str], Client] = {}
        self._breakers: dict[str, CircuitBreaker] = {}
        self._bulkheads: dict[str, Bulkhead] = {}

    # -- plumbing ----------------------------------------------------------------------

    def _http_client(self) -> httpx.AsyncClient:
        if self.http is not None:
            return self.http
        if self._own_http is None:
            self._own_http = httpx.AsyncClient(
                follow_redirects=False, timeout=httpx.Timeout(30.0, connect=10.0)
            )
        return self._own_http

    def _client_for(self, rec: PartnerRecord) -> Client | None:
        key = (rec.id, rec.card_hash)
        cached = self._clients.get(key)
        if cached is not None:
            return cached
        card = rec.agent_card
        offered = {i.protocol_binding for i in card.supported_interfaces}
        binding = next((b for b in BINDINGS if b in offered), None)
        if binding is None:
            return None
        config = ClientConfig(
            httpx_client=self._http_client(),
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
        client = self._client_for(rec)
        if client is None:
            return rec, None, self._unavailable(partner_id, rec, "no supported binding")
        return rec, client, None

    def _breaker(self, partner_id: str) -> CircuitBreaker:
        return self._breakers.setdefault(partner_id, CircuitBreaker())

    def _bulkhead(self, partner_id: str) -> Bulkhead:
        return self._bulkheads.setdefault(partner_id, Bulkhead())

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
                track.task_id, partner_id, track.context_id, inbound_task_id, origin, state
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
    ) -> ToolResult:
        started = time.monotonic()
        token = _caller.set(caller)
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
        finally:
            _caller.reset(token)
        self._publish(result, started)
        return result

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
        cc = current_call.get() or CallContext.new(self.agent_id)
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

        async def note() -> None:
            nonlocal recorded
            if not recorded and track.task_id is not None:
                recorded = True
                await self._record_handle(partner_id, track, inbound_task_id, cc.origin)

        deadline = asyncio.get_running_loop().time() + timeout
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
                        reply=bool(task_id),
                        generated_context=generated_context,
                        note=note,
                    )
                except ProtocolViolation:
                    probe.success()  # the partner answered, wrongly
                    outcome = PROTOCOL_ERROR
                finally:
                    probe.close()
        except Busy:
            return self._unavailable(partner_id, rec, "busy")

        if outcome == PROTOCOL_ERROR:
            return self._failed(partner_id, rec, outcome, task_id=task_id, context_id=ctx_id)
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
    ) -> str | None:
        """Send and follow. Returns None on success, or the failure reason."""
        loop = asyncio.get_running_loop()

        async def open_stream() -> tuple[AsyncIterator[StreamResponse], StreamResponse]:
            agen = client.send_message(request, context=self._ctx(deadline - loop.time()))
            try:
                first = await agen.__anext__()
            except BaseException as e:
                await _aclose(agen)
                if isinstance(e, Exception) and _kind(e) == "connect":
                    raise _ConnectFailed from e
                raise
            return agen, first

        async def recover(*, timed_out: bool = False) -> str | None:
            return await self._recover(
                client, track, probe, deadline, streaming, generated_context, note, timed_out
            )

        # Phase 1: send. Only connection errors before any response are retried.
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
        except (MissingCredential, InvalidCredential):
            return "credential error"
        except TimeoutError:
            return await recover(timed_out=True)
        except StopAsyncIteration:
            probe.success()
            return await recover()
        except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
            kind = _kind(e)
            _reraise_other(e, kind)
            probe.kind(kind)
            if kind == "transport" or _status(e) in _AMBIGUOUS_STATUS:
                return await recover()
            if kind == "server":
                return "partner error"
            return _protocol_reason(e)
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
                    async for ev in agen:
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
                    async for ev in stream:
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
                    task = await client.get_task(
                        GetTaskRequest(id=track.task_id), context=self._ctx(remaining)
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
        token = _caller.set(caller)
        try:
            async with self._bulkhead(partner_id).acquire(min(BULKHEAD_WAIT_S, timeout)):
                probe = self._admit(partner_id)
                if probe is None:
                    return self._unavailable(partner_id, rec, "circuit open", task_id=task_id)
                try:
                    async with asyncio.timeout(timeout):
                        task = await self._fetch(client, task_id, timeout, cancel=cancel)
                    probe.success()
                    track.set_task(task)
                except TimeoutError:
                    probe.failure()
                    return self._unavailable(partner_id, rec, "timed out", task_id=task_id)
                except (MissingCredential, InvalidCredential):
                    return self._unavailable(partner_id, rec, "credential error", task_id=task_id)
                except Exception as e:  # noqa: BLE001 - classified; internal errors re-raised
                    kind = _kind(e)
                    _reraise_other(e, kind)
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

    async def _fetch(self, client: Client, task_id: str, timeout: float, *, cancel: bool) -> Task:
        if cancel:
            try:
                return await client.cancel_task(
                    CancelTaskRequest(id=task_id), context=self._ctx(timeout)
                )
            except TaskNotCancelableError:
                pass  # already terminal: report its current state
        return await client.get_task(GetTaskRequest(id=task_id), context=self._ctx(timeout))

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
        within ``default_deadline_s`` overall. Returns how many reached ``canceled``."""
        if self.handles is None:
            return 0
        rows = [
            r
            for r in await self.handles.by_inbound(inbound_task_id)
            if r["state"] not in TERMINAL_NAMES
        ]
        if not rows:
            return 0
        tasks = [asyncio.create_task(self.cancel(r["partner_id"], r["task_id"])) for r in rows]
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
        """Drop cached SDK clients and close the httpx client this object owns.

        SDK clients close their httpx client, so they are only closed (through it) when the
        client is ours; an injected ``http`` client is left open for its owner.
        """
        self._clients.clear()
        if self._own_http is not None:
            await self._own_http.aclose()
            self._own_http = None
