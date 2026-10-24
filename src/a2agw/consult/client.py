"""PartnerClient: consult registered partner agents over A2A, with resilience and task handles.

Every call goes through: registry lookup (only ``active`` partners) and a full endpoint check,
the partner's circuit breaker, then its bulkhead. The current call context is sent unchanged
in the message metadata (R6), together with the ``A2A-Version`` and ``A2A-Extensions`` service
parameters and the partner's credential headers.

Failure handling never re-sends a message once a request may have reached the partner:

- connection errors raised before any response are retried (``with_retry``);
- a read error after the request was sent is ambiguous: the task is looked up by the
  ``context_id`` this call generated, and followed if found ("delivery unknown" otherwise);
- a broken stream falls back to ``subscribe``, then to polling ``get_task``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
import uuid
from collections.abc import Iterable
from contextvars import ContextVar
from typing import Any, Literal

import httpx
from a2a.client import Client, ClientCallContext, ClientConfig, ClientFactory
from a2a.client.interceptors import AfterArgs, BeforeArgs, ClientCallInterceptor
from a2a.extensions.common import HTTP_EXTENSION_HEADER
from a2a.server.tasks.task_manager import append_artifact_to_task
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
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, Field

from a2agw.consult.credentials import (
    CredentialInterceptor,
    CredentialProvider,
    InvalidCredential,
    MissingCredential,
)
from a2agw.consult.handles import OutboundHandleStore
from a2agw.consult.registry import CardFetchError, PartnerRecord, PartnerRegistry
from a2agw.consult.resilience import Bulkhead, Busy, CircuitBreaker, with_retry
from a2agw.context.call_context import EXTENSION_URI, CallContext, current_call
from a2agw.ops.bus import EventBus, GatewayEvent
from a2agw.security.principal import Principal

logger = logging.getLogger(__name__)

# Module-level so tests can shrink them.
POLL_MIN_S = 0.1  # first get_task poll interval; doubles up to POLL_MAX_S
POLL_MAX_S = 1.0
WAIT_ANY_INTERVAL_S = 0.5
RETRY_BASE_S = 0.2
RETRY_CAP_S = 2.0
BULKHEAD_WAIT_S = 1.0  # how long to wait for a free slot before answering "busy"
LOOKUP_TIMEOUT_S = 5.0  # bound on the list_tasks lookup after an ambiguous failure

BINDINGS = ("JSONRPC", "HTTP+JSON")  # in order of preference

ResultState = Literal[
    "completed",
    "working",
    "input_required",
    "auth_required",
    "failed",
    "canceled",
    "rejected",
    "unavailable",
]

_STATES: dict[int, ResultState] = {
    TaskState.TASK_STATE_COMPLETED: "completed",
    TaskState.TASK_STATE_WORKING: "working",
    TaskState.TASK_STATE_SUBMITTED: "working",
    TaskState.TASK_STATE_INPUT_REQUIRED: "input_required",
    TaskState.TASK_STATE_AUTH_REQUIRED: "auth_required",
    TaskState.TASK_STATE_FAILED: "failed",
    TaskState.TASK_STATE_CANCELED: "canceled",
    TaskState.TASK_STATE_REJECTED: "rejected",
}
_INTERRUPTED = {TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED}
_TERMINAL = {
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_REJECTED,
}
_TERMINAL_NAMES = {TaskState.Name(s) for s in _TERMINAL}

# The inbound caller whose credentials apply to the current outbound call.
_caller: ContextVar[Principal | None] = ContextVar("a2agw_outbound_caller", default=None)


class ToolResult(BaseModel):
    partner: str
    task_id: str | None = None
    context_id: str | None = None
    state: ResultState
    text: str = ""
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    question: str | None = None
    reason: str | None = None
    truncated: bool = False
    provenance: dict[str, Any] = Field(default_factory=dict)


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


def _kind(exc: BaseException) -> ErrorKind:
    """Classify an SDK/transport error by its httpx root cause."""
    seen: BaseException | None = exc
    for _ in range(10):
        if seen is None or isinstance(seen, httpx.HTTPError):
            break
        seen = seen.__cause__ or seen.__context__
    if isinstance(seen, (httpx.ConnectError, httpx.ConnectTimeout)):
        return "connect"
    if isinstance(seen, httpx.HTTPStatusError):
        return "server" if seen.response.status_code >= 500 else "protocol"
    if isinstance(seen, httpx.TransportError):
        return "transport"
    if isinstance(exc, A2AError):
        return "protocol"
    return "other"


def _record(breaker: CircuitBreaker, kind: ErrorKind) -> None:
    if kind in ("connect", "server", "transport"):
        breaker.record_failure()
    elif kind == "protocol":
        breaker.record_success()


def _texts(parts: Iterable[Part]) -> list[str]:
    return [p.text for p in parts if p.WhichOneof("content") == "text" and p.text]


def _part_summary(p: Part) -> dict[str, Any]:
    kind = p.WhichOneof("content")
    if kind == "text":
        return {"kind": "text", "text": p.text}
    if kind == "data":
        return {"kind": "data", "data": MessageToDict(p.data)}
    out: dict[str, Any] = {"kind": "file", "media_type": p.media_type or None}
    if p.filename:
        out["name"] = p.filename
    if kind == "raw":
        out["size"] = len(p.raw)  # raw bytes are never inlined
    elif kind == "url":
        out["url"] = p.url
    return out


class _Track:
    """Accumulates what one call has learned about the partner task."""

    def __init__(self, task_id: str | None, context_id: str | None) -> None:
        self.task_id = task_id
        self.context_id = context_id
        self.task: Task | None = None
        self.message: Message | None = None
        # On a reply to an interrupted task, the old interrupted status must not end the call.
        self.stale_status: str | None = None

    def set_task(self, task: Task) -> None:
        self.task = task
        self.task_id = task.id or self.task_id
        self.context_id = task.context_id or self.context_id

    def apply(self, ev: StreamResponse) -> None:
        kind = ev.WhichOneof("payload")
        if kind == "task":
            t = Task()
            t.CopyFrom(ev.task)
            self.set_task(t)
        elif kind == "message":
            self.message = ev.message
        elif kind in ("status_update", "artifact_update"):
            upd = getattr(ev, kind)
            if self.task is None:
                self.set_task(Task(id=upd.task_id, context_id=upd.context_id))
            assert self.task is not None
            if kind == "status_update":
                self.task.status.CopyFrom(upd.status)
            else:
                append_artifact_to_task(self.task, upd)

    def _status_key(self) -> str | None:
        if self.task is None:
            return None
        s = self.task.status
        return f"{s.state}:{s.message.message_id}:{s.timestamp.ToJsonString()}"

    def mark_stale(self) -> None:
        """Called for replies: an interrupted status seen now belongs to the previous turn."""
        if self.task is not None and self.task.status.state in _INTERRUPTED:
            self.stale_status = self._status_key()

    @property
    def settled(self) -> bool:
        if self.message is not None and self.task is None:
            return True
        if self.task is None:
            return False
        state = self.task.status.state
        if state in _TERMINAL:
            return True
        if state in _INTERRUPTED:
            return self._status_key() != self.stale_status
        return False


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

    def _result(self, partner_id: str, rec: PartnerRecord, track: _Track) -> ToolResult:
        prov = self._provenance(partner_id, rec)
        if track.task is None and track.message is not None:
            msg = track.message
            parts = list(msg.parts)
            arts = []
            if any(p.WhichOneof("content") != "text" for p in parts):
                arts = [
                    {
                        "artifact_id": None,
                        "name": "message",
                        "parts": [_part_summary(p) for p in parts],
                    }
                ]
            return ToolResult(
                partner=partner_id,
                task_id=None,
                context_id=msg.context_id or track.context_id,
                state="completed",
                text="\n".join(_texts(parts)),
                artifacts=arts,
                provenance=prov,
            )
        if track.task is None:
            # Only the id is known (e.g. the deadline hit before any task snapshot arrived).
            return ToolResult(
                partner=partner_id,
                task_id=track.task_id,
                context_id=track.context_id,
                state="working",
                provenance=prov,
            )
        task = track.task
        state = _STATES.get(task.status.state, "working")
        status_text = _texts(task.status.message.parts) if task.status.HasField("message") else []
        texts = list(status_text)
        artifacts = []
        for a in task.artifacts:
            texts += _texts(a.parts)
            artifacts.append(
                {
                    "artifact_id": a.artifact_id,
                    "name": a.name or None,
                    "parts": [_part_summary(p) for p in a.parts],
                }
            )
        question = None
        if state in ("input_required", "auth_required"):
            question = "\n".join(status_text) or None
        return ToolResult(
            partner=partner_id,
            task_id=task.id or track.task_id,
            context_id=task.context_id or track.context_id,
            state=state,
            text="\n".join(texts),
            artifacts=artifacts,
            question=question,
            provenance=prov,
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

    @staticmethod
    def _timeout(limit: float, cc: CallContext) -> float:
        rem = cc.remaining()
        return min(limit, rem if rem is not None else math.inf)

    async def _save_handle(
        self,
        result: ToolResult,
        *,
        inbound_task_id: str | None = None,
        origin: str | None = None,
        new: bool = False,
        state_name: str | None = None,
    ) -> None:
        if self.handles is None or result.task_id is None or result.state == "unavailable":
            return
        if state_name is None:
            return
        try:
            if new:
                await self.handles.record(
                    result.task_id,
                    result.partner,
                    result.context_id,
                    inbound_task_id,
                    origin,
                    state_name,
                )
            else:
                await self.handles.update_state(result.task_id, state_name)
        except Exception:
            logger.exception("could not record outbound handle for partner %s", result.partner)

    @staticmethod
    def _state_name(track: _Track) -> str | None:
        if track.task is not None:
            return TaskState.Name(track.task.status.state)
        if track.task_id is not None:
            return TaskState.Name(TaskState.TASK_STATE_SUBMITTED)
        return None

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
        breaker = self._breaker(partner_id)
        if not breaker.allow():
            return self._unavailable(partner_id, rec, "circuit open")

        generated_context = context_id is None
        ctx_id = context_id or uuid.uuid4().hex
        msg = Message(
            message_id=uuid.uuid4().hex,  # generated once; reused by every retry
            context_id=ctx_id,
            role=Role.ROLE_USER,
        )
        if text or not files and data is None:
            msg.parts.append(Part(text=text))
        if task_id:
            msg.task_id = task_id
        for name, content, media_type in files:
            msg.parts.append(Part(raw=content, filename=name, media_type=media_type))
        if data is not None:
            part = Part()
            part.data.struct_value.update(data)
            msg.parts.append(part)
        msg.metadata.update(cc.to_metadata())
        request = SendMessageRequest(message=msg)
        streaming = rec.agent_card.capabilities.streaming
        if not streaming:
            request.configuration.return_immediately = True  # then poll get_task

        track = _Track(task_id, ctx_id)
        recorded = False

        async def note() -> None:
            nonlocal recorded
            if recorded or track.task_id is None or self.handles is None:
                return
            recorded = True
            res = self._result(partner_id, rec, track)
            await self._save_handle(
                res,
                inbound_task_id=inbound_task_id,
                origin=cc.origin,
                new=True,
                state_name=self._state_name(track),
            )

        deadline = asyncio.get_running_loop().time() + timeout
        try:
            async with self._bulkhead(partner_id).acquire(min(BULKHEAD_WAIT_S, timeout)):
                outcome = await self._drive(
                    client,
                    request,
                    track,
                    breaker,
                    deadline,
                    streaming=streaming,
                    reply=task_id is not None,
                    generated_context=generated_context,
                    note=note,
                )
        except Busy:
            return self._unavailable(partner_id, rec, "busy")
        if outcome is not None:
            if not outcome.startswith("partner error:"):
                return self._unavailable(
                    partner_id, rec, outcome, task_id=track.task_id, context_id=ctx_id
                )
            # The partner answered with a protocol error: the request itself failed.
            if track.task is None:
                return ToolResult(
                    partner=partner_id,
                    task_id=track.task_id,
                    context_id=ctx_id,
                    state="failed",
                    reason=outcome,
                    provenance=self._provenance(partner_id, rec),
                )
            await note()
            res = self._result(partner_id, rec, track)
            res.state, res.reason = "failed", outcome
            await self._save_handle(res, state_name=self._state_name(track))
            return res
        await note()
        result = self._result(partner_id, rec, track)
        await self._save_handle(result, state_name=self._state_name(track))
        return result

    async def _drive(
        self,
        client: Client,
        request: SendMessageRequest,
        track: _Track,
        breaker: CircuitBreaker,
        deadline: float,
        *,
        streaming: bool,
        reply: bool,
        generated_context: bool,
        note,
    ) -> str | None:
        """Send and follow. Returns None on success, or the failure reason."""
        loop = asyncio.get_running_loop()

        async def open_stream():
            agen = client.send_message(request, context=self._ctx(deadline - loop.time()))
            try:
                first = await agen.__anext__()
            except BaseException as e:
                await agen.aclose()
                if isinstance(e, Exception) and _kind(e) == "connect":
                    raise _ConnectFailed from e
                raise
            return agen, first

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
            breaker.record_failure()
            return "partner unreachable"
        except (MissingCredential, InvalidCredential):
            return "credential error"
        except TimeoutError:
            return await self._recover(
                client, track, breaker, deadline, streaming, generated_context, note
            )
        except StopAsyncIteration:
            breaker.record_success()
            return await self._recover(
                client, track, breaker, deadline, streaming, generated_context, note
            )
        except Exception as e:  # noqa: BLE001 - classified by _kind; partner faults never escape
            kind = _kind(e)
            _record(breaker, kind)
            if kind == "transport":
                return await self._recover(
                    client, track, breaker, deadline, streaming, generated_context, note
                )
            if kind == "server":
                return "partner error"
            return f"partner error: {type(e).__name__}"
        breaker.record_success()
        track.apply(first)
        if reply:
            track.mark_stale()
        await note()

        # Phase 2: consume the stream (streaming partners only).
        broken = False
        if streaming and not track.settled:
            try:
                async with asyncio.timeout_at(deadline):
                    async for ev in agen:
                        track.apply(ev)
                        await note()
                        if track.settled:
                            break
            except TimeoutError:
                return None  # still working: the caller gets a handle
            except Exception as e:  # noqa: BLE001 - classified by _kind; partner faults never escape
                kind = _kind(e)
                _record(breaker, kind)
                if kind == "protocol":
                    return f"partner error: {type(e).__name__}"
                broken = True
            finally:
                await agen.aclose()
        else:
            await agen.aclose()

        if track.settled or track.task_id is None:
            return None
        # Phase 3: follow the task until it settles or the deadline passes.
        await self._follow(client, track, breaker, deadline, subscribe=streaming and broken)
        return None

    async def _recover(
        self,
        client: Client,
        track: _Track,
        breaker: CircuitBreaker,
        deadline: float,
        streaming: bool,
        generated_context: bool,
        note,
    ) -> str | None:
        """Ambiguous failure: the message may have been delivered. Find the task; never re-send."""
        if track.task_id is None:
            found = await self._lookup(client, track, generated_context)
            if found is None:
                return "delivery unknown"
            track.set_task(found)
            await note()
        if not track.settled:
            await self._follow(client, track, breaker, deadline, subscribe=streaming)
        return None

    async def _lookup(self, client: Client, track: _Track, generated_context: bool) -> Task | None:
        if not generated_context or track.context_id is None:
            return None  # a shared context could hold other tasks; we cannot tell which
        try:
            async with asyncio.timeout(LOOKUP_TIMEOUT_S):
                page = await client.list_tasks(
                    ListTasksRequest(context_id=track.context_id),
                    context=self._ctx(LOOKUP_TIMEOUT_S),
                )
        except Exception as e:  # noqa: BLE001 - any failure leaves delivery unknown
            logger.warning("task lookup after ambiguous failure failed: %s", type(e).__name__)
            return None
        tasks = [t for t in page.tasks if t.context_id == track.context_id]
        return tasks[0] if tasks else None

    async def _follow(
        self,
        client: Client,
        track: _Track,
        breaker: CircuitBreaker,
        deadline: float,
        *,
        subscribe: bool,
    ) -> None:
        """Re-attach with subscribe (if allowed), else poll get_task, until settled or deadline."""
        assert track.task_id is not None
        loop = asyncio.get_running_loop()
        if subscribe:
            try:
                async with asyncio.timeout_at(deadline):
                    stream = client.subscribe(
                        SubscribeToTaskRequest(id=track.task_id),
                        context=self._ctx(deadline - loop.time()),
                    )
                    try:
                        async for ev in stream:
                            track.apply(ev)
                            if track.settled:
                                break
                    finally:
                        await stream.aclose()
                breaker.record_success()
                if track.settled:
                    return
            except TimeoutError:
                return
            except Exception as e:  # noqa: BLE001 - classified by _kind; partner faults never escape
                _record(breaker, _kind(e))
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
                breaker.record_success()
                track.set_task(task)
                if track.settled:
                    return
            except TimeoutError:
                return
            except Exception as e:  # noqa: BLE001 - classified by _kind; partner faults never escape
                _record(breaker, _kind(e))
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
        breaker = self._breaker(partner_id)
        if not breaker.allow():
            return self._unavailable(partner_id, rec, "circuit open", task_id=task_id)
        token = _caller.set(caller)
        try:
            async with self._bulkhead(partner_id).acquire(min(BULKHEAD_WAIT_S, timeout)):
                async with asyncio.timeout(timeout):
                    task = await self._fetch(client, task_id, timeout, cancel=cancel)
        except Busy:
            return self._unavailable(partner_id, rec, "busy", task_id=task_id)
        except TimeoutError:
            return self._unavailable(partner_id, rec, "timed out", task_id=task_id)
        except (MissingCredential, InvalidCredential):
            return self._unavailable(partner_id, rec, "credential error", task_id=task_id)
        except Exception as e:  # noqa: BLE001 - classified by _kind; partner faults never escape
            kind = _kind(e)
            _record(breaker, kind)
            if kind == "protocol":
                return ToolResult(
                    partner=partner_id,
                    task_id=task_id,
                    state="failed",
                    reason=f"partner error: {type(e).__name__}",
                    provenance=self._provenance(partner_id, rec),
                )
            reason = "partner unreachable" if kind == "connect" else "partner error"
            return self._unavailable(partner_id, rec, reason, task_id=task_id)
        finally:
            _caller.reset(token)
        breaker.record_success()
        track = _Track(task_id, None)
        track.set_task(task)
        result = self._result(partner_id, rec, track)
        await self._save_handle(result, state_name=self._state_name(track))
        return result

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
        """Cancel every non-terminal partner task started for an inbound task."""
        if self.handles is None:
            return 0
        cancelled = 0
        for row in await self.handles.by_inbound(inbound_task_id):
            if row["state"] in _TERMINAL_NAMES:
                continue
            try:
                result = await self.cancel(row["partner_id"], row["task_id"])
            except Exception:
                logger.exception("cancel of partner task failed (partner %s)", row["partner_id"])
                continue
            if result.state == "canceled":
                cancelled += 1
            else:
                logger.warning(
                    "partner %s task not cancelled: %s",
                    row["partner_id"],
                    result.reason or result.state,
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
