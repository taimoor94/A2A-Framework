"""The gateway's connection to its control plane (``control_plane:`` in the config).

``ControlPlaneConnector`` connects out (the control plane never calls the gateway) and does
three things:

- **Desired state.** It holds ``GET {url}/cp/v1/stream?applied=<version>&epoch=<epoch>``
  open (server-sent events: ``hello``, ``state``, ``command``). A ``state`` is applied under
  a lock, partners first, then the policy, and only when every local check passes: each
  partner record through ``PartnerRegistry.apply_remote`` (SSRF on the card's endpoints,
  signature verification for the ``require_signed`` tiers, ``card_hash`` equal to the hash
  of ``card``), the policy through ``parse_policy``, and the document's hash. Anything
  failing rejects the whole state: nothing from it is applied, the previous state stays,
  the rejection is reported (``applied.status = "rejected"``, ``reason`` a dotted field path
  or an error class name) and audited ``cp.reject``. An applied state is saved
  (``a2agw_cp_state.applied_state``), audited ``cp.apply`` (``detail.version``,
  ``detail.hash``) and reported. A state of the epoch already applied with a version not
  above the applied one is ignored; another epoch (the control plane's database was reset or
  replaced) is applied whatever its version.
- **Commands.** Each ``command`` runs the matching ``a2agw.ops.actions`` function as actor
  ``cp:<the command's actor>`` and its result is reported (``done`` or ``failed`` with
  ``{"error": ...}``). A command whose ``expires_at`` has passed (control-plane time, from
  the ``hello`` frame's ``server_time``) is not run: it is reported ``failed`` with
  ``{"error": "expired"}``. Commands are delivered at most once; a result the control plane
  ignores (it expired there meanwhile) counts in its ``dropped``.
- **Reports.** Every ``report_interval_s`` it posts ``/cp/v1/report``: up to
  ``REPORT_EVENTS_MAX`` bus events (from a subscription of ``EVENT_QUEUE_MAX`` events; a
  full queue drops its oldest, counted in ``status()["dropped"]``), the audit rows after
  ``audit_acked_seq`` (ascending, up to ``REPORT_AUDIT_MAX``), command results, the last
  applied or rejected state, and every ``health_interval_s`` health, the metrics snapshot
  and the gateway info (exactly ``{version, agents, base_url}``). ``audit_acked_seq`` moves
  only from the response's ``acked_audit_seq``: rows not acknowledged are sent again (the
  control plane stores them idempotently). A report that fails is sent again, whole.

Fail static: with managed sections, the host's startup calls ``restore`` before it serves.
The last applied state is loaded from ``a2agw_cp_state`` and put in force again (local
checks only, no network), so a gateway restarted while the control plane is down serves its
last partners and policy. With no cached state, managed partners are empty and a managed
policy is a lockdown (a lone deny, rule id ``cp:unconfigured``, audited ``policy.update``),
as is a desired state that assigns no policy (``policy: null``) to a managed policy;
a WARNING in the log and in ``/a2agw/admin/healthz`` says the gateway waits for its first
state. A lost connection changes nothing that is in force.

Connection: through a guarded client (tier ``internal``; with ``tls_ref``, the client
certificate of that ``tls`` entry). A failure retries with jittered exponential back-off
(``BACKOFF_MIN_S`` doubling up to ``BACKOFF_MAX_S``, each delay drawn from its upper half).
Connects and disconnects are audited ``cp.connect`` (coalesced). A 401 stops the connector:
one ERROR names ``token_env``, ``status()["last_error_kind"]`` is ``"unauthorized"``. The
token is read from ``token_env`` at each connect, sent only in the ``Authorization``
header, and never logged.

The database work of each step (applying a state, a report, an audit row) runs as a task
the loops' cancellation cannot interrupt; ``stop`` cancels the loops, then waits for that
work and for running commands, posts one last report (``FINAL_REPORT_S`` at most), all
within ``STOP_TIMEOUT_S``, and cancels what is left.

One gateway per database: ``a2agw_cp_state`` holds this gateway's state under fixed keys.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import httpx
from sqlalchemy import Column, MetaData, String, Table, Text, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from a2agw._ddl import retry_ddl
from a2agw.consult.guarded_net import fixed_tier, guarded_async_client
from a2agw.consult.netguard import UnsafeURL
from a2agw.consult.registry import CardFetchError, ReloadConflict, RemoteStateError
from a2agw.consult.tls import build_async_client
from a2agw.ops import actions
from a2agw.ops.audit import AuditEvent, canonical_json
from a2agw.security.policy import PolicyError, parse_policy, policy_hash
from a2agw.serve.reap import ReapRefused

if TYPE_CHECKING:
    from a2agw.config import ControlPlaneConfig
    from a2agw.ops.bus import GatewayEvent, Subscription
    from a2agw.serve.host import AgentHost

log = logging.getLogger(__name__)

STREAM_PATH = "/cp/v1/stream"
REPORT_PATH = "/cp/v1/report"
EVENT_QUEUE_MAX = 10_000
REPORT_EVENTS_MAX = 500
REPORT_AUDIT_MAX = 500
REPORT_RESULTS_MAX = 100
RESULT_MAX_BYTES = 8192  # a larger command result is reported as {"truncated": true}
BACKOFF_MIN_S = 0.5
BACKOFF_MAX_S = 30.0
CONNECT_TIMEOUT_S = 10.0
STREAM_IDLE_S = 90.0  # no frame (keepalives included) for this long: reconnect
REPORT_TIMEOUT_S = 15.0
STOP_TIMEOUT_S = 5.0
FINAL_REPORT_S = 2.0  # stop: the last report's share of STOP_TIMEOUT_S
CANCEL_WAIT_S = 1.0
COMMAND_CONCURRENCY = 8
APPLIED_PENDING_MAX = 16  # applied / rejected outcomes kept for reporting
ACTOR = "control_plane"  # the actor of state changes this connector makes
LOCKDOWN_RULE_ID = "cp:unconfigured"
LOCKDOWN_POLICY: dict[str, Any] = {
    "version": 1,
    "authz": [{"id": LOCKDOWN_RULE_ID, "principal": "*", "agents": "*", "effect": "deny"}],
}
WAITING_WARNING = "waiting for its first desired state from the control plane"
NO_POLICY_WARNING = (
    "the control plane assigns no policy to this gateway: locked down (every call denied)"
)
APPLIED_KEY = "applied_state"
ACKED_KEY = "audit_acked_seq"
LOCAL_KEY = "partners_local"  # each managed partner's local state (PartnerRegistry.local_state)

Sleep = Callable[[float], Awaitable[None]]

_metadata = MetaData()
CP_STATE = Table(
    "a2agw_cp_state",
    _metadata,
    Column("key", String(64), primary_key=True),
    Column("value_json", Text, nullable=False),
)


class CpStateStore:
    """``a2agw_cp_state(key, value_json)``: this gateway's control-plane state."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def initialize(self) -> None:
        async def create() -> None:
            async with self._engine.begin() as conn:
                await conn.run_sync(_metadata.create_all, checkfirst=True)

        await retry_ddl(create)

    async def get(self, key: str) -> Any:
        async with self._engine.connect() as conn:
            raw = (
                await conn.execute(select(CP_STATE.c.value_json).where(CP_STATE.c.key == key))
            ).scalar_one_or_none()
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    async def set(self, key: str, value: Any) -> None:
        raw = canonical_json(value)
        for _ in range(2):
            async with self._engine.begin() as conn:
                done = await conn.execute(
                    update(CP_STATE).where(CP_STATE.c.key == key).values(value_json=raw)
                )
                if done.rowcount:
                    return
                try:
                    await conn.execute(insert(CP_STATE).values(key=key, value_json=raw))
                    return
                except IntegrityError:  # inserted concurrently: update it
                    pass


class _Rejected(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Halt(Exception):
    """The control plane refused the token: the connector stops."""


class _BadArgs(Exception):
    pass


@dataclass(frozen=True)
class _Applied:
    epoch: str
    version: int
    hash: str


def state_hash(partners: Any, policy: Any) -> str:
    """The control plane's hash of a desired document (SHA-256 of its canonical JSON)."""
    import hashlib

    doc = {"partners": partners, "policy": policy}
    return hashlib.sha256(canonical_json(doc).encode()).hexdigest()


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        f = float(value)
    except OverflowError:
        return None
    return f if math.isfinite(f) else None


async def _frames(response: httpx.Response) -> AsyncIterator[tuple[str, str]]:
    """``(event, data)`` of each server-sent event (comments are skipped)."""
    event, data = "message", list[str]()
    async for line in response.aiter_lines():
        if line == "":
            if data:
                yield event, "\n".join(data)
            event, data = "message", []
        elif line.startswith(":"):
            continue
        else:
            name, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if name == "event":
                event = value
            elif name == "data":
                data.append(value)


def _clip(result: Any) -> Any:
    try:
        size = len(json.dumps(result))
    except (TypeError, ValueError):
        return {"error": "unserializable"}
    return {"truncated": True} if size > RESULT_MAX_BYTES else result


def _arg_str(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value:
        raise _BadArgs(name)
    return value


def _arg_bool(args: dict[str, Any], name: str) -> bool:
    value = args.get(name, False)
    if not isinstance(value, bool):
        raise _BadArgs(name)
    return value


Handler = Callable[["AgentHost", dict[str, Any], str], Coroutine[Any, Any, Any]]


async def _task_cancel(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.cancel_task(
        host, _arg_str(a, "agent_id"), _arg_str(a, "task_id"), actor=actor
    )


async def _task_answer(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    text = a.get("text")
    if not isinstance(text, str):
        raise _BadArgs("text")
    return await actions.answer_task(
        host, _arg_str(a, "agent_id"), _arg_str(a, "task_id"), text, actor=actor
    )


async def _task_get(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.task_detail(
        host, _arg_str(a, "agent_id"), _arg_str(a, "task_id"), actor=actor
    )


async def _partner_refresh(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.refresh_partner(host, _arg_str(a, "id"), actor=actor)


async def _partner_approve(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.approve_partner(
        host, _arg_str(a, "id"), actor=actor, expected_hash=_arg_str(a, "expected_hash")
    )


async def _partner_reject(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.reject_partner(host, _arg_str(a, "id"), actor=actor)


async def _tasks_reap(host: AgentHost, a: dict[str, Any], actor: str) -> Any:
    return await actions.reap(
        host,
        _arg_str(a, "agent_id"),
        actor=actor,
        confirm=_arg_bool(a, "confirm"),
        force=_arg_bool(a, "force"),
    )


COMMANDS: dict[str, Handler] = {
    "task.cancel": _task_cancel,
    "task.answer": _task_answer,
    "task.get": _task_get,
    "partner.refresh": _partner_refresh,
    "partner.approve": _partner_approve,
    "partner.reject": _partner_reject,
    "tasks.reap": _tasks_reap,
}


def _failure(exc: BaseException) -> dict[str, Any]:
    """A command's failure as reported: an error code, and for refusals the reason (ids
    and field names only, as the actions write them)."""
    if isinstance(exc, _BadArgs):
        return {"error": "invalid_args", "detail": str(exc)}
    if isinstance(exc, actions.TaskNotFound | KeyError):
        return {"error": "not_found"}
    if isinstance(exc, actions.TaskConflict):
        return {"error": "conflict", "detail": exc.error}
    if isinstance(exc, ReapRefused):
        return {"error": "refused", "detail": exc.reason}
    if isinstance(exc, CardFetchError | UnsafeURL):
        return {"error": "card", "detail": type(exc).__name__}
    if isinstance(exc, ValueError):
        return {"error": "refused", "detail": str(exc)[:256]}
    return {"error": "internal", "detail": type(exc).__name__}


class ControlPlaneConnector:
    """The connection to the control plane of ``cfg`` for ``host``. Creating it attaches it
    to the host (``host.control_plane``): the host's startup runs ``restore`` before it
    serves and ``start`` at its end, and its shutdown runs ``stop``. ``http`` is the test
    seam (used as given, bypassing the guarded client); ``clock`` (monotonic seconds) and
    ``sleep`` drive every wait."""

    def __init__(
        self,
        host: AgentHost,
        cfg: ControlPlaneConfig,
        *,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.manage = frozenset(cfg.manage)
        if "partners" in self.manage and host.partners.path is not None:
            raise ValueError(
                "a control plane managing partners needs a host without a partners file"
            )
        self.host = host
        self.cfg = cfg
        self.url = cfg.url.rstrip("/")
        self._http = http
        self._own_http: httpx.AsyncClient | None = None
        self._clock = clock
        self._sleep = sleep
        self._rng = random.Random()
        self._lock = asyncio.Lock()
        self._store: CpStateStore | None = None
        self._applied: _Applied | None = None
        self._acked = 0
        self._connected = False
        self._last_error: str | None = None
        self._halted = False
        self._stopping = False
        self._hello_seen = False  # the current stream reached hello
        self._offset: float | None = None  # control-plane time minus our clock, from hello
        self._sub: Subscription | None = None
        self._unsent: list[dict[str, Any]] = []  # events of the report being (re)sent
        self._batch = REPORT_EVENTS_MAX  # halved after a 413, grown back after successes
        self._results: list[dict[str, Any]] = []
        # applied / rejected outcomes not yet reported, oldest first (one per report)
        self._pending_applied: list[dict[str, Any]] = []
        self._last_health: float | None = None
        self._loops: list[asyncio.Task[None]] = []
        self._work: set[asyncio.Task[Any]] = set()
        self._command_gate = asyncio.Semaphore(COMMAND_CONCURRENCY)
        self.waiting_for_state = False
        self.no_policy_assigned = False  # a managed policy of null: locked down
        host.policy_managed = "policy" in self.manage
        self._local_dirty = False
        self._local_task: asyncio.Task[None] | None = None
        if "partners" in self.manage:
            host.partners.add_listener(self._partner_changed)
        host.control_plane = self

    # -- status ----------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        sub = self._sub
        return {
            "connected": self._connected,
            "applied_version": self._applied.version if self._applied is not None else None,
            "last_error_kind": self._last_error,
            "queue": (sub.pending if sub is not None else 0) + len(self._unsent),
            "dropped": sub.dropped if sub is not None else 0,
        }

    @property
    def stopped(self) -> bool:
        """Whether neither loop runs (not started, stopped, or halted by a 401)."""
        return all(t.done() for t in self._loops)

    def health(self) -> dict[str, Any]:
        """``status()`` plus a ``warning`` while no state has been applied yet."""
        out = self.status()
        if self.waiting_for_state:
            out["warning"] = WAITING_WARNING
        elif self.no_policy_assigned:
            out["warning"] = NO_POLICY_WARNING
        return out

    # -- lifecycle -------------------------------------------------------------------------

    async def restore(self) -> None:
        """Before the host serves: create the state table, then put the last applied state
        in force again (local checks only), or, with none, empty managed partners and a
        lockdown policy. Called by the host's startup once its database is open."""
        engine = self.host.engine
        if engine is None:
            raise RuntimeError("host not started")
        store = self._store = CpStateStore(engine)
        await store.initialize()
        acked = await store.get(ACKED_KEY)
        self._acked = acked if type(acked) is int and acked > 0 else 0
        saved = await store.get(APPLIED_KEY)
        local = await store.get(LOCAL_KEY)
        if isinstance(saved, dict):
            try:
                applied = self._parse_frame(saved)
                key_ids = saved.get("key_ids")
                await self._put_in_force(
                    saved,
                    key_ids=key_ids if isinstance(key_ids, dict) else {},
                    local=local if isinstance(local, dict) else {},
                )
            except _Rejected as e:
                log.warning(
                    "control plane: the cached desired state no longer passes the local "
                    "checks (%s); not used",
                    e.reason,
                )
            else:
                self._applied = applied
                return
        if not self.manage:
            return
        if "partners" in self.manage:
            await self.host.partners.apply_remote(
                [], open_handles=self._open_handles(), actor=ACTOR
            )
        if "policy" in self.manage:
            await self._set_policy(LOCKDOWN_POLICY)
        self.waiting_for_state = True
        log.warning(
            "control plane: the gateway is %s; managed partners are empty and a managed "
            "policy denies every call until then",
            WAITING_WARNING,
        )

    async def start(self) -> None:
        """Start the stream and report loops (the host's startup does, at its end)."""
        if self._loops:
            return
        self._stopping = self._halted = False
        _, self._sub = self.host.bus.subscribe_with_replay(0, maxsize=EVENT_QUEUE_MAX)
        if self._http is None:
            self._own_http = self._build_client()
        self._loops = [
            asyncio.create_task(self._stream_loop(), name="a2agw:cp-stream"),
            asyncio.create_task(self._report_loop(), name="a2agw:cp-report"),
        ]

    async def stop(self) -> None:
        """Stop the loops, wait for the work they started (running commands included), then
        post one last report (``FINAL_REPORT_S`` at most) so recent events and results are
        not lost; all within ``STOP_TIMEOUT_S``. What is still running then is cancelled.
        Cancelling ``stop`` itself cancels everything at once (no task is left behind)."""
        self._stopping = True
        loop = asyncio.get_running_loop()
        deadline = loop.time() + STOP_TIMEOUT_S
        loops, self._loops = self._loops, []
        for t in loops:
            t.cancel()
        tracked: list[asyncio.Task[Any]] = [*loops]
        try:
            pending = [*loops, *self._work]
            if pending:
                await asyncio.wait(pending, timeout=max(0.0, STOP_TIMEOUT_S - FINAL_REPORT_S))
            tracked += self._work
            if loops and not self._halted and (self._http or self._own_http) is not None:
                final = asyncio.ensure_future(self._report_once())
                self._track(final)
                tracked.append(final)
                left = min(FINAL_REPORT_S, deadline - loop.time())
                await asyncio.wait([final], timeout=max(0.0, left))
            tracked += self._work
            stragglers = list({t for t in tracked if not t.done()})
            if stragglers:
                log.warning(
                    "control plane: cancelling %d task(s) still running at shutdown",
                    len(stragglers),
                )
                for t in stragglers:
                    t.cancel()
                await asyncio.wait(stragglers, timeout=CANCEL_WAIT_S)
        except asyncio.CancelledError:
            for t in {*tracked, *self._work}:
                t.cancel()
            raise
        finally:
            self._connected = False
            if self._sub is not None:
                self._sub.close()
            if self._own_http is not None:
                own, self._own_http = self._own_http, None
                await own.aclose()

    def _build_client(self) -> httpx.AsyncClient:
        timeout = httpx.Timeout(CONNECT_TIMEOUT_S, read=STREAM_IDLE_S)
        tier = fixed_tier("internal")
        if self.cfg.tls_ref is not None:
            tls = self.host.tls.get(self.cfg.tls_ref)
            if tls is None:
                raise ValueError(f"control_plane.tls_ref {self.cfg.tls_ref!r} is not configured")
            return build_async_client(tls, timeout, tier_for_host=tier)
        return guarded_async_client(tier, timeout=timeout)

    @property
    def http(self) -> httpx.AsyncClient:
        client = self._http or self._own_http
        if client is None:
            raise RuntimeError("connector not started")
        return client

    async def _bg(self, work: Coroutine[Any, Any, Any]) -> Any:
        """Run ``work`` as a tracked task the caller's cancellation does not interrupt."""
        task = asyncio.ensure_future(work)
        self._track(task)
        return await asyncio.shield(task)

    def _track(self, task: asyncio.Task[Any]) -> None:
        self._work.add(task)
        task.add_done_callback(self._done)

    def _done(self, task: asyncio.Task[Any]) -> None:
        self._work.discard(task)
        if not task.cancelled():
            task.exception()  # retrieved: its awaiter (if still there) reports it

    def _token(self) -> str | None:
        value = os.environ.get(self.cfg.token_env)
        return value if value else None

    def _headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _halt(self, kind: str, message: str) -> None:
        """Stop for good (until a restart): one ERROR, ``last_error_kind`` = ``kind``."""
        if not self._halted:
            log.error(message, self.cfg.token_env)
        self._halted = True
        self._last_error = kind
        raise _Halt

    def _unauthorized(self) -> None:
        self._halt(
            "unauthorized",
            "control plane refused the gateway token (401); check the token in environment "
            "variable %s; the connector stopped",
        )

    def _no_token(self) -> None:
        self._halt(
            "no_token",
            "control plane: environment variable %s (the gateway token) is not set; the "
            "connector stopped",
        )

    # -- the stream ------------------------------------------------------------------------

    def _backoff(self, attempt: int) -> float:
        ceiling = min(BACKOFF_MAX_S, BACKOFF_MIN_S * 2 ** min(attempt, 16))
        return self._rng.uniform(ceiling / 2, ceiling)

    async def _stream_loop(self) -> None:
        attempt = 0
        while not (self._stopping or self._halted):
            self._hello_seen = False
            try:
                await self._stream_once()
            except _Halt:
                await self._set_connected(False)
                return
            except Exception as e:  # noqa: BLE001 - any failure: reconnect after a back-off
                self._last_error = type(e).__name__
                if not isinstance(e, httpx.HTTPError):
                    log.warning("control plane: stream failed: %s", self._last_error)
            if self._hello_seen:
                attempt = 0  # it got as far as hello: back-off starts over, however it ended
            await self._set_connected(False)
            await self._sleep(self._backoff(attempt))
            attempt += 1

    async def _stream_once(self) -> bool:
        """One stream connection, until it ends; whether it reached ``hello``."""
        token = self._token()
        if token is None:
            self._no_token()
        assert token is not None
        params = {"applied": "0"}
        if self._applied is not None:
            params = {"applied": str(self._applied.version), "epoch": self._applied.epoch}
        hello = False
        async with self.http.stream(
            "GET", self.url + STREAM_PATH, params=params, headers=self._headers(token)
        ) as r:
            if r.status_code == 401:
                self._unauthorized()
            if r.status_code != 200:
                self._last_error = f"http_{r.status_code}"
                return False
            async for event, raw in _frames(r):
                try:
                    data = json.loads(raw)
                except ValueError:
                    log.warning("control plane: a %s frame is not JSON; ignored", event)
                    continue
                if not isinstance(data, dict):
                    continue
                if event == "hello":
                    self._on_hello(data)
                    hello = self._hello_seen = True
                    await self._set_connected(True)
                elif event == "state":
                    await self._bg(self._apply_state(data))
                elif event == "command":
                    self._start_command(data)
        self._last_error = "stream_ended"
        return hello

    def _on_hello(self, data: dict[str, Any]) -> None:
        server_time = _number(data.get("server_time"))
        if server_time is not None:
            self._offset = server_time - self._clock()

    async def _set_connected(self, connected: bool) -> None:
        if connected == self._connected:
            return
        self._connected = connected
        if connected:
            self._last_error = None
            log.info("control plane: connected to %s", self.url)
        else:
            retry = "" if self._halted else "; retrying"
            log.warning("control plane: disconnected (%s)%s", self._last_error, retry)
        outcome = "connected" if connected else "disconnected"
        detail = {} if connected else {"reason": self._last_error}
        ev = AuditEvent(actor=ACTOR, action="cp.connect", outcome=outcome, detail=detail)
        await self._bg(self._emit(ev, coalesce=outcome))

    async def _emit(self, ev: AuditEvent, *, coalesce: str | None = None) -> None:
        audit = self.host.audit
        if audit is None:
            return
        if coalesce is None:
            await audit.emit(ev)
        else:
            await audit.emit_coalesced(ev, coalesce)

    # -- desired state ---------------------------------------------------------------------

    @staticmethod
    def _parse_frame(data: dict[str, Any]) -> _Applied:
        epoch, version, digest = data.get("epoch"), data.get("version"), data.get("hash")
        if not isinstance(epoch, str) or not epoch or len(epoch) > 64:
            raise _Rejected("epoch")
        if type(version) is not int or version < 0:
            raise _Rejected("version")
        if not isinstance(digest, str) or len(digest) > 128:
            raise _Rejected("hash")
        return _Applied(epoch, version, digest)

    async def _apply_state(self, data: dict[str, Any]) -> None:
        async with self._lock:
            try:
                state = self._parse_frame(data)
            except _Rejected as e:
                log.warning("control plane: a state frame without a valid %s; ignored", e.reason)
                return
            applied = self._applied
            if (
                applied is not None
                and state.epoch == applied.epoch
                and state.version <= applied.version
            ):
                return  # older or the same: already in force
            try:
                if state_hash(data.get("partners"), data.get("policy")) != state.hash:
                    raise _Rejected("hash")
                await self._put_in_force(data)
            except _Rejected as e:
                await self._rejected(state, e.reason)
                return
            await self._save(data)
            self._applied = state
            self.waiting_for_state = False
            await self._emit(
                AuditEvent(
                    actor=ACTOR,
                    action="cp.apply",
                    outcome="applied",
                    detail={"version": state.version, "hash": state.hash},
                )
            )
            self._report_applied(
                {
                    "epoch": state.epoch,
                    "version": state.version,
                    "hash": state.hash,
                    "status": "applied",
                }
            )
            log.info("control plane: applied desired state version %d", state.version)

    def _report_applied(self, outcome: dict[str, Any]) -> None:
        self._pending_applied.append(outcome)
        del self._pending_applied[:-APPLIED_PENDING_MAX]  # the newest are kept

    async def _rejected(self, state: _Applied, reason: str) -> None:
        log.warning(
            "control plane: desired state version %d rejected (%s); the previous state stays",
            state.version,
            reason,
        )
        await self._emit(
            AuditEvent(
                actor=ACTOR,
                action="cp.reject",
                outcome="rejected",
                detail={"version": state.version, "hash": state.hash, "reason": reason},
            ),
            coalesce=f"{state.epoch}:{state.version}:{state.hash}",
        )
        self._report_applied(
            {
                "epoch": state.epoch,
                "version": state.version,
                "hash": state.hash,
                "status": "rejected",
                "reason": reason,
            }
        )

    def _open_handles(self) -> Callable[[list[str]], Awaitable[dict[str, int]]] | None:
        handles = self.host.handles
        return handles.count_open if handles is not None else None

    async def _put_in_force(
        self,
        data: dict[str, Any],
        *,
        key_ids: dict[str, Any] | None = None,
        local: dict[str, Any] | None = None,
    ) -> None:
        """Check, then apply the managed sections of a desired document: partners first,
        then the policy. ``_Rejected`` (nothing applied) when a check fails. ``key_ids``:
        restoring the cached state (local checks only), with ``local``: each partner's saved
        local state (a quarantine, a disable, a pending card survive a restart)."""
        policy_doc = data.get("policy")
        if "policy" in self.manage and policy_doc is not None:
            try:
                parse_policy(policy_doc)
            except PolicyError as e:
                raise _Rejected(",".join(f"policy.{f}" for f in e.fields) or "policy") from None
        if "partners" in self.manage:
            try:
                await self.host.partners.apply_remote(
                    data.get("partners"),
                    key_ids=key_ids,
                    local=local,
                    open_handles=self._open_handles(),
                    actor=ACTOR,
                )
            except RemoteStateError as e:
                raise _Rejected(e.reason) from None
            except ReloadConflict:
                raise _Rejected("ReloadConflict") from None
            if "policy" not in self.manage:
                self.host.warn_unknown_routing_partners()
        if "policy" in self.manage:
            # No policy assigned is not "no policy": the gateway stays locked down.
            self.no_policy_assigned = policy_doc is None
            await self._set_policy(LOCKDOWN_POLICY if policy_doc is None else policy_doc)
            if policy_doc is None:
                log.warning("control plane: %s", NO_POLICY_WARNING)

    async def _set_policy(self, doc: dict[str, Any] | None) -> None:
        """Put ``doc`` in force through ``actions.set_policy`` (``None``: no policy), unless
        the control plane's same document already is."""
        host = self.host
        current = host.policy.policy if host.policy is not None else None
        if host.policy_source == "control_plane":
            same = (
                current is None
                if doc is None
                else current is not None and policy_hash(current) == policy_hash(parse_policy(doc))
            )
            if same:
                return
        await actions.set_policy(host, doc, actor=ACTOR, source="control_plane")

    def _partner_changed(self, rec: Any, event: str) -> None:
        """Registry listener: save the partners' local state soon (one save at a time;
        changes meanwhile are picked up by the running one)."""
        if self._store is None or self._stopping:
            return
        self._local_dirty = True
        if self._local_task is not None and not self._local_task.done():
            return
        try:
            task = asyncio.get_running_loop().create_task(self._save_local())
        except RuntimeError:  # no loop (a change made outside the gateway's loop)
            return
        self._local_task = task
        self._track(task)

    async def _save_local(self) -> None:
        while self._local_dirty and self._store is not None:
            self._local_dirty = False
            await self._store.set(LOCAL_KEY, self.host.partners.local_state())

    async def _save(self, data: dict[str, Any]) -> None:
        assert self._store is not None
        saved = {k: data.get(k) for k in ("epoch", "version", "hash", "partners", "policy")}
        saved["key_ids"] = {r.id: r.signed_key_id for r in self.host.partners.all()}
        await self._store.set(APPLIED_KEY, saved)

    # -- commands --------------------------------------------------------------------------

    def _server_now(self) -> float | None:
        return None if self._offset is None else self._clock() + self._offset

    def _start_command(self, data: dict[str, Any]) -> None:
        cid = data.get("id")
        if not isinstance(cid, str) or not cid:
            log.warning("control plane: a command without an id; ignored")
            return
        task = asyncio.create_task(self._run_command(cid, data), name=f"a2agw:cp-{cid[:24]}")
        self._track(task)

    async def _run_command(self, cid: str, data: dict[str, Any]) -> None:
        kind, args = data.get("kind"), data.get("args")
        expires_at, now = _number(data.get("expires_at")), self._server_now()
        status: Literal["done", "failed"]
        if expires_at is None or now is None or expires_at <= now:
            status, result = "failed", {"error": "expired"}
        elif not isinstance(kind, str) or kind not in COMMANDS:
            status, result = "failed", {"error": "unknown_command"}
        elif not isinstance(args, dict):
            status, result = "failed", {"error": "invalid_args"}
        else:
            who = data.get("actor")
            actor = f"cp:{who}" if isinstance(who, str) and who else f"cp:{cid}"
            async with self._command_gate:
                try:
                    status, result = "done", await COMMANDS[kind](self.host, args, actor)
                except Exception as exc:  # noqa: BLE001 - every failure is reported
                    status, result = "failed", _failure(exc)
                    if result["error"] == "internal":
                        log.warning("control plane: command %s failed: %s", kind, result["detail"])
        self._results.append({"id": cid, "status": status, "result": _clip(result)})

    # -- reports ---------------------------------------------------------------------------

    async def _report_loop(self) -> None:
        failures = 0
        interval = self.cfg.report_interval_s
        while not (self._stopping or self._halted):
            try:
                ok = await self._bg(self._report_once())
            except _Halt:
                return
            except Exception as e:  # noqa: BLE001 - retried after a back-off
                if not isinstance(e, httpx.HTTPError):
                    log.warning("control plane: report failed: %s", type(e).__name__)
                if not self._connected:
                    self._last_error = type(e).__name__
                ok = False
            failures = 0 if ok else failures + 1
            delay = interval if ok else min(BACKOFF_MAX_S, interval * 2 ** min(failures, 16))
            await self._sleep(delay)

    def _event(self, ev: GatewayEvent) -> dict[str, Any]:
        return {"kind": ev.kind, "agent_id": ev.agent_id, "data": ev.data, "ts": ev.ts}

    def _info(self) -> dict[str, Any]:
        from a2agw import __version__

        return {
            "version": __version__,
            "agents": sorted(self.host.specs),
            "base_url": self.host.base_url,
        }

    async def _report_once(self) -> bool:
        """Post one report (nothing when there is nothing to say); whether it went."""
        host, now = self.host, self._clock()
        if self._sub is not None and len(self._unsent) < self._batch:
            self._unsent += [
                self._event(e) for e in self._sub.take(self._batch - len(self._unsent))
            ]
        body: dict[str, Any] = {}
        events = self._unsent[: self._batch]
        if events:
            body["events"] = events
        if host.audit is not None:
            rows, _ = await host.audit.query(
                {},
                limit=min(REPORT_AUDIT_MAX, self._batch),
                cursor=str(self._acked),
                ascending=True,
            )
            if rows:
                body["audit"] = rows
        results = self._results[: min(REPORT_RESULTS_MAX, self._batch)]
        if results:
            body["results"] = results
        applied = self._pending_applied[0] if self._pending_applied else None
        if applied is not None:
            body["applied"] = applied
        health_due = (
            self._last_health is None or now - self._last_health >= self.cfg.health_interval_s
        )
        if health_due:
            body["health"] = {
                "status": "waiting" if self.waiting_for_state else "ok",
                "audit_errors": host.audit.audit_errors if host.audit is not None else 0,
                **self.status(),
            }
            body["metrics"] = await host.metrics.snapshot_with_index(host.index)
            body["info"] = self._info()
        if not body:
            return True
        token = self._token()
        if token is None:
            self._no_token()
        assert token is not None
        r = await self.http.post(
            self.url + REPORT_PATH,
            json=body,
            headers=self._headers(token),
            timeout=REPORT_TIMEOUT_S,
        )
        if r.status_code == 401:
            self._unauthorized()
        if r.status_code == 413:
            self._batch = max(1, self._batch // 2)  # smaller reports until one fits
            self._last_error = "http_413"
            return False
        if r.status_code != 200:
            self._last_error = f"http_{r.status_code}"
            return False
        del self._unsent[: len(events)]
        del self._results[: len(results)]
        if applied is not None and self._pending_applied and self._pending_applied[0] is applied:
            del self._pending_applied[0]
        if health_due:
            self._last_health = now
        self._batch = min(REPORT_EVENTS_MAX, self._batch * 2)
        try:
            acked = r.json().get("acked_audit_seq")
        except (ValueError, AttributeError):
            acked = None
        if type(acked) is int and acked > self._acked:
            self._acked = acked
            if self._store is not None:
                await self._store.set(ACKED_KEY, acked)
        return True
