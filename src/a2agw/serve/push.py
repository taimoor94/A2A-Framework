"""Inbound A2A push notifications: per-agent config stores and a guarded webhook sender.

A client registers a webhook for one of its tasks (inline in ``SendMessage`` or with
``CreateTaskPushNotificationConfig``). The SDK request handler owns the CRUD, scoped to the
caller by the store's owner resolver, and checks the URL with ``make_push_url_validator`` when
the config is created. ``GuardedPushSender`` then POSTs each task update to the webhooks:

- the URL is checked again before every delivery (DNS may have changed since), within
  ``timeout_s``; a check that times out counts as unsafe;
- redirects are never followed, the response body is never read, and each request has a
  total timeout;
- 5xx answers and connect/timeout errors are retried with jittered backoff, 4xx is final;
- deliveries run in the background, in order, on one worker per task, with a bounded backlog
  per task, a bounded number of tasks with pending updates, a global cap on concurrent POSTs
  and a per-task share of it (so one task's slow webhooks cannot take every slot);
- a task has at most ``max_configs_per_task`` webhooks, and its configs are deleted once its
  terminal update has been delivered.

Logs name the agent and task only: webhook URLs can carry credentials and are never logged.
The webhook client is a guarded client, whose requests httpx/httpcore do not log either (a
filter scoped to those requests; no logger level is changed).

Ownership: configs are owner-scoped by the principal id. Without ``AuthConfig`` every caller
is the same ``anonymous`` owner, so anyone who knows a task id can read, replace or delete its
configs; run with auth whenever push is exposed beyond a trusted network.

Receivers. Each request carries:

- ``X-A2A-Notification-Token``: the config's ``token`` (A2A), when set;
- ``Authorization``: the config's ``authentication`` (A2A), when set;
- ``X-A2AGW-Delivery-Id``: one id per update per webhook, the same on every retry attempt.
  Receivers should de-duplicate on it: a retry after a lost 2xx delivers the update twice.
- with ``jwt_signer``: a JWT signed with the gateway key, in ``Authorization: Bearer`` or, when
  the config's ``authentication`` uses that header, in ``X-A2AGW-Push-JWT``. Its JOSE header
  has ``typ: a2agw-push+jwt`` (receivers should require it, so no other token signed with the
  gateway key passes as a push JWT). Claims: ``iss``
  (the host's base URL), ``aud`` (the exact webhook URL, query string included), ``iat``,
  ``exp`` (``iat`` + 300 s), ``task_id``, ``delivery_id``, ``body_sha256`` (hex SHA-256 of the
  exact request body) and ``jti`` (unique per attempt). A receiver should verify the signature
  against the gateway's published key, check ``aud`` equals the URL it is served at, check
  ``exp``, compare ``body_sha256`` with the body it received, and reject a ``jti`` it has seen
  within the token's lifetime (replay).

Encryption at rest (``encryption_key_env``): the env var holds one Fernet key or a comma-
separated list; the first key encrypts and every key decrypts (``MultiFernet``), so keys can be
rotated by prepending the new one. Rows written before encryption was turned on stay readable
but stay plaintext until rewritten. A row no listed key can decrypt (wrong or retired key) is
skipped: its webhook gets no deliveries, and the SDK logs the config id (not its contents).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import time
import uuid
import warnings
import weakref
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from a2a.server.context import ServerCallContext
from a2a.server.models import create_push_notification_config_model
from a2a.server.tasks import (
    DatabasePushNotificationConfigStore,
    PushNotificationEvent,
    PushNotificationSender,
)
from a2a.types import TaskPushNotificationConfig
from a2a.utils.errors import InvalidParamsError
from a2a.utils.proto_utils import to_stream_response
from google.protobuf.json_format import MessageToDict
from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from a2agw.consult.guarded_net import fixed_tier, guarded_async_client, is_unsafe_address
from a2agw.consult.netguard import Tier, UnsafeURL, check_url
from a2agw.security.cardsign import CardSigner

if TYPE_CHECKING:
    from cryptography.fernet import MultiFernet

__all__ = [
    "GatewayPushConfigStore",
    "GuardedPushSender",
    "PushSettings",
    "make_push_url_validator",
    "push_config_store_for",
    "push_http_client",
]

logger = logging.getLogger(__name__)

BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 4.0
MAX_BACKLOG = 100  # queued updates per task; on overflow the oldest is dropped
DRAIN_TIMEOUT_S = 5.0  # host shutdown waits this long for pending deliveries
JWT_TTL_S = 300
PUSH_JWT_TYP = "a2agw-push+jwt"  # JOSE header ``typ`` of push JWTs
# Carries the gateway JWT when the config's own `authentication` already uses Authorization.
JWT_HEADER = "X-A2AGW-Push-JWT"
DELIVERY_ID_HEADER = "X-A2AGW-Delivery-Id"
MAX_TASK_ID_LEN = 36  # the SDK's task_id column is String(36)
MAX_CONFIG_ID_LEN = 255  # and config_id String(255)
_TERMINAL_STATES = frozenset(
    {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"}
)

_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# table name -> (agent id, model). The SDK registers generated models on a process-global
# MetaData, so each table's model is built once per process and shared by every engine.
_MODELS: dict[str, tuple[str, type]] = {}

UrlValidator = Callable[[str], Awaitable[bool]]


@dataclass(frozen=True)
class PushSettings:
    """Turns on push notifications for every agent of an ``AgentHost``.

    - ``allow_private``: accept webhooks on private/loopback addresses and plain http (the
      ``internal`` netguard tier). Off by default: only public https webhooks are accepted.
    - ``timeout_s``: bounds each request and each per-delivery URL re-check.
    - ``max_attempts``: attempts in total per delivery (1 = no retry).
    - ``jwt_signer``: also send a short-lived JWT signed with the gateway key, so receivers
      can tell the update came from this gateway (see the module docstring for the claims).
    - ``encryption_key_env``: name of an env var holding a Fernet key, or a comma-separated
      list of keys (the first encrypts). When set, stored configs, which hold the client's
      token and webhook credentials, are encrypted at rest.
    - ``max_configs_per_task``: webhooks one task may have; one more is InvalidParams.
    - ``max_concurrent_deliveries``: POSTs in flight at once, per agent. One task may use at
      most half of them.
    - ``max_pending_tasks``: tasks with queued updates, per agent. Beyond it, updates for
      further tasks are dropped (counted and logged), never waited for.
    """

    allow_private: bool = False
    timeout_s: float = 10.0
    max_attempts: int = 3
    jwt_signer: CardSigner | None = None
    encryption_key_env: str | None = None
    max_configs_per_task: int = 10
    max_concurrent_deliveries: int = 32
    max_pending_tasks: int = 1000

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        for name in (
            "max_attempts",
            "max_configs_per_task",
            "max_concurrent_deliveries",
            "max_pending_tasks",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")

    @property
    def per_task_concurrency(self) -> int:
        return max(1, self.max_concurrent_deliveries // 2)

    def fernet(self) -> MultiFernet | None:
        """The keys from ``encryption_key_env``; ValueError if it is unset or a key is invalid.
        The error names the variable, never a key."""
        if self.encryption_key_env is None:
            return None
        raw = os.environ.get(self.encryption_key_env, "")
        keys = [k.strip() for k in raw.split(",") if k.strip()]
        if not keys:
            raise ValueError(f"push encryption key env var {self.encryption_key_env} is not set")
        from cryptography.fernet import Fernet, MultiFernet

        try:
            return MultiFernet([Fernet(k.encode()) for k in keys])
        except (ValueError, TypeError):
            raise ValueError(
                f"push encryption keys in {self.encryption_key_env} are not valid Fernet keys"
            ) from None


def push_tier(allow_private: bool) -> Tier:
    return "internal" if allow_private else "public"


def push_http_client(settings: PushSettings, *, slots: int) -> httpx.AsyncClient:
    """The webhook client: a guarded client (``a2agw.consult.guarded_net``) that connects only
    to addresses vetted for the push tier at connect time, so a webhook host re-pointed to a
    private address after the URL check is still refused. ``slots`` sizes its pool."""
    return guarded_async_client(
        fixed_tier(push_tier(settings.allow_private)),
        timeout=settings.timeout_s,
        limits=httpx.Limits(max_connections=slots, max_keepalive_connections=slots),
    )


def make_push_url_validator(allow_private: bool) -> UrlValidator:
    """An SDK ``push_url_validator``: netguard's ``internal`` tier when private webhooks are
    allowed, else ``public``. Returns False for any URL netguard refuses."""
    tier = push_tier(allow_private)

    async def validate(url: str) -> bool:
        try:
            await check_url(url, tier)
        except UnsafeURL:
            return False
        return True

    return validate


def _check_ids(task_id: str, config_id: str | None) -> None:
    if len(task_id) > MAX_TASK_ID_LEN:
        raise InvalidParamsError(message="task id too long")
    if config_id is not None and len(config_id) > MAX_CONFIG_ID_LEN:
        raise InvalidParamsError(message="push config id too long")


class GatewayPushConfigStore(DatabasePushNotificationConfigStore):
    """The SDK's database store plus a per-task config limit, id length checks and an
    owner-independent delete used to clean up after a task ends.

    The handler calls ``set_info`` both for ``CreateTaskPushNotificationConfig`` and for a
    config sent inline with ``SendMessage``, so the limit covers both paths."""

    max_configs_per_task: int = 10

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # One lock per task with a create in progress, so concurrent creates cannot all pass
        # the count before any inserts. Entries vanish once no create holds them. The lock
        # is per process: gateways sharing one database can still race each other.
        self._task_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def _lock_for(self, task_id: str) -> asyncio.Lock:
        lock = self._task_locks.get(task_id)
        if lock is None:
            lock = self._task_locks[task_id] = asyncio.Lock()
        return lock

    async def set_info(
        self,
        task_id: str,
        notification_config: TaskPushNotificationConfig,
        context: ServerCallContext,
    ) -> TaskPushNotificationConfig:
        config_id = notification_config.id or task_id
        _check_ids(task_id, config_id)
        await self._ensure_initialized()
        model = self.config_model
        async with self._lock_for(task_id):
            async with self.async_session_maker() as session:
                others = await session.scalar(
                    select(func.count()).where(
                        and_(model.task_id == task_id, model.config_id != config_id)
                    )
                )
            if (others or 0) >= self.max_configs_per_task:
                raise InvalidParamsError(message="too many push configs for task")
            return await super().set_info(task_id, notification_config, context)

    async def delete_info(
        self, task_id: str, context: ServerCallContext, config_id: str | None = None
    ) -> None:
        _check_ids(task_id, config_id)
        await super().delete_info(task_id, context, config_id)

    async def delete_for_task(self, task_id: str) -> int:
        """Delete every config of a task, whoever owns it (the SDK's ``delete_info`` is
        owner-scoped, and the dispatch path has no caller). Returns the rows deleted."""
        await self._ensure_initialized()
        async with self.async_session_maker.begin() as session:
            result = await session.execute(
                delete(self.config_model).where(self.config_model.task_id == task_id)
            )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]


def push_config_store_for(
    engine: AsyncEngine,
    agent_id: str,
    *,
    fernet: MultiFernet | None = None,
    max_configs_per_task: int = 10,
) -> GatewayPushConfigStore:
    """A push config store backed by this agent's own table, ``push_configs_<agent>``.

    Like ``task_store_for``: each table's model is built once per process and reused on any
    engine. Each call returns a new store."""
    if not _AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(f"invalid agent_id for table name: {agent_id!r}")
    table_name = f"push_configs_{agent_id.replace('-', '_')}"
    cached = _MODELS.get(table_name)
    if cached is not None and cached[0] != agent_id:
        raise ValueError(
            f"agent ids {cached[0]!r} and {agent_id!r} map to the same table {table_name!r}"
        )
    if cached is None:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", message="This declarative base already contains a class"
            )
            model = create_push_notification_config_model(table_name)
        cached = _MODELS[table_name] = (agent_id, model)
    # The default table name makes the SDK reuse its built-in model; we then swap in ours.
    store = GatewayPushConfigStore(engine, create_table=True)
    store.config_model = cached[1]
    # MultiFernet has the Fernet encrypt/decrypt interface the SDK store uses.
    store._fernet = fernet  # type: ignore[assignment]
    store.max_configs_per_task = max_configs_per_task
    return store


@dataclass
class _Update:
    payload: dict[str, Any]
    terminal: bool


def _is_terminal(payload: dict[str, Any]) -> bool:
    for key in ("task", "statusUpdate"):
        if key in payload:
            return payload[key].get("status", {}).get("state") in _TERMINAL_STATES
    return False


class GuardedPushSender(PushNotificationSender):
    """Delivers task updates to the task's webhooks, in the background and in order.

    Implements the SDK's ``PushNotificationSender`` directly rather than subclassing
    ``BasePushNotificationSender``: that class delivers inline, logs webhook URLs and does not
    retry. The payload is the same: the update as a ``StreamResponse`` in JSON.

    ``http`` should come from ``push_http_client`` (what ``AgentHost`` uses), which vets the
    webhook's address again at connect time; any other client is used as given and bypasses
    that guard (the test seam).
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        config_store: GatewayPushConfigStore,
        *,
        settings: PushSettings,
        agent_id: str,
        base_url: str,
        validator: UrlValidator | None = None,
    ) -> None:
        self.http = http
        self.store = config_store
        self.settings = settings
        self.agent_id = agent_id
        self.base_url = base_url
        self.validator = validator or make_push_url_validator(settings.allow_private)
        self.stats: dict[str, int] = {
            "delivered": 0,
            "failed": 0,
            "retries": 0,
            "skipped_unsafe": 0,
            "dropped": 0,
        }
        self._slots = asyncio.Semaphore(settings.max_concurrent_deliveries)
        self._queues: dict[str, deque[_Update]] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._overflowing: set[str] = set()
        self._saturated = False  # max_pending_tasks reached (logged once per episode)
        self._closed = False

    # -- queueing ----------------------------------------------------------------------

    async def send_notification(self, task_id: str, event: PushNotificationEvent) -> None:
        """Queue the update and return at once; the task's worker delivers it."""
        if self._closed:
            self.stats["dropped"] += 1
            logger.warning(
                "push: sender closed, update dropped (agent=%s task=%s)", self.agent_id, task_id
            )
            return
        queue = self._queues.get(task_id)
        if queue is None:
            if len(self._queues) >= self.settings.max_pending_tasks:
                self.stats["dropped"] += 1
                if not self._saturated:
                    self._saturated = True
                    logger.warning(
                        "push: too many tasks with pending updates, update dropped "
                        "(agent=%s task=%s)",
                        self.agent_id,
                        task_id,
                    )
                return
            self._saturated = False
            queue = self._queues[task_id] = deque()
        # Serialized now, so later changes to the event object cannot alter what is sent.
        payload = MessageToDict(to_stream_response(event))
        if len(queue) >= MAX_BACKLOG:
            queue.popleft()
            self.stats["dropped"] += 1
            if task_id not in self._overflowing:
                self._overflowing.add(task_id)
                logger.warning(
                    "push: backlog full, oldest update dropped (agent=%s task=%s)",
                    self.agent_id,
                    task_id,
                )
        queue.append(_Update(payload, _is_terminal(payload)))
        if task_id not in self._workers:
            self._workers[task_id] = asyncio.create_task(self._run(task_id, queue))

    async def _run(self, task_id: str, queue: deque[_Update]) -> None:
        try:
            while queue:
                update = queue.popleft()
                try:
                    await self._deliver_all(task_id, update.payload)
                    if update.terminal:
                        # The task is over: its webhooks get nothing more.
                        await self.store.delete_for_task(task_id)
                except Exception as exc:  # noqa: BLE001 - one bad update must not stop the rest
                    self.stats["failed"] += 1
                    logger.warning(
                        "push: delivery error %s (agent=%s task=%s)",
                        type(exc).__name__,
                        self.agent_id,
                        task_id,
                    )
        except asyncio.CancelledError:
            abandoned = len(queue) + 1
            self.stats["dropped"] += abandoned
            logger.warning(
                "push: %d undelivered update(s) abandoned (agent=%s task=%s)",
                abandoned,
                self.agent_id,
                task_id,
            )
            raise
        finally:
            # No await between the loop's empty check and here, so no update is stranded.
            self._queues.pop(task_id, None)
            self._workers.pop(task_id, None)
            self._overflowing.discard(task_id)

    def pending(self) -> int:
        """Updates queued or in flight."""
        return sum(len(q) for q in self._queues.values()) + len(self._workers)

    def counters(self) -> dict[str, int]:
        """Delivery counters plus the current backlog, for the admin API."""
        return {**self.stats, "pending": self.pending()}

    async def drain(self, timeout: float = DRAIN_TIMEOUT_S) -> None:
        """Wait up to ``timeout`` for every queued update; cancel whatever is left."""
        tasks = list(self._workers.values())
        if not tasks:
            return
        _, still = await asyncio.wait(tasks, timeout=timeout)
        for t in still:
            t.cancel()
        await asyncio.gather(*still, return_exceptions=True)

    async def aclose(self, timeout: float = DRAIN_TIMEOUT_S) -> None:
        """Stop accepting updates and drain. The http client belongs to the caller."""
        self._closed = True
        await self.drain(timeout)

    # -- delivery ----------------------------------------------------------------------

    async def _deliver_all(self, task_id: str, payload: dict[str, Any]) -> None:
        try:
            configs = await self.store.get_info_for_dispatch(task_id)
        except Exception as exc:  # noqa: BLE001 - best effort: never disturb the task
            self.stats["failed"] += 1
            logger.warning(
                "push: cannot read webhook configs, %s (agent=%s task=%s)",
                type(exc).__name__,
                self.agent_id,
                task_id,
            )
            return
        if not configs:
            return
        body = json.dumps(payload, separators=(",", ":")).encode()
        digest = hashlib.sha256(body).hexdigest()
        share = asyncio.Semaphore(self.settings.per_task_concurrency)

        async def one(config: TaskPushNotificationConfig) -> None:
            async with share:
                await self._deliver(task_id, config, body, digest)

        await asyncio.gather(*(one(c) for c in configs))

    async def _url_allowed(self, url: str) -> bool:
        try:
            async with asyncio.timeout(self.settings.timeout_s):
                return bool(await self.validator(url))
        except Exception:  # noqa: BLE001 - fail closed, a slow resolver included
            return False

    def _headers(
        self, task_id: str, config: TaskPushNotificationConfig, delivery_id: str, digest: str
    ) -> dict[str, str]:
        headers = {"Content-Type": "application/json", DELIVERY_ID_HEADER: delivery_id}
        if config.token:
            headers["X-A2A-Notification-Token"] = config.token
        auth = config.authentication
        if config.HasField("authentication") and auth.scheme and auth.credentials:
            # The client's own credentials for its webhook (A2A AuthenticationInfo).
            headers["Authorization"] = f"{auth.scheme} {auth.credentials}"
        signer = self.settings.jwt_signer
        if signer is not None:
            iat = int(time.time())
            token = signer.sign_jwt(
                {
                    "iss": self.base_url,
                    "aud": config.url,
                    "iat": iat,
                    "exp": iat + JWT_TTL_S,
                    "task_id": task_id,
                    "delivery_id": delivery_id,
                    "body_sha256": digest,
                    "jti": uuid.uuid4().hex,
                },
                typ=PUSH_JWT_TYP,
            )
            if "Authorization" in headers:
                headers[JWT_HEADER] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """POST once and return the status. The response body is never read (a webhook cannot
        make us buffer anything), and ``timeout_s`` bounds the whole request."""
        async with (
            self._slots,
            asyncio.timeout(self.settings.timeout_s),
            self.http.stream(
                "POST",
                url,
                content=body,
                headers=headers,
                follow_redirects=False,
                timeout=self.settings.timeout_s,
            ) as resp,
        ):
            return resp.status_code

    async def _deliver(
        self, task_id: str, config: TaskPushNotificationConfig, body: bytes, digest: str
    ) -> None:
        if not await self._url_allowed(config.url):
            self.stats["skipped_unsafe"] += 1
            logger.warning(
                "push: webhook URL refused, delivery skipped (agent=%s task=%s)",
                self.agent_id,
                task_id,
            )
            return
        delivery_id = uuid.uuid4().hex  # the same on every attempt of this delivery
        attempts = self.settings.max_attempts
        outcome = "failed"
        for attempt in range(attempts):
            retryable = False
            headers = self._headers(task_id, config, delivery_id, digest)
            try:
                status = await self._post(config.url, body, headers)
            except (httpx.ConnectError, httpx.TimeoutException, TimeoutError) as exc:
                if is_unsafe_address(exc):
                    # Refused at connect time (DNS now points somewhere unsafe): permanent.
                    self.stats["skipped_unsafe"] += 1
                    logger.warning(
                        "push: webhook address refused, delivery skipped (agent=%s task=%s)",
                        self.agent_id,
                        task_id,
                    )
                    return
                retryable, outcome = True, type(exc).__name__
            except Exception as exc:  # noqa: BLE001 - any other failure is final
                outcome = type(exc).__name__
            else:
                if 200 <= status < 300:
                    self.stats["delivered"] += 1
                    return
                retryable = status >= 500
                outcome = f"status {status}"
            if not retryable or attempt == attempts - 1:
                break
            self.stats["retries"] += 1
            ceiling = min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2**attempt)
            await asyncio.sleep(ceiling / 2 + random.uniform(0, ceiling / 2))
        self.stats["failed"] += 1
        logger.warning(
            "push: delivery failed, %s (agent=%s task=%s)", outcome, self.agent_id, task_id
        )
