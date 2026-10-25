"""Inbound A2A push notifications: per-agent config stores and a guarded webhook sender.

A client registers a webhook for one of its tasks (inline in ``SendMessage`` or with
``CreateTaskPushNotificationConfig``). The SDK request handler owns the CRUD, scoped to the
caller by the store's owner resolver, and checks the URL with ``make_push_url_validator`` when
the config is created. ``GuardedPushSender`` then POSTs each task update to the webhooks:

- the URL is checked again before every delivery (DNS may have changed since);
- redirects are never followed, the response body is never read, and each request has a
  total timeout;
- 5xx answers and connect/timeout errors are retried with jittered backoff, 4xx is final;
- deliveries run in the background, in order, on one worker per task, with a bounded backlog.

Logs name the agent and task only: webhook URLs can carry credentials and are never logged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time
import uuid
import warnings
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from a2a.server.models import create_push_notification_config_model
from a2a.server.tasks import (
    DatabasePushNotificationConfigStore,
    PushNotificationConfigStore,
    PushNotificationEvent,
    PushNotificationSender,
)
from a2a.types import TaskPushNotificationConfig
from a2a.utils.proto_utils import to_stream_response
from google.protobuf.json_format import MessageToDict
from sqlalchemy.ext.asyncio import AsyncEngine

from a2agw.consult.netguard import UnsafeURL, check_url
from a2agw.security.cardsign import CardSigner

__all__ = [
    "GuardedPushSender",
    "PushSettings",
    "make_push_url_validator",
    "push_config_store_for",
]

logger = logging.getLogger(__name__)

BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 4.0
MAX_BACKLOG = 100  # queued updates per task; on overflow the oldest is dropped
DRAIN_TIMEOUT_S = 5.0  # host shutdown waits this long for pending deliveries
JWT_TTL_S = 300
# Carries the gateway JWT when the config's own `authentication` already uses Authorization.
JWT_HEADER = "X-A2AGW-Push-JWT"

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
    - ``timeout_s``: per-request timeout. ``max_retries``: attempts in total per delivery.
    - ``jwt_signer``: also send a short-lived JWT signed with the gateway key, so receivers
      can tell the update came from this gateway.
    - ``encryption_key_env``: name of an env var holding a Fernet key; when set, stored
      configs (which hold the client's token and webhook credentials) are encrypted at rest.
    """

    allow_private: bool = False
    timeout_s: float = 10.0
    max_retries: int = 3
    jwt_signer: CardSigner | None = None
    encryption_key_env: str | None = None

    def __post_init__(self) -> None:
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if self.max_retries < 1:
            raise ValueError("max_retries must be at least 1")

    def encryption_key(self) -> bytes | None:
        """The Fernet key from ``encryption_key_env``; ValueError if it is unset or invalid."""
        if self.encryption_key_env is None:
            return None
        raw = os.environ.get(self.encryption_key_env)
        if not raw:
            raise ValueError(f"push encryption key env var {self.encryption_key_env} is not set")
        from cryptography.fernet import Fernet

        try:
            Fernet(raw.encode())
        except (ValueError, TypeError):
            raise ValueError(
                f"push encryption key in {self.encryption_key_env} is not a valid Fernet key"
            ) from None
        return raw.encode()


def make_push_url_validator(allow_private: bool) -> UrlValidator:
    """An SDK ``push_url_validator``: netguard's ``internal`` tier when private webhooks are
    allowed, else ``public``. Returns False for any URL netguard refuses."""
    tier = "internal" if allow_private else "public"

    async def validate(url: str) -> bool:
        try:
            await check_url(url, tier)
        except UnsafeURL:
            return False
        return True

    return validate


def push_config_store_for(
    engine: AsyncEngine, agent_id: str, *, encryption_key: bytes | None = None
) -> DatabasePushNotificationConfigStore:
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
    store = DatabasePushNotificationConfigStore(
        engine, create_table=True, encryption_key=encryption_key
    )
    store.config_model = cached[1]
    return store


class GuardedPushSender(PushNotificationSender):
    """Delivers task updates to the task's webhooks, in the background and in order.

    Implements the SDK's ``PushNotificationSender`` directly rather than subclassing
    ``BasePushNotificationSender``: that class delivers inline, logs webhook URLs and does not
    retry. The payload is the same: the update as a ``StreamResponse`` in JSON.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        config_store: PushNotificationConfigStore,
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
        self._queues: dict[str, deque[dict[str, Any]]] = {}
        self._workers: dict[str, asyncio.Task[None]] = {}
        self._overflowing: set[str] = set()
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
        # Serialized now, so later changes to the event object cannot alter what is sent.
        payload = MessageToDict(to_stream_response(event))
        queue = self._queues.setdefault(task_id, deque())
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
        queue.append(payload)
        if task_id not in self._workers:
            self._workers[task_id] = asyncio.create_task(self._run(task_id, queue))

    async def _run(self, task_id: str, queue: deque[dict[str, Any]]) -> None:
        try:
            while queue:
                payload = queue.popleft()
                try:
                    await self._deliver_all(task_id, payload)
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
        if configs:
            body = json.dumps(payload, separators=(",", ":")).encode()
            await asyncio.gather(*(self._deliver(task_id, c, body) for c in configs))

    async def _url_allowed(self, url: str) -> bool:
        try:
            return bool(await self.validator(url))
        except Exception:  # noqa: BLE001 - fail closed
            return False

    def _headers(self, task_id: str, config: TaskPushNotificationConfig) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
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
                    "jti": uuid.uuid4().hex,
                }
            )
            if "Authorization" in headers:
                headers[JWT_HEADER] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _post(self, url: str, body: bytes, headers: dict[str, str]) -> int:
        """POST once and return the status. The response body is never read (a webhook cannot
        make us buffer anything), and ``timeout_s`` bounds the whole request."""
        async with asyncio.timeout(self.settings.timeout_s):
            async with self.http.stream(
                "POST",
                url,
                content=body,
                headers=headers,
                follow_redirects=False,
                timeout=self.settings.timeout_s,
            ) as resp:
                return resp.status_code

    async def _deliver(self, task_id: str, config: TaskPushNotificationConfig, body: bytes) -> None:
        if not await self._url_allowed(config.url):
            self.stats["skipped_unsafe"] += 1
            logger.warning(
                "push: webhook URL refused, delivery skipped (agent=%s task=%s)",
                self.agent_id,
                task_id,
            )
            return
        attempts = self.settings.max_retries
        outcome = "failed"
        for attempt in range(attempts):
            retryable = False
            try:
                status = await self._post(config.url, body, self._headers(task_id, config))
            except (httpx.ConnectError, httpx.TimeoutException, TimeoutError) as exc:
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
