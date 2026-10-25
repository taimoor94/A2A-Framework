"""Inbound A2A push notifications: guarded, authenticated, retried and owner-scoped delivery.

Webhooks are a real Starlette app on a real uvicorn port, so the gateway's own httpx client
makes real HTTP requests (redirect handling, connect errors and timeouts are not simulated).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt as pyjwt
import pytest
import uvicorn
from a2a.client import ClientConfig, ClientFactory
from a2a.types import (
    AuthenticationInfo,
    DeleteTaskPushNotificationConfigRequest,
    GetTaskPushNotificationConfigRequest,
    ListTaskPushNotificationConfigsRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    Task,
    TaskPushNotificationConfig,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import (
    InvalidParamsError,
    PushNotificationNotSupportedError,
    TaskNotFoundError,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from a2agw.core.events import ArtifactChunk, Done, Status
from a2agw.security.auth import ApiKeyEntry, AuthConfig
from a2agw.security.cardsign import CardSigner
from a2agw.serve import push as push_mod
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost
from a2agw.serve.push import (
    GuardedPushSender,
    PushSettings,
    make_push_url_validator,
    push_config_store_for,
)
from a2agw.serve.store import create_engine

# -- webhook receiver ------------------------------------------------------------------


@dataclass
class Hit:
    path: str
    headers: dict[str, str]
    body: Any


@dataclass
class Receiver:
    port: int = 0
    hits: list[Hit] = field(default_factory=list)
    fail_first: int = 0  # answer 503 to the first N requests
    status: int = 200
    redirect_to: str | None = None
    gate: asyncio.Event | None = None  # when set, requests wait for it
    gate_paths: set[str] | None = None  # None: the gate holds every path

    def url(self, path: str = "/hook") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def app(self) -> Starlette:
        async def handle(request: Request) -> Response:
            body = await request.json()
            self.hits.append(Hit(request.url.path, dict(request.headers), body))
            if self.gate is not None and (
                self.gate_paths is None or request.url.path in self.gate_paths
            ):
                await self.gate.wait()
            if request.url.path == "/hook":
                if self.fail_first > 0:
                    self.fail_first -= 1
                    return JSONResponse({}, status_code=503)
                if self.redirect_to is not None:
                    return Response(status_code=307, headers={"location": self.redirect_to})
            return JSONResponse({}, status_code=self.status)

        return Starlette(routes=[Route("/{p:path}", handle, methods=["POST"])])

    async def wait_for(self, pred, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while not pred(self.hits):
            if time.monotonic() > deadline:
                raise AssertionError(f"timed out; hits={[h.body for h in self.hits]}")
            await asyncio.sleep(0.01)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _serve(app, port: int) -> tuple[uvicorn.Server, asyncio.Task]:
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="off")
    )
    task = asyncio.create_task(server.serve())
    for _ in range(500):
        if server.started:
            break
        await asyncio.sleep(0.01)
    assert server.started
    return server, task


@pytest.fixture
async def receiver():
    rec = Receiver(port=_free_port())
    server, task = await _serve(rec.app(), rec.port)
    yield rec
    if rec.gate is not None:
        rec.gate.set()
    server.should_exit = True
    await asyncio.wait_for(task, 10)


@pytest.fixture(autouse=True)
def _fast_backoff(monkeypatch):
    monkeypatch.setattr(push_mod, "BACKOFF_BASE_S", 0.01)
    monkeypatch.setattr(push_mod, "BACKOFF_CAP_S", 0.02)


# -- host helpers ----------------------------------------------------------------------


class Steps:
    durable_sessions = False

    async def run(self, ctx):
        yield Status("working")
        yield ArtifactChunk([Part(text="partial")])
        yield Done(text="done")


def spec(agent_id: str = "alpha", adapter=None) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test agent",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter or Steps(),
    )


def msg(text: str = "hi") -> Message:
    return Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text=text)])


def key_auth(**keys: str) -> AuthConfig:
    return AuthConfig(
        api_keys={
            hashlib.sha256(secret.encode()).hexdigest(): ApiKeyEntry(principal_id=pid)
            for pid, secret in keys.items()
        }
    )


@pytest.fixture
async def host_env(tmp_path):
    made: list[tuple[AgentHost, list[httpx.AsyncClient]]] = []

    async def _make(*specs: AgentSpec, **kwargs) -> tuple[AgentHost, Any]:
        host = AgentHost(
            "https://gw.example", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", **kwargs
        )
        for s in specs or (spec(),):
            host.add(s)
        await host.startup()
        clients: list[httpx.AsyncClient] = []
        made.append((host, clients))

        def client(agent_id: str = "alpha", **headers: str):
            hc = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=host.app()),
                base_url="http://t",
                headers=headers,
            )
            clients.append(hc)
            return ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
                host.cards[agent_id]
            )

        return host, client

    yield _make
    for host, clients in made:
        for hc in clients:
            await hc.aclose()
        await host.shutdown()


async def send(client, message: Message, push: TaskPushNotificationConfig | None = None):
    req = SendMessageRequest(message=message)
    if push is not None:
        req.configuration.CopyFrom(SendMessageConfiguration(task_push_notification_config=push))
    return [ev async for ev in client.send_message(req)]


def _state(body: dict) -> str | None:
    for key in ("task", "statusUpdate"):
        if key in body:
            return body[key].get("status", {}).get("state")
    return None


def _kinds(hits: list[Hit]) -> list[str]:
    out = []
    for h in hits:
        if "artifactUpdate" in h.body:
            out.append("artifact")
        else:
            out.append(_state(h.body) or "?")
    return out


def _completed(hits: list[Hit]) -> bool:
    return any(_state(h.body) == "TASK_STATE_COMPLETED" for h in hits)


# -- card capability -------------------------------------------------------------------


async def test_card_declares_push_only_when_configured(host_env, tmp_path):
    host, _client = await host_env(push=PushSettings(allow_private=True))
    assert host.cards["alpha"].capabilities.push_notifications is True

    plain = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    plain.add(spec())
    await plain.startup()
    try:
        assert plain.cards["alpha"].capabilities.push_notifications is False
        hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=plain.app()), base_url="http://t")
        c = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            plain.cards["alpha"]
        )
        tid = (await send(c, msg()))[0].task.id
        with pytest.raises(PushNotificationNotSupportedError):
            await c.create_task_push_notification_config(
                TaskPushNotificationConfig(task_id=tid, id="c1", url="https://example.com/h")
            )
        await hc.aclose()
    finally:
        await plain.shutdown()


# -- delivery --------------------------------------------------------------------------


async def test_state_changes_delivered_in_order_with_token(host_env, receiver):
    host, client = await host_env(push=PushSettings(allow_private=True))
    events = await send(
        client(),
        msg(),
        TaskPushNotificationConfig(id="c1", url=receiver.url(), token="tok-123"),
    )
    tid = events[0].task.id
    await receiver.wait_for(_completed)
    assert all(h.headers["x-a2a-notification-token"] == "tok-123" for h in receiver.hits)
    assert all(h.headers["content-type"] == "application/json" for h in receiver.hits)
    assert "authorization" not in receiver.hits[0].headers
    ids = {
        (h.body.get("task") or h.body.get("statusUpdate") or h.body.get("artifactUpdate")).get(
            "taskId", (h.body.get("task") or {}).get("id")
        )
        for h in receiver.hits
    }
    assert ids == {tid}
    kinds = _kinds(receiver.hits)
    # Every update, in the order the task produced it: the new task, the executor's and the
    # adapter's WORKING, the adapter's artifact, Done's result artifact, then COMPLETED.
    assert kinds == [
        "TASK_STATE_SUBMITTED",
        "TASK_STATE_WORKING",
        "TASK_STATE_WORKING",
        "artifact",
        "artifact",
        "TASK_STATE_COMPLETED",
    ]
    artifacts = [
        h.body["artifactUpdate"]["artifact"]["parts"][0]["text"]
        for h in receiver.hits
        if "artifactUpdate" in h.body
    ]
    assert artifacts == ["partial", "done"]
    assert host.push_stats("alpha")["delivered"] == len(receiver.hits)


async def test_config_authentication_sent_as_authorization(host_env, receiver):
    _, client = await host_env(push=PushSettings(allow_private=True))
    cfg = TaskPushNotificationConfig(
        id="c1",
        url=receiver.url(),
        authentication=AuthenticationInfo(scheme="Bearer", credentials="cfg-cred"),
    )
    await send(client(), msg(), cfg)
    await receiver.wait_for(_completed)
    assert receiver.hits[0].headers["authorization"] == "Bearer cfg-cred"


def _ec_signer(tmp_path) -> tuple[CardSigner, Any]:
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "gw.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return CardSigner(path, "gw-key", "ES256"), key.public_key()


async def test_jwt_signer_adds_gateway_jwt(host_env, receiver, tmp_path):
    signer, pub = _ec_signer(tmp_path)
    _, client = await host_env(push=PushSettings(allow_private=True, jwt_signer=signer))
    events = await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    tid = events[0].task.id
    await receiver.wait_for(_completed)
    jtis = set()
    for hit in receiver.hits:
        scheme, _, token = hit.headers["authorization"].partition(" ")
        assert scheme == "Bearer"
        assert pyjwt.get_unverified_header(token)["kid"] == "gw-key"
        claims = pyjwt.decode(token, pub, algorithms=["ES256"], audience=receiver.url())
        assert claims["iss"] == "https://gw.example"
        assert claims["task_id"] == tid
        assert claims["exp"] - claims["iat"] == 300
        assert claims["delivery_id"] == hit.headers["x-a2agw-delivery-id"]
        raw = json.dumps(hit.body, separators=(",", ":")).encode()
        assert claims["body_sha256"] == hashlib.sha256(raw).hexdigest()
        jtis.add(claims["jti"])
    assert len(jtis) == len(receiver.hits)  # a fresh jti per delivery


async def test_jwt_moves_to_own_header_when_config_has_authentication(host_env, receiver, tmp_path):
    signer, pub = _ec_signer(tmp_path)
    _, client = await host_env(push=PushSettings(allow_private=True, jwt_signer=signer))
    cfg = TaskPushNotificationConfig(
        id="c1",
        url=receiver.url(),
        authentication=AuthenticationInfo(scheme="Bearer", credentials="cfg-cred"),
    )
    await send(client(), msg(), cfg)
    await receiver.wait_for(_completed)
    hit = receiver.hits[0]
    assert hit.headers["authorization"] == "Bearer cfg-cred"
    claims = pyjwt.decode(
        hit.headers[push_mod.JWT_HEADER.lower()], pub, algorithms=["ES256"], audience=receiver.url()
    )
    assert claims["iss"] == "https://gw.example"


async def test_receiver_down_at_first_is_retried(host_env, receiver):
    receiver.fail_first = 2
    host, client = await host_env(push=PushSettings(allow_private=True, max_attempts=3))
    await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    await receiver.wait_for(_completed)
    # The first update took three attempts (503, 503, 200); every update got through.
    first = receiver.hits[0].body
    assert [h.body for h in receiver.hits[:3]] == [first, first, first]
    ids = [h.headers["x-a2agw-delivery-id"] for h in receiver.hits]
    assert len(set(ids[:3])) == 1  # one delivery id for every attempt of one update
    assert len(set(ids)) == len(ids) - 2  # and a new one per update
    stats = host.push_stats("alpha")
    assert stats["retries"] == 2 and stats["failed"] == 0


async def test_connection_refused_is_retried_then_given_up(tmp_path):
    port = _free_port()  # nothing listens here
    sender, _store, engine = await _sender(
        tmp_path, f"http://127.0.0.1:{port}/hook", max_attempts=3
    )
    try:
        await sender.send_notification("t1", _task("t1"))
        await sender.drain(5)
        assert sender.stats["failed"] == 1 and sender.stats["retries"] == 2
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_4xx_is_final(host_env, receiver):
    receiver.status = 400
    host, client = await host_env(push=PushSettings(allow_private=True))
    await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    await receiver.wait_for(_completed)
    stats = host.push_stats("alpha")
    assert stats["retries"] == 0 and stats["delivered"] == 0
    assert stats["failed"] == len(receiver.hits)


async def test_redirect_is_not_followed(host_env, receiver):
    # The webhook answers 307 pointing at another address; the gateway must not go there.
    receiver.redirect_to = receiver.url("/target")
    host, client = await host_env(push=PushSettings(allow_private=True))
    await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    await receiver.wait_for(_completed)
    await host.push_senders["alpha"].drain(5)
    assert {h.path for h in receiver.hits} == {"/hook"}
    stats = host.push_stats("alpha")
    assert stats["delivered"] == 0 and stats["retries"] == 0
    assert stats["failed"] == len(receiver.hits)


async def test_private_webhook_rejected_at_config_time(host_env):
    _host, client = await host_env(push=PushSettings())  # allow_private=False
    c = client()
    for url in ("https://127.0.0.1/hook", "https://10.1.2.3/hook", "http://user:pw@x.example/"):
        with pytest.raises(InvalidParamsError):
            await send(c, msg(), TaskPushNotificationConfig(id="c1", url=url))
    tid = (await send(c, msg()))[0].task.id
    with pytest.raises(InvalidParamsError):
        await c.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id="c1", url="https://169.254.169.254/x")
        )


async def test_url_validator_tiers(monkeypatch):
    monkeypatch.delenv("A2AGW_DEV", raising=False)
    public = make_push_url_validator(allow_private=False)
    internal = make_push_url_validator(allow_private=True)
    assert await public("https://127.0.0.1/h") is False
    assert await public("http://93.184.216.34/h") is False  # https required
    assert await public("ftp://x.example/") is False
    assert await internal("http://127.0.0.1:9/h") is True
    assert await internal("http://u:p@127.0.0.1/h") is False  # userinfo never allowed
    assert await internal("not a url") is False


async def test_agent_run_does_not_wait_for_slow_webhook(host_env, receiver):
    receiver.gate = asyncio.Event()  # the webhook hangs until released
    _, client = await host_env(push=PushSettings(allow_private=True))
    started = time.monotonic()
    events = await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    assert time.monotonic() - started < 5.0  # the webhook never answers before the release
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    receiver.gate.set()
    await receiver.wait_for(_completed)


# -- sender-level behaviour ------------------------------------------------------------


def _task(task_id: str, state: TaskState = TaskState.TASK_STATE_WORKING) -> Task:
    return Task(id=task_id, context_id="ctx", status=TaskStatus(state=state))


async def _sender(tmp_path, url: str, *, validator=None, configs=None, **settings):
    """A sender on a fresh store. ``configs`` maps task id -> webhook URLs (default: t1 -> url)."""
    from a2a.server.context import ServerCallContext

    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 's.db'}")
    store = push_config_store_for(engine, "alpha")
    await store.initialize()
    for task_id, urls in (configs or {"t1": [url]}).items():
        for i, u in enumerate(urls):
            await store.set_info(
                task_id, TaskPushNotificationConfig(id=f"c{i}", url=u), ServerCallContext()
            )
    ps = PushSettings(allow_private=True, **settings)
    http = httpx.AsyncClient(follow_redirects=False, timeout=ps.timeout_s)
    sender = GuardedPushSender(
        http,
        store,
        settings=ps,
        agent_id="alpha",
        base_url="https://gw.example",
        validator=validator or make_push_url_validator(True),
    )
    return sender, store, engine


async def test_delivery_rechecks_url_and_never_logs_it(tmp_path, receiver, caplog):
    allowed = True

    async def flip(url: str) -> bool:
        return allowed

    secret_url = receiver.url("/hook") + "?sig=supersecret"
    sender, _, engine = await _sender(tmp_path, secret_url, validator=flip)
    try:
        await sender.send_notification("t1", _task("t1"))
        await sender.drain(5)
        assert sender.stats["delivered"] == 1
        allowed = False  # e.g. DNS now points somewhere private
        with caplog.at_level(logging.DEBUG):
            await sender.send_notification("t1", _task("t1"))
            await sender.drain(5)
        assert sender.stats["skipped_unsafe"] == 1 and len(receiver.hits) == 1
        assert "t1" in caplog.text and "alpha" in caplog.text
        assert "supersecret" not in caplog.text and "127.0.0.1" not in caplog.text
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_validator_exception_fails_closed(tmp_path, receiver):
    async def boom(url: str) -> bool:
        raise RuntimeError("resolver exploded")

    sender, _, engine = await _sender(tmp_path, receiver.url(), validator=boom)
    try:
        await sender.send_notification("t1", _task("t1"))
        await sender.drain(5)
        assert sender.stats["skipped_unsafe"] == 1 and receiver.hits == []
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_backlog_bounded_drops_oldest(tmp_path, receiver, caplog):
    receiver.gate = asyncio.Event()
    sender, _, engine = await _sender(tmp_path, receiver.url())
    try:
        with caplog.at_level(logging.WARNING):
            for i in range(push_mod.MAX_BACKLOG + 30):
                await sender.send_notification("t1", _task("t1"))
                if i == 0:  # let the worker pick up the first update and block on it
                    await receiver.wait_for(lambda hits: len(hits) == 1)
        assert sender.stats["dropped"] == 29  # 1 in flight + 100 queued kept
        assert "dropped" in caplog.text
        receiver.gate.set()
        await sender.drain(10)
        assert sender.stats["delivered"] == push_mod.MAX_BACKLOG + 1
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_drain_is_bounded(tmp_path, receiver):
    receiver.gate = asyncio.Event()  # never released before drain
    sender, _, engine = await _sender(tmp_path, receiver.url())
    try:
        await sender.send_notification("t1", _task("t1"))
        await receiver.wait_for(lambda hits: len(hits) == 1)
        started = time.monotonic()
        await sender.drain(0.2)
        assert time.monotonic() - started < 3.0  # the webhook never answers
        assert sender.pending() == 0
    finally:
        receiver.gate.set()
        await sender.http.aclose()
        await engine.dispose()


async def test_host_shutdown_drains_and_closes_client(tmp_path, receiver):
    host = AgentHost(
        "https://gw.example",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}",
        push=PushSettings(allow_private=True),
    )
    host.add(spec())
    await host.startup()
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    c = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(host.cards["alpha"])
    await send(c, msg(), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    await hc.aclose()
    http = host.push_http
    await host.shutdown()  # pending deliveries are flushed before the engine goes
    assert _completed(receiver.hits)
    assert http is not None and http.is_closed


# -- stores ----------------------------------------------------------------------------


async def test_store_tables_per_agent_and_reusable_across_engines(db_factory):
    from a2a.server.context import ServerCallContext

    ctx = ServerCallContext()
    engines = [await create_engine(db_factory()) for _ in range(2)]
    try:
        for engine in engines:  # same agent id on two engines: no duplicate-table error
            store = push_config_store_for(engine, "my-agent")
            await store.initialize()
            assert store.config_model.__tablename__ == "push_configs_my_agent"
            await store.set_info("t", TaskPushNotificationConfig(id="c", url="https://x/"), ctx)
            assert len(await store.get_info_for_dispatch("t")) == 1
        other = push_config_store_for(engines[0], "other")
        await other.initialize()
        assert await other.get_info_for_dispatch("t") == []
        with pytest.raises(ValueError):
            push_config_store_for(engines[0], "bad name")
    finally:
        for engine in engines:
            await engine.dispose()


async def test_configs_encrypted_at_rest_when_key_configured(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from sqlalchemy import text

    monkeypatch.setenv("PUSH_KEY", Fernet.generate_key().decode())
    host = AgentHost(
        "https://gw.example",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'enc.db'}",
        push=PushSettings(allow_private=True, encryption_key_env="PUSH_KEY"),
    )
    host.add(spec())
    await host.startup()
    hc = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    try:
        c = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(
            host.cards["alpha"]
        )
        tid = (await send(c, msg()))[0].task.id
        url = "https://hook.example/x?sig=abc"
        await c.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id="c1", url=url, token="tk-9")
        )
        got = await c.get_task_push_notification_config(
            GetTaskPushNotificationConfigRequest(task_id=tid, id="c1")
        )
        assert (got.url, got.token) == (url, "tk-9")
        async with host.engine.connect() as conn:
            raw = (await conn.execute(text("SELECT config_data FROM push_configs_alpha"))).scalar()
        assert b"tk-9" not in raw and b"hook.example" not in raw
    finally:
        await hc.aclose()
        await host.shutdown()


async def test_encryption_key_rotation_and_wrong_key(tmp_path, monkeypatch):
    from a2a.server.context import ServerCallContext
    from cryptography.fernet import Fernet

    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    ctx = ServerCallContext()
    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'rot.db'}")

    def store_with(keys: str):
        monkeypatch.setenv("PUSH_KEYS", keys)
        fernet = PushSettings(encryption_key_env="PUSH_KEYS").fernet()
        return push_config_store_for(engine, "rot", fernet=fernet)

    try:
        before = store_with(old)
        await before.initialize()
        await before.set_info("t", TaskPushNotificationConfig(id="a", url="https://x/a"), ctx)
        rotated = store_with(f"{new}, {old}")  # new key first: it encrypts, both decrypt
        assert [c.id for c in await rotated.get_info_for_dispatch("t")] == ["a"]
        await rotated.set_info("t", TaskPushNotificationConfig(id="b", url="https://x/b"), ctx)
        assert {c.id for c in await rotated.get_info_for_dispatch("t")} == {"a", "b"}
        # The old key alone cannot read the row the new key wrote: that config is skipped.
        assert [c.id for c in await store_with(old).get_info_for_dispatch("t")] == ["a"]
        monkeypatch.setenv("PUSH_KEYS", "not-a-key")
        with pytest.raises(ValueError, match="PUSH_KEYS") as exc:
            PushSettings(encryption_key_env="PUSH_KEYS").fernet()
        assert "not-a-key" not in str(exc.value)
    finally:
        await engine.dispose()


async def test_missing_encryption_key_fails_startup(tmp_path, monkeypatch):
    monkeypatch.delenv("NO_SUCH_PUSH_KEY", raising=False)
    host = AgentHost(
        "https://gw.example",
        db_url=f"sqlite+aiosqlite:///{tmp_path / 'x.db'}",
        push=PushSettings(encryption_key_env="NO_SUCH_PUSH_KEY"),
    )
    host.add(spec())
    with pytest.raises(ValueError, match="NO_SUCH_PUSH_KEY"):
        await host.startup()
    assert host.engine is None


# -- owner scoping ---------------------------------------------------------------------


async def test_other_principal_cannot_read_or_delete_config(host_env):
    host, client = await host_env(
        push=PushSettings(allow_private=True), auth=key_auth(a="secret-a", b="secret-b")
    )
    a = client(**{"X-API-Key": "secret-a"})
    b = client(**{"X-API-Key": "secret-b"})
    tid = (await send(a, msg()))[0].task.id
    created = await a.create_task_push_notification_config(
        TaskPushNotificationConfig(task_id=tid, id="c1", url="https://hook.example/x", token="t")
    )
    assert created.id == "c1"

    with pytest.raises(TaskNotFoundError):
        await b.get_task_push_notification_config(
            GetTaskPushNotificationConfigRequest(task_id=tid, id="c1")
        )
    with pytest.raises(TaskNotFoundError):
        await b.list_task_push_notification_configs(
            ListTaskPushNotificationConfigsRequest(task_id=tid)
        )
    with pytest.raises(TaskNotFoundError):
        await b.delete_task_push_notification_config(
            DeleteTaskPushNotificationConfigRequest(task_id=tid, id="c1")
        )
    with pytest.raises(TaskNotFoundError):
        await b.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id="c2", url="https://evil.example/")
        )

    got = await a.get_task_push_notification_config(
        GetTaskPushNotificationConfigRequest(task_id=tid, id="c1")
    )
    assert got.url == "https://hook.example/x"
    listed = await a.list_task_push_notification_configs(
        ListTaskPushNotificationConfigsRequest(task_id=tid)
    )
    assert [c.id for c in listed.configs] == ["c1"]

    # The store itself is owner-scoped too, below the handler's task check.
    from a2a.server.context import ServerCallContext

    from a2agw.security.principal import Principal, PrincipalUser

    store = host.push_stores["alpha"]
    b_ctx = ServerCallContext(user=PrincipalUser(Principal.from_id("key:b")))
    assert await store.get_info(tid, b_ctx) == []
    await store.delete_info(tid, b_ctx, "c1")
    assert len(await store.get_info_for_dispatch(tid)) == 1


async def test_store_with_encryption_and_limits(db_url):
    from a2a.server.context import ServerCallContext
    from cryptography.fernet import Fernet, MultiFernet

    engine = await create_engine(db_url)
    try:
        store = push_config_store_for(
            engine,
            "pg-agent",
            fernet=MultiFernet([Fernet(Fernet.generate_key())]),
            max_configs_per_task=2,
        )
        await store.initialize()
        ctx = ServerCallContext()
        cfg = TaskPushNotificationConfig(id="c", url="https://x.example/h", token="tok")
        await store.set_info("t", cfg, ctx)
        await store.set_info("t", cfg, ctx)  # upsert, not a duplicate
        got = await store.get_info_for_dispatch("t")
        assert [(c.id, c.token) for c in got] == [("c", "tok")]
        await store.delete_info("t", ctx, "c")
        assert await store.get_info("t", ctx) == []
        for i in range(2):
            await store.set_info(
                "lim", TaskPushNotificationConfig(id=f"c{i}", url="https://x/"), ctx
            )
        with pytest.raises(InvalidParamsError, match="too many"):
            await store.set_info("lim", TaskPushNotificationConfig(id="c9", url="https://x/"), ctx)
        assert await store.delete_for_task("lim") == 2
    finally:
        await engine.dispose()


async def test_hanging_webhook_times_out_and_is_retried(tmp_path, receiver):
    receiver.gate = asyncio.Event()  # never answers
    sender, _, engine = await _sender(tmp_path, receiver.url(), timeout_s=0.2, max_attempts=2)
    try:
        started = time.monotonic()
        await sender.send_notification("t1", _task("t1"))
        await receiver.wait_for(lambda hits: len(hits) == 2)
        await sender.drain(5)
        assert time.monotonic() - started < 4.5  # two 0.2 s attempts, not the drain bound
        assert sender.stats == {**sender.stats, "retries": 1, "failed": 1, "delivered": 0}
    finally:
        receiver.gate.set()
        await sender.http.aclose()
        await engine.dispose()


# -- fix round 1: bounds, re-check timeout, cleanup, ids, logging, admin ---------------


class AskOnce:
    """First turn asks for input; the follow-up completes."""

    durable_sessions = False

    async def run(self, ctx):
        from a2agw.core.events import NeedInput

        if ctx.text == "first":
            yield NeedInput("more?")
        else:
            yield Done(text="ok")


async def test_config_limit_per_task_on_both_paths(host_env):
    _, client = await host_env(
        spec("alpha", AskOnce()), push=PushSettings(allow_private=True, max_configs_per_task=3)
    )
    c = client()
    events = await send(c, msg("first"))
    tid = events[0].task.id
    assert events[0].task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    for i in range(3):
        await c.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id=f"c{i}", url=f"https://h.example/{i}")
        )
    with pytest.raises(InvalidParamsError, match="too many push configs"):
        await c.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id="c3", url="https://h.example/3")
        )
    # Replacing an existing config is not a new one.
    await c.create_task_push_notification_config(
        TaskPushNotificationConfig(task_id=tid, id="c1", url="https://h.example/1b")
    )
    # Inline with SendMessage: the same limit.
    follow = msg("second")
    follow.task_id = tid
    with pytest.raises(InvalidParamsError, match="too many push configs"):
        await send(c, follow, TaskPushNotificationConfig(id="c9", url="https://h.example/9"))


async def test_overlong_ids_rejected_before_the_database(host_env, tmp_path):
    from a2a.server.context import ServerCallContext

    host, client = await host_env(push=PushSettings(allow_private=True))
    c = client()
    tid = (await send(c, msg()))[0].task.id
    with pytest.raises(InvalidParamsError, match="config id too long"):
        await c.create_task_push_notification_config(
            TaskPushNotificationConfig(task_id=tid, id="x" * 256, url="https://h.example/")
        )
    store = host.push_stores["alpha"]
    with pytest.raises(InvalidParamsError, match="task id too long"):
        await store.set_info(
            "t" * 37, TaskPushNotificationConfig(id="c", url="https://h/"), ServerCallContext()
        )
    with pytest.raises(InvalidParamsError):
        await store.delete_info("t", ServerCallContext(), "x" * 256)


async def test_slow_webhooks_of_one_task_do_not_starve_another(tmp_path, receiver):
    receiver.gate = asyncio.Event()
    receiver.gate_paths = {"/slow"}
    slow = [receiver.url("/slow") + f"?n={i}" for i in range(10)]
    sender, _, engine = await _sender(
        tmp_path,
        "",
        configs={"t1": slow, "t2": [receiver.url("/hook")]},
        max_concurrent_deliveries=4,
    )
    try:
        await sender.send_notification("t1", _task("t1"))
        await receiver.wait_for(lambda hits: len(hits) >= 2)
        started = time.monotonic()
        await sender.send_notification("t2", _task("t2"))
        await receiver.wait_for(lambda hits: any(h.path == "/hook" for h in hits), timeout=5.0)
        assert time.monotonic() - started < 5.0  # t1's webhooks never answer before the release
        # t1 holds only its share (half of the 4 slots) while its webhooks hang.
        assert sum(h.path == "/slow" for h in receiver.hits) == 2
        receiver.gate.set()
        await sender.drain(5)
        assert sender.stats["delivered"] == 11
    finally:
        receiver.gate.set()
        await sender.http.aclose()
        await engine.dispose()


async def test_pending_tasks_cap_drops_new_tasks(tmp_path, receiver, caplog):
    receiver.gate = asyncio.Event()
    url = receiver.url()
    sender, _, engine = await _sender(
        tmp_path, url, configs={"t1": [url], "t2": [url], "t3": [url]}, max_pending_tasks=2
    )
    try:
        await sender.send_notification("t1", _task("t1"))
        await sender.send_notification("t2", _task("t2"))
        with caplog.at_level(logging.WARNING):
            started = time.monotonic()
            await sender.send_notification("t3", _task("t3"))
            await sender.send_notification("t3", _task("t3"))
            assert time.monotonic() - started < 3.0  # dropped, never waited for
        assert sender.stats["dropped"] == 2
        assert caplog.text.count("too many tasks with pending updates") == 1
        await sender.send_notification("t1", _task("t1"))  # a known task still queues
        receiver.gate.set()
        await sender.drain(5)
        assert sender.stats["delivered"] == 3
        assert {h.body["task"]["id"] for h in receiver.hits} == {"t1", "t2"}
    finally:
        receiver.gate.set()
        await sender.http.aclose()
        await engine.dispose()


async def test_slow_dns_recheck_counts_as_unsafe(tmp_path, monkeypatch, receiver):
    from a2agw.consult import netguard

    async def slow_resolve(host):
        await asyncio.sleep(10)
        return ["93.184.216.34"]

    monkeypatch.delenv("A2AGW_DEV", raising=False)
    monkeypatch.setattr(netguard, "_resolve", slow_resolve)
    sender, _, engine = await _sender(
        tmp_path,
        "https://hook.example/x",
        validator=make_push_url_validator(False),
        timeout_s=0.2,
    )
    try:
        started = time.monotonic()
        await sender.send_notification("t1", _task("t1"))
        await sender.drain(5)
        assert time.monotonic() - started < 4.5  # the 0.2 s re-check timeout, not the 10 s lookup
        assert sender.stats["skipped_unsafe"] == 1 and sender.stats["delivered"] == 0
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_configs_deleted_after_terminal_update(host_env, receiver):
    host, client = await host_env(push=PushSettings(allow_private=True))
    tid = (await send(client(), msg(), TaskPushNotificationConfig(id="c1", url=receiver.url())))[
        0
    ].task.id
    await receiver.wait_for(_completed)
    await host.push_senders["alpha"].drain(5)
    assert await host.push_stores["alpha"].get_info_for_dispatch(tid) == []


async def test_non_terminal_updates_keep_configs(host_env, receiver):
    host, client = await host_env(spec("alpha", AskOnce()), push=PushSettings(allow_private=True))
    tid = (
        await send(client(), msg("first"), TaskPushNotificationConfig(id="c1", url=receiver.url()))
    )[0].task.id
    await receiver.wait_for(
        lambda hits: any(_state(h.body) == "TASK_STATE_INPUT_REQUIRED" for h in hits)
    )
    await host.push_senders["alpha"].drain(5)
    assert len(await host.push_stores["alpha"].get_info_for_dispatch(tid)) == 1


async def test_http_client_logs_never_carry_webhook_urls(tmp_path, receiver, caplog):
    """Push requests are not logged by httpx/httpcore, without touching logger levels: an
    embedding application's own httpx client still logs its requests at INFO."""
    assert logging.getLogger("httpx").level == logging.NOTSET  # importing a2agw changed nothing
    assert logging.getLogger("httpcore").level == logging.NOTSET
    url = receiver.url() + "?sig=supersecret"
    sender, _, engine = await _sender(tmp_path, url)
    await sender.http.aclose()
    sender.http = push_mod.push_http_client(sender.settings, slots=4)  # what AgentHost uses
    try:
        with caplog.at_level(logging.DEBUG):  # root at DEBUG, below INFO even
            await sender.send_notification("t1", _task("t1"))
            await sender.drain(5)
            async with httpx.AsyncClient() as app_client:  # the embedding app's own client
                r = await app_client.post(receiver.url("/app") + "?mine=1", json={})
            assert r.status_code == 200
        assert sender.stats["delivered"] == 1
        assert "supersecret" not in caplog.text
        app_lines = [
            rec for rec in caplog.records if rec.name == "httpx" and rec.levelno == logging.INFO
        ]
        assert len(app_lines) == 1 and "mine=1" in app_lines[0].getMessage()
        assert any(rec.name.startswith("httpcore") for rec in caplog.records)  # app's, DEBUG
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_concurrent_config_creates_respect_the_limit(tmp_path):
    from a2a.server.context import ServerCallContext

    engine = await create_engine(f"sqlite+aiosqlite:///{tmp_path / 'lim.db'}")
    try:
        store = push_config_store_for(engine, "alpha", max_configs_per_task=10)
        await store.initialize()
        ctx = ServerCallContext()
        results = await asyncio.gather(
            *(
                store.set_info(
                    "t1", TaskPushNotificationConfig(id=f"c{i}", url="https://h.example/"), ctx
                )
                for i in range(20)
            ),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) == 10 and all(isinstance(e, InvalidParamsError) for e in errors)
        assert len(await store.get_info_for_dispatch("t1")) == 10
        assert len(store._task_locks) == 0  # no lock kept once the creates are done
    finally:
        await engine.dispose()


async def test_metadata_webhook_refused_even_with_allow_private(tmp_path, monkeypatch):
    """Ruling: cloud metadata addresses are refused on every tier, ``internal`` included."""
    from a2agw.consult import netguard

    validator = make_push_url_validator(True)
    assert not await validator("http://169.254.169.254/latest/meta-data")
    assert not await validator("http://[fd00:ec2::254]/")
    assert await validator("http://10.0.0.5/hook")  # private is still allowed

    async def to_metadata(host):
        return ["169.254.169.254"]

    monkeypatch.setattr(netguard, "_resolve", to_metadata)
    url = "http://meta.internal/hook"  # passes the config-time check (no lookup on internal)
    assert await validator(url)
    sender, _, engine = await _sender(tmp_path, url, max_attempts=3)
    await sender.http.aclose()
    sender.http = push_mod.push_http_client(sender.settings, slots=4)
    try:
        await sender.send_notification("t1", _task("t1"))
        await sender.drain(5)
        # Refused at connect time (UnsafeAddress): permanent, so no retry.
        assert sender.stats["skipped_unsafe"] == 1
        assert sender.stats["retries"] == 0 and sender.stats["failed"] == 0
    finally:
        await sender.http.aclose()
        await engine.dispose()


async def test_admin_push_counters(host_env, receiver):
    auth = AuthConfig(
        api_keys={
            hashlib.sha256(b"adm").hexdigest(): ApiKeyEntry(
                principal_id="ops", scopes=["a2agw:admin"]
            ),
            hashlib.sha256(b"usr").hexdigest(): ApiKeyEntry(principal_id="u"),
        }
    )
    host, client = await host_env(push=PushSettings(allow_private=True), auth=auth)
    await send(
        client(**{"X-API-Key": "usr"}),
        msg(),
        TaskPushNotificationConfig(id="c1", url=receiver.url()),
    )
    await receiver.wait_for(_completed)
    await host.push_senders["alpha"].drain(5)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()), base_url="http://t"
    ) as hc:
        denied = await hc.get("/a2agw/admin/push", headers={"X-API-Key": "usr"})
        assert denied.status_code == 403
        r = await hc.get("/a2agw/admin/push", headers={"X-API-Key": "adm"})
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    counters = body["agents"]["alpha"]
    assert counters["delivered"] == len(receiver.hits) and counters["pending"] == 0
    assert set(counters) == {
        "delivered",
        "failed",
        "retries",
        "skipped_unsafe",
        "dropped",
        "pending",
    }
    assert str(receiver.port) not in r.text
