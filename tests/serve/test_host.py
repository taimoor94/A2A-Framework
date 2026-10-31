"""AgentHost end to end: routing, auth, limits and restart recovery."""

from __future__ import annotations

import asyncio
import hashlib
import uuid

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import (
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    TaskState,
)
from a2a.utils.errors import (
    ContentTypeNotSupportedError,
    InvalidParamsError,
    TaskNotFoundError,
)

from a2agw.core.events import Done, NeedInput
from a2agw.security.auth import AgentAccess, ApiKeyEntry, AuthConfig
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost


class Echo:
    durable_sessions = False

    async def run(self, ctx):
        yield Done(text=f"echo: {ctx.text}")


class Blocker:
    durable_sessions = False

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def run(self, ctx):
        self.started.set()
        await asyncio.Event().wait()
        yield Done(text="never")


def spec(agent_id: str, adapter=None, **kw) -> AgentSpec:
    return AgentSpec(
        id=agent_id,
        name=agent_id.title(),
        description="Test agent",
        skills=[SkillSpec(id="s", name="S", description="d")],
        adapter=adapter or Echo(),
        **kw,
    )


def msg(text: str = "hi", parts: int = 1) -> Message:
    return Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text=text) for _ in range(parts)],
    )


def key_auth(**keys: str) -> AuthConfig:
    return AuthConfig(
        api_keys={
            hashlib.sha256(secret.encode()).hexdigest(): ApiKeyEntry(principal_id=pid)
            for pid, secret in keys.items()
        }
    )


class Env:
    def __init__(self, tmp_path, *, db_url: str | None = None, **host_kwargs) -> None:
        self.host = AgentHost(
            "http://t",
            db_url=db_url or f"sqlite+aiosqlite:///{tmp_path / 'host.db'}",
            **host_kwargs,
        )
        self._clients: list[httpx.AsyncClient] = []

    async def start(self) -> None:
        await self.host.startup()

    def http(self, *, root_path: str = "", **headers: str) -> httpx.AsyncClient:
        hc = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.host.app(), root_path=root_path),
            base_url="http://t",
            headers=headers,
        )
        self._clients.append(hc)
        return hc

    def client(self, agent_id: str, *, streaming: bool = False, **headers: str):
        hc = self.http(**headers)
        card = self.host.cards[agent_id]
        return ClientFactory(ClientConfig(httpx_client=hc, streaming=streaming)).create(card)

    async def stop(self) -> None:
        for hc in self._clients:
            await hc.aclose()
        await self.host.shutdown()


@pytest.fixture
async def env(tmp_path):
    made: list[Env] = []

    async def _make(*specs: AgentSpec, **host_kwargs) -> Env:
        e = Env(tmp_path, **host_kwargs)
        for s in specs:
            e.host.add(s)
        await e.start()
        made.append(e)
        return e

    yield _make
    for e in made:
        await e.stop()


async def send_one(client, message: Message, **config):
    req = SendMessageRequest(message=message)
    if config:
        req.configuration.CopyFrom(SendMessageConfiguration(**config))
    return [ev async for ev in client.send_message(req)]


def task_id_of(events) -> str:
    return events[0].task.id


async def test_two_agents_isolated_cards_and_rpc(env):
    e = await env(spec("alpha"), spec("beta"))
    hc = e.http()
    for aid in ("alpha", "beta"):
        r = await hc.get(f"/agents/{aid}/.well-known/agent-card.json")
        assert r.status_code == 200 and r.json()["name"] == aid.title()
    events = await send_one(e.client("alpha"), msg("yo"))
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert events[0].task.artifacts[0].parts[0].text == "echo: yo"
    assert (await hc.get("/.well-known/agent-card.json")).status_code == 404
    assert (await hc.post("/agents/nope/", json={})).status_code == 404


async def test_duplicate_and_late_add_rejected(env):
    e = await env(spec("alpha"))
    with pytest.raises(ValueError):
        e.host.add(spec("alpha"))
    e.host.app()
    with pytest.raises(RuntimeError):
        e.host.add(spec("beta"))


async def test_single_agent_root_card(env):
    e = await env(spec("solo"))
    r = await e.http().get("/.well-known/agent-card.json")
    assert r.status_code == 200 and r.json()["name"] == "Solo"


async def test_task_from_agent_a_not_visible_via_agent_b(env):
    e = await env(spec("alpha"), spec("beta"))
    tid = task_id_of(await send_one(e.client("alpha"), msg()))
    with pytest.raises(TaskNotFoundError):
        await e.client("beta").get_task(GetTaskRequest(id=tid))
    assert (await e.client("alpha").get_task(GetTaskRequest(id=tid))).id == tid


async def test_other_principal_cannot_get_task(env):
    e = await env(spec("alpha"), auth=key_auth(a="secret-a", b="secret-b"))
    tid = task_id_of(await send_one(e.client("alpha", **{"X-API-Key": "secret-a"}), msg()))
    got = await e.client("alpha", **{"X-API-Key": "secret-a"}).get_task(GetTaskRequest(id=tid))
    assert got.id == tid
    with pytest.raises(TaskNotFoundError):
        await e.client("alpha", **{"X-API-Key": "secret-b"}).get_task(GetTaskRequest(id=tid))


async def test_unauthenticated_401_and_public_paths(env):
    e = await env(spec("alpha"), auth=key_auth(a="secret-a"))
    hc = e.http()
    assert (await hc.post("/agents/alpha/", json={})).status_code == 401
    assert (await hc.get("/agents/alpha/.well-known/agent-card.json")).status_code == 200
    assert (await hc.get("/.well-known/agent-card.json")).status_code == 200


async def test_forbidden_principal_403(env):
    e = await env(
        spec("alpha", access=AgentAccess(allowed_principals=frozenset({"key:a"}))),
        auth=key_auth(a="secret-a", b="secret-b"),
    )
    r = await e.http(**{"X-API-Key": "secret-b"}).post("/agents/alpha/", json={})
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    events = await send_one(e.client("alpha", **{"X-API-Key": "secret-a"}), msg())
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    # An unknown agent is 404 even when authenticated.
    r = await e.http(**{"X-API-Key": "secret-a"}).post("/agents/zzz/", json={})
    assert r.status_code == 404 and r.json() == {"error": "not found"}


async def test_body_too_large_413(env):
    e = await env(spec("alpha"), max_body_bytes=1000)
    hc = e.http()
    r = await hc.post("/agents/alpha/", content=b"x" * 2000)
    assert r.status_code == 413 and r.json() == {"error": "payload too large"}

    async def chunks():
        for _ in range(4):
            yield b"x" * 500

    r = await hc.post("/agents/alpha/", content=chunks())  # no Content-Length
    assert r.status_code == 413 and r.json() == {"error": "payload too large"}


@pytest.mark.parametrize("streaming", [False, True])
async def test_too_many_parts_invalid_params(env, streaming):
    e = await env(spec("alpha"), max_parts=3)
    client = e.client("alpha", streaming=streaming)
    with pytest.raises(InvalidParamsError, match="too many parts"):
        await send_one(client, msg(parts=4))
    events = await send_one(client, msg(parts=3))
    assert events


async def test_restart_recovers(tmp_path, db_url):
    blocker = Blocker()
    e1 = Env(tmp_path, db_url=db_url)
    e1.host.add(spec("alpha", blocker))
    await e1.start()
    events = await send_one(e1.client("alpha"), msg(), return_immediately=True)
    tid = task_id_of(events)
    await asyncio.wait_for(blocker.started.wait(), 5)
    working = TaskState.Name(TaskState.TASK_STATE_WORKING)
    rows, _ = await e1.host.index.list(agent_id="alpha")
    assert [(r["task_id"], r["state"]) for r in rows] == [(tid, working)]
    await e1.stop()

    e2 = Env(tmp_path, db_url=db_url)
    e2.host.add(spec("alpha"))
    await e2.start()
    try:
        assert e2.host.last_recovery.failed == [tid]
        # Same principal as the original (anonymous, no auth configured).
        got = await e2.client("alpha").get_task(GetTaskRequest(id=tid))
        assert got.status.state == TaskState.TASK_STATE_FAILED
        rows, _ = await e2.host.index.list(agent_id="alpha")
        assert rows[0]["state"] == TaskState.Name(TaskState.TASK_STATE_FAILED)
    finally:
        await e2.stop()


def _restricted(**kw):
    return dict(
        specs=(spec("alpha", access=AgentAccess(allowed_principals=frozenset({"key:a"}))),),
        auth=key_auth(a="secret-a", b="secret-b"),
        **kw,
    )


async def test_root_path_does_not_bypass_authz(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    bad = e.http(root_path="/api", **{"X-API-Key": "secret-b"})
    assert (await bad.post("/api/agents/alpha/", json={})).status_code == 403
    assert (await bad.get("/api/agents/alpha/rest/tasks")).status_code == 403
    good = e.http(root_path="/api", **{"X-API-Key": "secret-a"})
    assert (
        await good.get("/api/agents/alpha/rest/tasks", headers={"A2A-Version": "1.0"})
    ).status_code == 200
    # The card stays public under a root_path too.
    anon = e.http(root_path="/api")
    assert (await anon.get("/api/agents/alpha/.well-known/agent-card.json")).status_code == 200


async def test_rest_binding_forbidden(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    r = await e.http(**{"X-API-Key": "secret-b"}).get("/agents/alpha/rest/tasks")
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}


async def test_healthz_path_exempt_from_auth(tmp_path):
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def health(request):
        return PlainTextResponse("ok")

    e = Env(tmp_path, auth=key_auth(a="secret-a"))
    e.host.add(spec("alpha"))
    e.host.extra_routes.append(Route("/a2agw/admin/healthz", health))
    e.host.extra_routes.append(Route("/a2agw/admin/other", health))
    await e.start()
    try:
        hc = e.http()
        assert (await hc.get("/a2agw/admin/healthz")).text == "ok"
        assert (await hc.get("/a2agw/admin/other")).status_code == 401
    finally:
        await e.stop()


async def test_post_to_card_path_not_exempt(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    hc = e.http()
    for path in ("/agents/alpha/.well-known/agent-card.json", "/.well-known/agent-card.json"):
        assert (await hc.post(path, json={})).status_code in (401, 404, 405)


async def test_unknown_agent_404_json(env):
    kw = _restricted()
    e = await env(*kw.pop("specs"), **kw)
    r = await e.http(**{"X-API-Key": "secret-a"}).post("/agents/zzz/", json={})
    assert r.status_code == 404 and r.json() == {"error": "not found"}


async def test_lying_content_length_413(env):
    e = await env(spec("alpha"), max_body_bytes=1000)

    async def chunks():
        for _ in range(4):
            yield b"x" * 500

    r = await e.http().post("/agents/alpha/", content=chunks(), headers={"Content-Length": "10"})
    assert r.status_code == 413


async def test_add_after_startup_rejected(env):
    e = await env(spec("alpha"))
    with pytest.raises(RuntimeError):
        e.host.add(spec("beta"))


async def test_app_is_cached(env):
    e = await env(spec("alpha"))
    assert e.host.app() is e.host.app()


# -- REST binding conformance (A2A spec 1.0 sections 5.4 and 11.1) -------------------------

REST_HEADERS = {"A2A-Version": "1.0"}


async def _rest_send(hc: httpx.AsyncClient, agent_id: str = "alpha") -> httpx.Response:
    body = {
        "message": {
            "messageId": uuid.uuid4().hex,
            "role": "ROLE_USER",
            "parts": [{"text": "hi"}],
        }
    }
    return await hc.post(f"/agents/{agent_id}/rest/message:send", json=body, headers=REST_HEADERS)


async def test_rest_responses_use_application_json(env):
    e = await env(spec("alpha"))
    r = await _rest_send(e.http())
    assert r.status_code == 200
    assert r.headers["content-type"].split(";")[0] == "application/json"
    assert r.json()["task"]["status"]["state"] == "TASK_STATE_COMPLETED"


async def test_rest_cancel_of_terminal_task_is_409(env):
    e = await env(spec("alpha"))
    hc = e.http()
    tid = (await _rest_send(hc)).json()["task"]["id"]
    r = await hc.post(f"/agents/alpha/rest/tasks/{tid}:cancel", headers=REST_HEADERS)
    assert r.status_code == 409
    assert r.headers["content-type"].split(";")[0] == "application/json"
    err = r.json()["error"]
    assert err["code"] == 409
    assert any(d.get("reason") == "TASK_NOT_CANCELABLE" for d in err["details"])
    assert int(r.headers["content-length"]) == len(r.content)


async def test_rest_other_errors_keep_their_status(env):
    e = await env(spec("alpha"))
    r = await e.http().get("/agents/alpha/rest/tasks/nope", headers=REST_HEADERS)
    assert r.status_code == 404
    assert r.json()["error"]["code"] == 404


async def test_rest_cancel_via_sdk_client_maps_to_not_cancelable(env):
    from a2a.client import ClientConfig as _Config
    from a2a.types import CancelTaskRequest
    from a2a.utils.errors import TaskNotCancelableError

    e = await env(spec("alpha"))
    card = e.host.cards["alpha"]
    client = ClientFactory(
        _Config(httpx_client=e.http(), streaming=False, supported_protocol_bindings=["HTTP+JSON"])
    ).create(card)
    events = await send_one(client, msg())
    with pytest.raises(TaskNotCancelableError):
        await client.cancel_task(CancelTaskRequest(id=task_id_of(events)))


async def test_jsonrpc_errors_unchanged(env):
    e = await env(spec("alpha"))
    hc = e.http()
    tid = (await _rest_send(hc)).json()["task"]["id"]
    body = {"jsonrpc": "2.0", "id": 1, "method": "CancelTask", "params": {"id": tid}}
    r = await hc.post("/agents/alpha/", json=body, headers=REST_HEADERS)
    assert r.status_code == 200
    assert r.json()["error"]["code"] == -32002


async def test_rest_conformance_passes_large_error_bodies_through():
    from starlette.responses import Response

    from a2agw.serve.host import _RestConformance

    big = b'{"error": {"code": 400, "details": [{"reason": "TASK_NOT_CANCELABLE"}]}' + b" " * 70000
    big += b"}"
    app = _RestConformance(Response(big, status_code=400, media_type="application/a2a+json"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as hc:
        r = await hc.get("/")
    assert r.status_code == 400 and r.content == big
    assert r.headers["content-type"].startswith("application/json")


async def test_rest_conformance_leaves_non_json_errors_alone():
    from starlette.responses import PlainTextResponse

    from a2agw.serve.host import _RestConformance

    app = _RestConformance(PlainTextResponse("nope", status_code=400))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as hc:
        r = await hc.get("/")
    assert r.status_code == 400 and r.text == "nope"


async def test_card_cache_control_default_and_override(env):
    e = await env(spec("alpha"))
    hc = e.http()
    for path in ("/.well-known/agent-card.json", "/agents/alpha/.well-known/agent-card.json"):
        r = await hc.get(path)
        assert r.headers["cache-control"] == "public, max-age=300"
    e2 = await env(spec("beta"), card_cache_control=None)
    r = await e2.http().get("/agents/beta/.well-known/agent-card.json")
    assert "cache-control" not in r.headers


async def test_partners_path_accepts_str(tmp_path):
    path = tmp_path / "partners.yaml"
    path.write_text("partners: []\n")
    host = AgentHost(
        "http://t", partners_path=str(path), db_url=f"sqlite+aiosqlite:///{tmp_path}/a.db"
    )
    host.partners.load()  # raised AttributeError when the str was passed through
    assert host.partners.all() == []


def test_run_binds_localhost_by_default(monkeypatch):
    """Finding 3: AgentHost.run() must not expose the host on every interface by default."""
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    host = AgentHost("http://localhost:8000")
    host.run()
    host.run(host="0.0.0.0", port=9000)
    assert calls == [
        {"host": "127.0.0.1", "port": 8000, "timeout_graceful_shutdown": 10},
        {"host": "0.0.0.0", "port": 9000, "timeout_graceful_shutdown": 10},
    ]


def test_run_passes_graceful_timeout(monkeypatch):
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    AgentHost("http://localhost:8000").run(graceful_timeout_s=3.5)
    assert calls[0]["timeout_graceful_shutdown"] == 3.5


async def _exit_signal_with_previous(sig, prev, *, loop=None):
    """Install _on_exit_signal over ``prev`` (bound to ``loop``, default the running one) and
    deliver ``sig`` to it; return (callback ran, exception raised by the handler)."""
    import signal
    from unittest import mock

    from a2agw.serve import host as host_mod

    ran: list[bool] = []
    original = signal.getsignal(sig)
    signal.signal(sig, prev)
    raised: BaseException | None = None
    try:
        target = loop or asyncio.get_running_loop()
        with mock.patch.object(host_mod.asyncio, "get_running_loop", lambda: target):
            ctx = host_mod._on_exit_signal(lambda: ran.append(True))
            ctx.__enter__()
        try:
            try:
                signal.getsignal(sig)(sig, None)
            except BaseException as exc:  # noqa: BLE001
                raised = exc
            await asyncio.sleep(0)
        finally:
            ctx.__exit__(None, None, None)
    finally:
        signal.signal(sig, original)
    return bool(ran), raised


async def test_exit_signal_sigint_over_sig_dfl_raises_keyboard_interrupt():
    import signal

    ran, raised = await _exit_signal_with_previous(signal.SIGINT, signal.SIG_DFL)
    assert ran and isinstance(raised, KeyboardInterrupt)


@pytest.mark.parametrize("sig_name", ["SIGINT", "SIGTERM"])
async def test_exit_signal_over_sig_ign_does_nothing_more(sig_name):
    """SIG_IGN before ours: the streams end, and nothing else happens (no exception, no
    termination)."""
    import signal

    ran, raised = await _exit_signal_with_previous(getattr(signal, sig_name), signal.SIG_IGN)
    assert ran and raised is None


async def test_exit_signal_over_none_previous():
    """``None`` (a handler installed outside Python): SIGINT still raises KeyboardInterrupt,
    any other signal only ends the streams."""
    import signal
    from unittest import mock

    from a2agw.serve import host as host_mod

    for sig, expect in ((signal.SIGINT, KeyboardInterrupt), (signal.SIGTERM, None)):
        real = signal.getsignal

        def fake(s, real=real, sig=sig):
            return None if s == sig else real(s)

        ran: list[bool] = []
        original = signal.getsignal(sig)
        try:
            with mock.patch.object(host_mod.signal, "getsignal", fake):
                ctx = host_mod._on_exit_signal(lambda ran=ran: ran.append(True))
                ctx.__enter__()
            raised = None
            try:
                real(sig)(sig, None)
            except BaseException as exc:  # noqa: BLE001
                raised = exc
            await asyncio.sleep(0)
            ctx.__exit__(None, None, None)
        finally:
            signal.signal(sig, original)
        assert ran
        assert (type(raised) if raised is not None else None) is expect


def test_exit_signal_sigterm_over_sig_dfl_terminates_process(tmp_path):
    """SIGTERM over SIG_DFL keeps its default action: the process dies by SIGTERM (checked
    in a subprocess)."""
    import subprocess
    import sys

    code = (
        "import asyncio, signal\n"
        "from a2agw.serve.host import _on_exit_signal\n"
        "async def main():\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
        "    with _on_exit_signal(lambda: None):\n"
        "        signal.raise_signal(signal.SIGTERM)\n"
        "        await asyncio.sleep(1)\n"
        "    print('survived')\n"
        "asyncio.run(main())\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], check=False, capture_output=True, text=True, timeout=180
    )
    assert out.returncode in (-15, 143), (out.returncode, out.stderr)
    assert "survived" not in out.stdout


async def test_exit_signal_closed_loop_is_ignored():
    """A signal arriving after the loop closed must not raise RuntimeError from the handler."""
    import signal

    seen: list[int] = []
    closed = asyncio.new_event_loop()
    closed.close()
    ran, raised = await _exit_signal_with_previous(
        signal.SIGTERM, lambda s, f: seen.append(s), loop=closed
    )
    assert raised is None and not ran
    assert seen == [signal.SIGTERM]  # the previous handler still ran


async def test_startup_failure_disposes_engine(tmp_path, monkeypatch):
    """Finding 11: a bad partners file must not leak the engine opened before it."""
    from sqlalchemy.ext.asyncio import AsyncEngine

    bad = tmp_path / "partners.yaml"
    bad.write_text("not: a partner list\n")
    disposed: list[AsyncEngine] = []
    real_dispose = AsyncEngine.dispose

    async def dispose(self, *args, **kwargs):
        disposed.append(self)
        return await real_dispose(self, *args, **kwargs)

    monkeypatch.setattr(AsyncEngine, "dispose", dispose)
    host = AgentHost(
        "http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'h.db'}", partners_path=bad
    )
    host.add(spec("alpha"))
    with pytest.raises(ValueError, match="partners"):
        await host.startup()
    assert len(disposed) == 1
    assert host.engine is None and host.client is None


_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "http_proxy", "ALL_PROXY"])
async def test_env_proxy_warned_once_at_startup(tmp_path, monkeypatch, caplog, var):
    import logging

    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(var, "http://user:s3cret@proxy.example:3128")
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}", audit=False)
    host.add(spec("alpha"))
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        await host.startup()
        await host.shutdown()
    lines = [r.getMessage() for r in caplog.records if "proxies" in r.getMessage()]
    assert len(lines) == 1 and var in lines[0] and "ignore" in lines[0]
    assert "s3cret" not in caplog.text and "proxy.example" not in caplog.text


async def test_no_proxy_warning_without_env_proxies(tmp_path, monkeypatch, caplog):
    import logging

    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'p.db'}", audit=False)
    host.add(spec("alpha"))
    with caplog.at_level(logging.WARNING, logger="a2agw.serve.host"):
        await host.startup()
        await host.shutdown()
    assert "prox" not in caplog.text


@pytest.mark.parametrize("streaming", [False, True])
async def test_part_without_content_invalid_params(env, streaming):
    """Spec 8.8: a part with none of text/raw/url/data (empty, or only an unknown field the
    parser dropped) is rejected before the agent runs."""
    e = await env(spec("alpha"))
    client = e.client("alpha", streaming=streaming)
    bad = Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="x"), Part()])
    with pytest.raises(InvalidParamsError, match="unsupported part"):
        await send_one(client, bad)
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert rows == []
    r = await e.http(**{"A2A-Version": "1.0"}).post(
        "/agents/alpha/rest/message:send",
        json={"message": {"messageId": "m1", "role": "ROLE_USER", "parts": [{"video": "x"}]}},
    )
    assert r.status_code == 400


async def test_rest_tenant_path_from_the_card_is_served(env):
    """Spec 8.12: the card's REST interface is ``.../rest`` with ``tenant``; SDK clients call
    ``.../rest/{tenant}/...``, which must reach the agent (as must the bare ``.../rest``)."""
    e = await env(spec("alpha", tenant="acme"))
    card = e.host.cards["alpha"]
    rest_only = type(card)()
    rest_only.CopyFrom(card)
    del rest_only.supported_interfaces[:]
    rest_only.supported_interfaces.extend(
        [i for i in card.supported_interfaces if i.protocol_binding == "HTTP+JSON"]
    )
    paths: list[str] = []

    async def hook(request: httpx.Request) -> None:
        paths.append(request.url.path)

    hc = e.http()
    hc.event_hooks["request"].append(hook)
    config = ClientConfig(
        httpx_client=hc, streaming=False, supported_protocol_bindings=["HTTP+JSON"]
    )
    client = ClientFactory(config).create(rest_only)
    events = await send_one(client, msg())
    assert events[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    assert paths == ["/agents/alpha/rest/acme/message:send"]
    body = {"message": {"messageId": "m2", "role": "ROLE_USER", "parts": [{"text": "x"}]}}
    plain = await e.http(**{"A2A-Version": "1.0"}).post(
        "/agents/alpha/rest/message:send", json=body
    )
    assert plain.status_code == 200


# -- inbound idempotency (spec 8.5) -------------------------------------------------------


class Counting:
    durable_sessions = False

    def __init__(self) -> None:
        self.runs = 0
        self.gate: asyncio.Event | None = None

    async def run(self, ctx):
        self.runs += 1
        if self.gate is not None:
            await self.gate.wait()
        yield Done(text=f"run {self.runs}")


def fixed_msg(mid: str, text: str = "hi") -> Message:
    return Message(message_id=mid, role=Role.ROLE_USER, parts=[Part(text=text)])


async def test_resent_message_returns_the_open_task(env):
    """Spec 8.5: a re-send while the first task is open (here input-required) returns that
    task and does not run the agent again; a different request under the id is a new
    message; once the task has ended, an identical re-send starts a new task."""
    runs: list[str] = []

    class Asker:
        durable_sessions = False

        async def run(self, ctx):
            runs.append(ctx.text)
            if not ctx.resumed:
                yield NeedInput("which one?")
                return
            yield Done(text="ok")

    e = await env(spec("alpha", Asker()))
    client = e.client("alpha")
    [first] = await send_one(client, fixed_msg("m-1"))
    assert first.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    [again] = await send_one(client, fixed_msg("m-1"))
    assert again.task.id == first.task.id and runs == ["hi"]
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert len(rows) == 1
    # The id re-used for a different request is a different message (the A2A TCK does this).
    [other] = await send_one(client, fixed_msg("m-1", "changed text"))
    assert other.task.id != first.task.id and runs == ["hi", "changed text"]
    # Once the task has ended, the id is free: the identical request starts a new task.
    answer = fixed_msg("m-2", "the second")
    answer.task_id, answer.context_id = first.task.id, first.task.context_id
    [done] = await send_one(client, answer)
    assert done.task.status.state == TaskState.TASK_STATE_COMPLETED
    [still] = await send_one(client, fixed_msg("m-1", "changed text"))  # T2 still open
    assert still.task.id == other.task.id and len(runs) == 3
    # T1 is completed: re-sending its first request unchanged now starts a new task.
    [fresh] = await send_one(client, fixed_msg("m-1"))
    assert fresh.task.id not in (first.task.id, other.task.id) and len(runs) == 4


async def test_resent_stream_resubscribes_to_the_running_task(env):
    agent = Counting()
    agent.gate = asyncio.Event()
    e = await env(spec("alpha", agent))
    stream = e.client("alpha", streaming=True)

    async def collect():
        return [
            ev async for ev in stream.send_message(SendMessageRequest(message=fixed_msg("s-1")))
        ]

    first = asyncio.create_task(collect())
    async with asyncio.timeout(5):
        while agent.runs == 0:
            await asyncio.sleep(0.01)
    second = asyncio.create_task(collect())
    await asyncio.sleep(0.2)
    agent.gate.set()
    a, b = await asyncio.wait_for(asyncio.gather(first, second), 10)

    def ids(events):
        return {
            ev.task.id if ev.HasField("task") else ev.status_update.task_id
            for ev in events
            if ev.HasField("task") or ev.HasField("status_update")
        }

    assert ids(a) == ids(b) and len(ids(a)) == 1
    last = b[-1]
    state = last.task.status.state if last.HasField("task") else last.status_update.status.state
    assert state == TaskState.TASK_STATE_COMPLETED
    assert agent.runs == 1
    # Once that task is terminal the id is free again: a new task (the A2A TCK relies on it).
    again = [ev async for ev in stream.send_message(SendMessageRequest(message=fixed_msg("s-1")))]
    assert ids(again).isdisjoint(ids(a)) and agent.runs == 2


async def test_same_message_id_from_another_principal_or_tenant_is_new(env):
    agent = Counting()
    e = await env(spec("alpha", agent), auth=key_auth(a="secret-a", b="secret-b"))
    [a] = await send_one(e.client("alpha", **{"X-API-Key": "secret-a"}), fixed_msg("m-1"))
    [b] = await send_one(e.client("alpha", **{"X-API-Key": "secret-b"}), fixed_msg("m-1"))
    assert a.task.id != b.task.id and agent.runs == 2
    hc = e.http(**{"X-API-Key": "secret-a", "A2A-Version": "1.0"})
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "tenant": "t2",
            "message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "x"}]},
        },
    }
    r = await hc.post("/agents/alpha/", json=body)
    assert r.json()["result"]["task"]["id"] not in (a.task.id, b.task.id)
    assert agent.runs == 3


class DurableAsker:
    durable_sessions = True  # an input-required task survives a restart

    def __init__(self) -> None:
        self.runs = 0

    async def run(self, ctx):
        self.runs += 1
        yield NeedInput("which one?")


async def test_message_ids_survive_a_restart(tmp_path, db_url):
    e1 = Env(tmp_path, db_url=db_url)
    e1.host.add(spec("alpha", DurableAsker()))
    await e1.start()
    [first] = await send_one(e1.client("alpha"), fixed_msg("m-r"))
    assert first.task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED
    await e1.stop()
    agent = DurableAsker()
    e2 = Env(tmp_path, db_url=db_url)
    e2.host.add(spec("alpha", agent))
    await e2.start()
    try:
        assert e2.host.last_recovery.kept == [first.task.id]
        [again] = await send_one(e2.client("alpha"), fixed_msg("m-r"))
        assert again.task.id == first.task.id and agent.runs == 0
    finally:
        await e2.stop()


async def test_direct_reply_message_is_not_remembered(env):
    from a2agw.core.events import Reply

    runs: list[int] = []

    class Replier:
        durable_sessions = False

        async def run(self, ctx):
            runs.append(1)
            yield Reply("hello")

    e = await env(spec("alpha", Replier(), direct_replies=True))
    for _ in range(2):
        [ev] = await send_one(e.client("alpha"), fixed_msg("m-d"))
        assert ev.HasField("message")
    assert len(runs) == 2  # no task to point a re-send at: it runs again


# -- media types against input modes (spec 8.8) -------------------------------------------


async def test_concurrent_resends_after_the_task_ended_run_once(env):
    """N identical re-sends racing after the first task ended: exactly one takes the id
    over and runs; every caller gets that one new task."""
    agent = Counting()
    e = await env(spec("alpha", agent))
    [first] = await send_one(e.client("alpha"), fixed_msg("m-c"))
    assert first.task.status.state == TaskState.TASK_STATE_COMPLETED
    agent.gate = asyncio.Event()  # hold the new run so all re-sends overlap it
    sends = [asyncio.create_task(send_one(e.client("alpha"), fixed_msg("m-c"))) for _ in range(8)]
    await asyncio.sleep(0.3)
    agent.gate.set()
    results = await asyncio.wait_for(asyncio.gather(*sends), 15)
    ids = {r[0].task.id for r in results}
    assert len(ids) == 1 and first.task.id not in ids
    assert agent.runs == 2
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert len(rows) == 2


@pytest.mark.parametrize("auth", [False, True])
async def test_resent_stream_of_an_interrupted_task_returns_its_snapshot(env, auth):
    from a2agw.core.events import NeedAuth

    runs: list[int] = []

    class Stops:
        durable_sessions = False

        async def run(self, ctx):
            runs.append(1)
            yield NeedAuth(scheme="oauth2") if auth else NeedInput("which one?")

    e = await env(spec("alpha", Stops()))
    stream = e.client("alpha", streaming=True)

    async def collect():
        req = SendMessageRequest(message=fixed_msg("s-i"))
        return [ev async for ev in stream.send_message(req)]

    first = await asyncio.wait_for(collect(), 10)
    task_id = first[0].task.id
    [again] = await asyncio.wait_for(collect(), 5)  # ends: no waiting for the next turn
    expected = TaskState.TASK_STATE_AUTH_REQUIRED if auth else TaskState.TASK_STATE_INPUT_REQUIRED
    assert again.task.id == task_id and again.task.status.state == expected
    assert runs == [1]


def test_media_type_matching():
    from a2agw.serve.host import media_type_accepted

    for malformed in ("text", "text/", "/plain", "a/b/c", "   ", "text /plain", "*/*", "text/*"):
        assert not media_type_accepted(malformed, ["text/*"]), malformed
        assert not media_type_accepted(malformed, None), malformed

    assert media_type_accepted("image/png", ["image/*"])
    assert media_type_accepted("IMAGE/PNG; q=1", ["image/png"])
    assert media_type_accepted("video/mp4", ["*/*"])
    assert media_type_accepted("anything/x", None)
    assert not media_type_accepted("image/png", ["text/plain", "application/json"])
    assert not media_type_accepted("imagex/png", ["image/*"])


def test_accepted_modes_union_of_skills_with_fallback():
    from a2agw.serve.host import accepted_input_modes

    s = spec("alpha", input_modes=["text/plain"])
    s.skills.append(SkillSpec(id="img", name="Img", description="d", input_modes=["image/*"]))
    assert accepted_input_modes(s) == ["text/plain", "image/*"]
    s.skills.append(SkillSpec(id="any", name="Any", description="d", input_modes=[]))
    assert accepted_input_modes(s) is None  # an empty list accepts all


@pytest.mark.parametrize("streaming", [False, True])
async def test_part_media_type_checked_against_input_modes(env, streaming):
    e = await env(spec("alpha"))  # default modes: text/plain, application/json
    client = e.client("alpha", streaming=streaming)
    ok = Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(text="x")],
    )
    from google.protobuf.json_format import ParseDict

    ok.parts.append(ParseDict({"data": {"k": 1}}, Part()))
    assert await send_one(client, ok)
    for part, shown in (
        (Part(raw=b"\x89PNG", media_type="image/png", filename="a.png"), "image/png"),
        (Part(raw=b"MZ", filename="a.exe"), "application/octet-stream"),
        (Part(url="https://x.example/a.pdf", media_type="application/pdf"), "application/pdf"),
        (Part(text="x", media_type="text/html"), "text/html"),
    ):
        bad = Message(
            message_id=uuid.uuid4().hex, role=Role.ROLE_USER, parts=[Part(text="x"), part]
        )
        with pytest.raises(
            ContentTypeNotSupportedError, match=f"media type {shown} is not accepted"
        ):
            await send_one(client, bad)
    rows, _ = await e.host.index.list(agent_id="alpha")
    assert len(rows) == 1


async def test_skill_input_modes_widen_what_is_accepted(env):
    s = spec("alpha")
    s.skills.append(SkillSpec(id="img", name="Img", description="d", input_modes=["image/*"]))
    e = await env(s)
    msg_ = Message(
        message_id=uuid.uuid4().hex,
        role=Role.ROLE_USER,
        parts=[Part(raw=b"\x89PNG", media_type="image/png", filename="a.png")],
    )
    [ev] = await send_one(e.client("alpha"), msg_)
    assert ev.task.status.state == TaskState.TASK_STATE_COMPLETED


async def test_v03_request_keeps_the_a2a_error_code(env):
    """0.3 compat: an A2A error from the handler keeps its JSON-RPC code (the SDK would
    turn it into -32603)."""
    e = await env(spec("alpha"), max_parts=1)
    hc = e.http(**{"A2A-Version": "0.3"})

    async def error_of(parts):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "kind": "message",
                    "messageId": uuid.uuid4().hex,
                    "role": "user",
                    "parts": parts,
                }
            },
        }
        return (await hc.post("/agents/alpha/", json=body)).json()["error"]

    err = await error_of([{"kind": "file", "file": {"bytes": "aGk=", "mimeType": "image/png"}}])
    assert err["code"] == -32005 and "image/png" in err["message"]
    err = await error_of([{"kind": "text", "text": "a"}, {"kind": "text", "text": "b"}])
    assert err["code"] == -32602 and err["message"] == "too many parts"


# -- live policy and the partner.state / security.denied events ---------------------------

LOCKDOWN = {
    "version": 1,
    "authz": [{"id": "lock", "principal": "*", "agents": ["alpha"], "effect": "deny"}],
}


def _policy(doc):
    from a2agw.security.policy import Policy

    return Policy.model_validate(doc)


async def _audit_rows(host, action):
    await host.audit.drain()
    rows, _ = await host.audit.query({"action": action})
    return rows


async def test_set_policy_swaps_live_and_audits(env):
    from a2agw.security.policy import PolicyEngine

    engine = PolicyEngine(_policy({"version": 1}))
    e = await env(spec("alpha"), auth=key_auth(a="secret-a"), policy=engine)
    hc = e.http(**{"X-API-Key": "secret-a"})
    client = e.client("alpha", **{"X-API-Key": "secret-a"})
    assert (await send_one(client, msg()))[0].task.status.state == TaskState.TASK_STATE_COMPLETED

    e.host.set_policy(_policy(LOCKDOWN), actor="key:ops", source="admin")
    assert e.host.policy is engine  # swapped on the shared engine
    assert engine.policy.authz[0].id == "lock"
    r = await hc.post("/agents/alpha/", json={})
    assert r.status_code == 403  # the mounted authorizer sees the new policy at once

    e.host.set_policy(_policy({"version": 1}), actor="cp", source="control_plane")
    assert (await send_one(client, msg()))[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    rows = await _audit_rows(e.host, "policy.update")
    assert [(r["actor"], r["detail"]["reason"]) for r in rows] == [
        ("cp", "control_plane"),
        ("key:ops", "admin"),
    ]
    assert all(len(r["detail"]["hash"]) == 64 for r in rows)


async def test_set_policy_none_restores_open(env):
    e = await env(spec("alpha"), auth=key_auth(a="secret-a"))
    assert e.host.policy is None
    hc = e.http(**{"X-API-Key": "secret-a"})
    client = e.client("alpha", **{"X-API-Key": "secret-a"})
    # No policy at startup: setting one creates the engine every consumer then uses.
    e.host.set_policy(_policy(LOCKDOWN), actor="key:ops", source="file")
    assert e.host.policy is not None
    assert (await hc.post("/agents/alpha/", json={})).status_code == 403
    assert e.host.executors["alpha"].policy is e.host.policy
    assert e.host.client.policy is e.host.policy

    e.host.set_policy(None, actor="key:ops", source="admin")
    assert e.host.policy is None
    assert e.host.executors["alpha"].policy is None and e.host.client.policy is None
    assert (await send_one(client, msg()))[0].task.status.state == TaskState.TASK_STATE_COMPLETED
    rows = await _audit_rows(e.host, "policy.update")
    assert [(r["outcome"], r["detail"]["reason"]) for r in rows] == [
        ("cleared", "admin"),
        ("applied", "file"),
    ]


async def test_partner_state_and_security_denied_are_published(env):
    from google.protobuf.json_format import MessageToDict

    e = await env(spec("alpha"), auth=key_auth(a="secret-a", b="secret-b"))
    _, sub = e.host.bus.subscribe_with_replay(0)
    card = MessageToDict(e.host.cards["alpha"])
    await e.host.partners.add_from_card("p1", card, "internal")
    e.host.partners.disable("p1")

    e.host.set_policy(_policy(LOCKDOWN), actor="key:ops", source="admin")
    r = await e.http(**{"X-API-Key": "secret-b"}).post("/agents/alpha/", json={"m": "hello"})
    assert r.status_code == 403
    await e.host.audit.drain()

    got = []
    async with sub:
        while len(got) < 3:
            got.append(await asyncio.wait_for(sub.__anext__(), 5))
    assert [(ev.kind, ev.data) for ev in got[:2]] == [
        ("partner.state", {"partner_id": "p1", "status": "active", "event": "added"}),
        ("partner.state", {"partner_id": "p1", "status": "disabled", "event": "disabled"}),
    ]
    denied = got[2]
    assert denied.kind == "security.denied" and denied.agent_id == "alpha"
    assert denied.data == {"reason": "denied by rule", "rule": "lock", "principal_kind": "api_key"}
    text = repr(denied)
    assert "key:b" not in text and "secret-b" not in text and "hello" not in text


async def test_security_denied_published_with_audit_disabled(env):
    e = await env(spec("alpha"), auth=key_auth(b="secret-b"), audit=False)
    assert e.host.audit is None
    _, sub = e.host.bus.subscribe_with_replay(0)
    e.host.set_policy(_policy(LOCKDOWN), actor="key:ops", source="admin")
    hc = e.http(**{"X-API-Key": "secret-b"})
    for _ in range(3):  # never coalesced on the bus
        assert (await hc.post("/agents/alpha/", json={})).status_code == 403
    got = []
    async with sub:
        while len(got) < 3:
            got.append(await asyncio.wait_for(sub.__anext__(), 5))
    assert [(ev.kind, ev.agent_id, ev.data) for ev in got] == [
        (
            "security.denied",
            "alpha",
            {"reason": "denied by rule", "rule": "lock", "principal_kind": "api_key"},
        )
    ] * 3


async def test_security_denied_bus_events_are_not_coalesced(env):
    """Anonymous refusals are coalesced in the audit log, never on the (bounded) bus."""
    auth = key_auth(b="secret-b").model_copy(update={"allow_anonymous": True})
    e = await env(spec("alpha"), auth=auth)
    _, sub = e.host.bus.subscribe_with_replay(0)
    hc = e.http()
    for _ in range(3):
        assert (await hc.post("/agents/alpha/", json={})).status_code == 403
    got = []
    async with sub:
        while len(got) < 3:
            got.append(await asyncio.wait_for(sub.__anext__(), 5))
    assert [ev.data for ev in got] == [
        {"reason": "agent access: authentication required", "principal_kind": "anonymous"}
    ] * 3
    await e.host.audit.drain()
    rows, _ = await e.host.audit.query({"action": "authz.deny"})
    assert len(rows) == 1  # coalesced
