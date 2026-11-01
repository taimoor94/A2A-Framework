"""The VSC host attachment: the ``deliver`` agent over A2A, the admin API, the plain gateway."""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest
from a2a.client import ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

from a2agw.config import build_host, load_config
from a2agw.security.auth import ApiKeyEntry, AuthConfig, hash_api_key
from a2agw.serve.host import AgentHost
from a2agw.vsc.config import VscConfig, WorkerConfig
from a2agw.vsc.host import VscRuntime, attach_vsc

from .conftest import make_repo, worker
from .test_runner import REPO_FILES, FixedPlanner, edit, git, merge_step, sys_cfg, until

KEYS = {"vsc": ["a2agw:vsc"], "admin": ["a2agw:admin"], "user": []}
ADMIN = "/a2agw/admin/vsc"
WRITE = {"X-A2AGW-Admin": "1"}


def _auth() -> AuthConfig:
    return AuthConfig(
        api_keys={
            hash_api_key(f"key-{name}"): ApiKeyEntry(principal_id=name, scopes=scopes)
            for name, scopes in KEYS.items()
        }
    )


def _headers(name: str, **extra: str) -> dict[str, str]:
    return {"X-API-Key": f"key-{name}", **extra}


def _cfg(tmp_path) -> VscConfig:
    repo = make_repo(tmp_path, "repo-a", REPO_FILES)
    w = worker("apply")
    return VscConfig(
        systems=[sys_cfg("alpha", repo)],
        workers=[WorkerConfig(id=w.id, command=w.command, cost_class="cheap")],
        planner="scripted",
        workspace_dir="ws",
    )


@asynccontextmanager
async def _gateway(tmp_path):
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'g.db'}", auth=_auth())
    cfg = _cfg(tmp_path)
    runtime = attach_vsc(host, cfg, tmp_path)
    await host.startup()
    await runtime.resumed  # jobs the test creates are its own
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=host.app()), base_url="http://t")
    try:
        yield host, runtime, http
    finally:
        await http.aclose()
        await host.shutdown()


def _request(files: dict[str, str] | None = None) -> str:
    files = files or {"greet.py": "def hello():\n    return 'hi'\n"}
    return "add the greeting\n---FILES---\n" + json.dumps({"files": files})


async def _send(host, text: str, *, context_id: str, task_id: str = "", key: str = "vsc"):
    http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=host.app()),
        base_url="http://t",
        headers=_headers(key),
        timeout=60,
    )
    try:
        client = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(
            host.cards["deliver"]
        )
        msg = Message(
            message_id=uuid.uuid4().hex,
            context_id=context_id,
            task_id=task_id,
            role=Role.ROLE_USER,
            parts=[Part(text=text)],
        )
        events = [ev async for ev in client.send_message(SendMessageRequest(message=msg))]
    finally:
        await http.aclose()
    [ev] = events
    return ev.task


def _status_text(task) -> str:
    return "".join(p.text for p in task.status.message.parts)


def _result_text(task) -> str:
    return "".join(p.text for a in task.artifacts for p in a.parts)


async def test_submit_via_a2a_creates_job_in_context(tmp_path):
    async with _gateway(tmp_path) as (host, runtime, http):
        assert {"deliver", "vsc-planner"} <= set(host.specs)
        task = await _send(host, _request(), context_id="ctx-1")
        assert task.status.state == TaskState.TASK_STATE_COMPLETED, task
        job = await runtime.store.job_for_context("ctx-1")
        assert job is not None and job["owner"] == "key:vsc"
        assert job["state"] == "accepted"
        assert _result_text(task) == f"job {job['job_id']} accepted"
        assert job["current_task_id"] == task.id

        async def receipt_built() -> bool:  # by on_accepted, right after the job is accepted
            return await runtime.store.get_receipt(job["job_id"]) is not None

        await until(receipt_built)

        # Another message in the job's context answers with the job's state; no new job.
        again = await _send(host, "how is it going?", context_id="ctx-1")
        assert again.status.state == TaskState.TASK_STATE_COMPLETED
        assert f"job {job['job_id']}: accepted" in _status_text(again)
        assert len(await runtime.store.list_jobs()) == 1

        # The job is visible over the admin API, receipt included.
        r = await http.get(f"{ADMIN}/jobs/{job['job_id']}", headers=_headers("vsc"))
        assert r.status_code == 200 and r.json()["state"] == "accepted"
        assert [s["step_id"] for s in r.json()["steps"]] == ["edit-alpha"]
        r = await http.get(f"{ADMIN}/jobs/{job['job_id']}/receipt", headers=_headers("vsc"))
        assert r.status_code == 200 and r.json()["job_id"] == job["job_id"]


async def test_deliver_needs_vsc_scope(tmp_path):
    async with _gateway(tmp_path) as (host, runtime, _):
        task = await _send(host, _request(), context_id="ctx-x", key="user")
        assert task.status.state == TaskState.TASK_STATE_FAILED
        assert await runtime.store.list_jobs() == []


async def test_approval_over_a2a_resumes_the_task(tmp_path):
    async with _gateway(tmp_path) as (host, runtime, _):
        runtime.planner_factory = lambda job_id: FixedPlanner([edit("alpha"), merge_step()])
        task = await _send(host, "greet", context_id="ctx-2")
        assert task.status.state == TaskState.TASK_STATE_INPUT_REQUIRED, task
        assert "merge-alpha" in _status_text(task)
        job = await runtime.store.job_for_context("ctx-2")
        assert job["state"] == "awaiting_approval"
        # Someone else in the job's context cannot approve.
        other = await _send(host, "approve", context_id="ctx-2", key="admin")
        assert other.status.state == TaskState.TASK_STATE_FAILED
        assert (await runtime.store.get_job(job["job_id"]))["state"] == "awaiting_approval"

        done = await _send(host, "approve", context_id="ctx-2", task_id=task.id)
        assert done.status.state == TaskState.TASK_STATE_COMPLETED, done
        assert _result_text(done) == f"job {job['job_id']} accepted"
        repo = tmp_path / "repo-a"
        assert git(repo, "rev-parse", "main") == git(
            repo, "rev-parse", f"vsc/{job['job_id']}/repo-a"
        )


async def test_admin_jobs_requires_scope(tmp_path):
    async with _gateway(tmp_path) as (host, _runtime, http):
        assert (await http.get(f"{ADMIN}/jobs")).status_code == 401
        assert (await http.get(f"{ADMIN}/jobs", headers=_headers("user"))).status_code == 403
        for key in ("vsc", "admin"):
            r = await http.get(f"{ADMIN}/jobs", headers=_headers(key))
            assert r.status_code == 200 and r.json() == {"jobs": []}
        # The generic admin API still needs the admin scope: a2agw:vsc does not imply it.
        assert (await http.get("/a2agw/admin/agents", headers=_headers("vsc"))).status_code == 403
        await host.audit.drain()
        rows, _ = await host.audit.query({"action": "authz.deny"})
        assert any(r["detail"].get("reason") == "admin vsc.jobs" for r in rows)


async def test_admin_approve_needs_admin_header(tmp_path):
    async with _gateway(tmp_path) as (_host, runtime, http):
        runtime.planner_factory = lambda job_id: FixedPlanner([edit("alpha"), merge_step()])
        r = await http.post(f"{ADMIN}/jobs", json={"request": "greet"}, headers=_headers("vsc"))
        assert r.status_code == 403
        r = await http.post(
            f"{ADMIN}/jobs", json={"request": "greet"}, headers=_headers("vsc", **WRITE)
        )
        assert r.status_code == 201, r.text
        job_id = r.json()["job_id"]

        async def waiting() -> bool:
            return (await runtime.store.get_job(job_id))["state"] == "awaiting_approval"

        await until(waiting)
        body = {"step_id": "merge-alpha", "note": "ok"}
        url = f"{ADMIN}/jobs/{job_id}/approve"
        assert (await http.post(url, json=body, headers=_headers("vsc"))).status_code == 403
        assert (await runtime.store.get_job(job_id))["state"] == "awaiting_approval"
        bad = await http.post(url, json={"step_id": "edit-alpha"}, headers=_headers("vsc", **WRITE))
        assert bad.status_code == 400 and bad.json()["field"] == "step_id"
        r = await http.post(url, json=body, headers=_headers("vsc", **WRITE))
        assert r.status_code == 200, r.text

        async def accepted() -> bool:
            return (await runtime.store.get_job(job_id))["state"] == "accepted"

        await until(accepted)
        again = await http.post(url, json=body, headers=_headers("vsc", **WRITE))
        assert again.status_code == 409
        missing = await http.post(
            f"{ADMIN}/jobs/nope/approve", json=body, headers=_headers("vsc", **WRITE)
        )
        assert missing.status_code == 404


async def test_admin_cancel_and_reject(tmp_path):
    async with _gateway(tmp_path) as (_host, runtime, http):
        runtime.planner_factory = lambda job_id: FixedPlanner([edit("alpha"), merge_step()])
        ids = []
        for _ in range(2):
            r = await http.post(
                f"{ADMIN}/jobs", json={"request": "greet"}, headers=_headers("admin", **WRITE)
            )
            ids.append(r.json()["job_id"])
        for job_id in ids:

            async def waiting(job_id=job_id) -> bool:
                return (await runtime.store.get_job(job_id))["state"] == "awaiting_approval"

            await until(waiting)
        r = await http.post(
            f"{ADMIN}/jobs/{ids[0]}/reject",
            json={"step_id": "merge-alpha", "note": "no"},
            headers=_headers("vsc", **WRITE),
        )
        assert r.status_code == 200
        r = await http.post(f"{ADMIN}/jobs/{ids[1]}/cancel", headers=_headers("vsc", **WRITE))
        assert r.status_code == 200 and r.json()["state"] == "cancelled"

        async def finished() -> bool:
            states = [(await runtime.store.get_job(i))["state"] for i in ids]
            return states == ["failed", "cancelled"]

        await until(finished)
        r = await http.get(f"{ADMIN}/jobs?state=failed", headers=_headers("vsc"))
        assert [j["job_id"] for j in r.json()["jobs"]] == [ids[0]]
        assert r.json()["jobs"][0]["reason"] == "rejected"


async def test_spec_put_conflict_when_running(tmp_path):
    async with _gateway(tmp_path) as (_host, runtime, http):
        store = runtime.store
        await store.create_job("j1", "greet", "key:vsc")
        await store.set_state("j1", "running")
        spec = {
            "request": "greet",
            "done": _request(),
            "systems": ["alpha"],
            "acceptance": [],
            "budgets": {},
        }
        url = f"{ADMIN}/jobs/j1/spec"
        assert (await http.put(url, json=spec, headers=_headers("vsc"))).status_code == 403
        r = await http.put(url, json=spec, headers=_headers("vsc", **WRITE))
        assert r.status_code == 409 and "awaiting_spec" in r.json()["error"]
        assert (await store.get_job("j1"))["spec_json"] is None

        await store.set_state("j1", "awaiting_spec")
        bad = {**spec, "systems": ["nope"]}
        r = await http.put(url, json=bad, headers=_headers("vsc", **WRITE))
        assert r.status_code == 400
        r = await http.put(url, json=spec, headers=_headers("vsc", **WRITE))
        assert r.status_code == 200, r.text
        assert json.loads((await store.get_job("j1"))["spec_json"])["systems"] == ["alpha"]

        async def accepted() -> bool:
            return (await store.get_job("j1"))["state"] == "accepted"

        await until(accepted)  # the job continues from the given spec
        r = await http.put(f"{ADMIN}/jobs/nope/spec", json=spec, headers=_headers("vsc", **WRITE))
        assert r.status_code == 404


async def test_resume_on_startup(tmp_path):
    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'g.db'}", auth=_auth())
    runtime = attach_vsc(host, _cfg(tmp_path), tmp_path)
    await host.startup()
    await runtime.resumed
    await runtime.store.create_job("j2", _request(), "key:vsc")
    await host.shutdown()

    host = AgentHost("http://t", db_url=f"sqlite+aiosqlite:///{tmp_path / 'g.db'}", auth=_auth())
    runtime = attach_vsc(host, VscConfig.model_validate(runtime.cfg.model_dump()), tmp_path)
    await host.startup()
    try:

        async def accepted() -> bool:
            return (await runtime.store.get_job("j2"))["state"] == "accepted"

        await until(accepted)
    finally:
        await host.shutdown()


@pytest.mark.parametrize("planner", ["scripted"])
def test_build_host_attaches_vsc(tmp_path, planner):
    make_repo(tmp_path, "core", {"a.txt": "a"})
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: http://x\n"
        "vsc:\n"
        "  systems:\n    - {id: core, repo: ./core}\n"
        "  workers:\n    - {id: w, command: [echo]}\n"
        f"  planner: {planner}\n"
    )
    host = build_host(load_config(tmp_path / "a2agw.yaml"), config_dir=tmp_path)
    assert {"deliver", "vsc-planner"} <= set(host.specs)
    assert isinstance(host.vsc, VscRuntime)
    assert host.vsc.workspaces_root == tmp_path / ".a2agw/vsc"
    paths = {getattr(r, "path", "") for r in host.admin_extra_routes}
    assert f"{ADMIN}/jobs" in paths


async def test_plain_gateway_without_vsc_unchanged(tmp_path):
    (tmp_path / "a2agw.yaml").write_text(
        "base_url: http://t\n"
        f"db_url: sqlite+aiosqlite:///{tmp_path / 'g.db'}\n"
        "auth:\n  api_keys:\n"
        f"    {hash_api_key('key-admin')}: {{principal_id: admin, scopes: [a2agw:admin]}}\n"
    )
    host = build_host(load_config(tmp_path / "a2agw.yaml"), config_dir=tmp_path)
    assert "deliver" not in host.specs and "vsc-planner" not in host.specs
    assert host.admin_extra_routes == [] and host.vsc is None
    await host.startup()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=host.app()), base_url="http://t"
        ) as http:
            r = await http.get(f"{ADMIN}/jobs", headers=_headers("admin"))
            assert r.status_code == 404
            r = await http.get("/a2agw/admin/agents", headers=_headers("admin"))
            assert r.status_code == 200 and r.json() == []
    finally:
        await host.shutdown()
