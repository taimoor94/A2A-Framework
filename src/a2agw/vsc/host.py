"""Verified System Change on a running gateway: ``attach_vsc`` adds two hosted agents and the
VSC admin API to an ``AgentHost``.

- ``deliver``: the user-facing job agent (``VscAgentAdapter``). A caller's message in a context
  where they have no job submits one (the message text is the request) and runs it in the
  background; the A2A task stays ``working``, mirroring the job's state changes from the event
  bus, until the job ends (``Done("job <id> accepted")``, or ``Failed`` for a failed or
  cancelled job), a privileged step waits for approval (the task becomes ``input-required``)
  or the task's deadline nears (``Done("job <id> continues")``; the job goes on). In the
  caller's job context, while it is ``awaiting_approval``, ``approve [note]`` or
  ``reject [note]`` decides the waiting step and the task follows the job again; any other
  message is answered with the job's state. Jobs are per (context, owner). With auth
  configured the caller needs the ``a2agw:vsc`` scope (``a2agw:admin`` implies it). Its
  sessions are durable: an ``input-required`` task survives a restart.
- ``vsc-planner``: the planner's agent; ``AgentPlanner`` sends it every planning turn (the
  claude planner, with no tools, in a private empty directory: ``claude_planner_options``).
  Only the holder of an API key minted by ``attach_vsc`` and held only in this process's memory
  may call it, with or without auth (``AgentAccess.api_key_sha256``); with auth the key is
  also the principal ``key:vsc-internal`` (``AuthConfig.register_ephemeral_key``), the only
  one the agent admits. With ``planner: scripted`` planning runs in process and this agent
  only says so.
- Without ``auth`` VSC is refused unless ``admin_without_auth`` and ``vsc.allow_self_approval``
  are both set (development only: every caller is ``anonymous``, owner and approver alike).
- Cancelling the A2A task that follows a job (``tasks/cancel``) cancels the job.
- With ``vsc.require_spec_review`` the task becomes ``input-required`` once the spec is
  written (state ``awaiting_spec``, with the spec hash); ``PUT .../spec`` resumes the job.
- ``/a2agw/admin/vsc``: jobs, receipts, approvals, cancel, spec edits
  (``a2agw.vsc.admin.vsc_admin_routes``), behind the admin API's rules: the ``a2agw:vsc``
  scope (or ``a2agw:admin``) and the ``X-A2AGW-Admin: 1`` header on every write.

The stores, workspaces, gate and job runner are built when the host starts
(``VscAgentAdapter.start``, a ``LifecycleAdapter``), on the host's engine, audit log and bus;
jobs a previous process left unfinished are then resumed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import shutil
import tempfile
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from a2agw.adapters.callable import CallableAdapter
from a2agw.core.events import AgentEvent, Done, Failed, NeedInput, Reply, Status
from a2agw.core.spi import InboundContext
from a2agw.ops.admin import ADMIN_SCOPE
from a2agw.ops.bus import GatewayEvent, Subscription
from a2agw.security.auth import VSC_SCOPE, AgentAccess, has_scope, hash_api_key
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.vsc.admin import vsc_admin_routes
from a2agw.vsc.config import RESERVED_PRINCIPAL_ID, VscConfig
from a2agw.vsc.gate import Gate, NotApprover
from a2agw.vsc.plan import PRIVILEGED_KINDS, Plan, PlanStep
from a2agw.vsc.planner import (
    AgentPlanner,
    Planner,
    ScriptedPlanner,
    claude_planner_adapter,
    planner_agent,
)
from a2agw.vsc.receipt import build_receipt
from a2agw.vsc.runner import TERMINAL_STATES, JobRunner
from a2agw.vsc.store import VscStore
from a2agw.vsc.workers import WorkerSpec
from a2agw.vsc.workspace import WorkspaceManager

if TYPE_CHECKING:
    from a2agw.serve.host import AgentHost

__all__ = ["VscAgentAdapter", "VscRuntime", "attach_vsc", "deliver_agent"]

log = logging.getLogger(__name__)

DELIVER_AGENT = "deliver"
PLANNER_AGENT = "vsc-planner"
# The in-process caller of ``vsc-planner`` (the ephemeral key's principal and scope).
INTERNAL_PRINCIPAL = RESERVED_PRINCIPAL_ID
INTERNAL_SCOPE = "a2agw:vsc-internal"
# The inbound task gives up following its job this long before the task's deadline.
DEADLINE_MARGIN_S = 5.0
# How often a following task re-reads the job (bus events can be dropped).
POLL_S = 2.0
_DESCRIPTION = "Delivers verified changes across systems: send the change request."


class VscRuntime:
    """The VSC parts of one gateway. ``store``, ``gate`` and ``runner`` exist once the host
    has started (``start``); ``planner_factory`` (job id -> ``Planner``) may be replaced before
    a job runs."""

    def __init__(self, host: AgentHost, cfg: VscConfig, config_dir: Path) -> None:
        self.host = host
        self.cfg = cfg
        self.config_dir = Path(config_dir)
        self.workspaces_root = self.config_dir / cfg.workspace_dir
        self.planner_factory: Callable[[str], Planner] = self._default_planner
        self.store: VscStore | None = None
        self.gate: Gate | None = None
        self.runner: JobRunner | None = None
        # Resuming the jobs a previous process left unfinished (scheduled by ``start``).
        self.resumed: asyncio.Task[Any] | None = None
        # The planner turns' API key: minted here, never logged or stored; the vsc-planner
        # agent admits only its holder (``AgentAccess.api_key_sha256``).
        self._planner_key: str = secrets.token_hex(32)
        self._key_registered = False
        # The claude planner's private, empty working directory (created by ``attach_vsc``).
        self.planner_cwd: str | None = None

    def _default_planner(self, job_id: str) -> Planner:
        if self.cfg.planner == "scripted":
            return ScriptedPlanner()
        return AgentPlanner(self.host, PLANNER_AGENT, job_id=job_id, api_key=self._planner_key)

    async def start(self) -> None:
        host = self.host
        if host.engine is None:
            raise RuntimeError("the host has no database engine yet")
        if host.auth is not None and not self._key_registered:
            host.auth.register_ephemeral_key(
                self._planner_key, INTERNAL_PRINCIPAL, {INTERNAL_SCOPE}
            )
            self._key_registered = True
        if self.planner_cwd is not None:
            os.makedirs(self.planner_cwd, mode=0o700, exist_ok=True)
        store = VscStore(host.engine)
        await store.initialize()
        gate = Gate(self.cfg, host.audit, on_wait=self._on_wait)
        self.runner = JobRunner(
            store=store,
            workspaces=WorkspaceManager(self.workspaces_root, self.cfg.systems, self.config_dir),
            workers=[WorkerSpec(**w.model_dump()) for w in self.cfg.workers],
            planner_factory=lambda job_id: self.planner_factory(job_id),
            cfg=self.cfg,
            audit=host.audit,
            bus=host.bus,
            consult=host.consult_issuer,
            gate=gate,
            on_accepted=self._on_accepted,
        )
        self.store, self.gate = store, gate
        self.resumed = asyncio.create_task(self._resume_all(), name="a2agw:vsc-resume")

    async def stop(self) -> None:
        if self.resumed is not None:
            self.resumed.cancel()
            await asyncio.gather(self.resumed, return_exceptions=True)
            self.resumed = None
        if self.runner is not None:
            await self.runner.aclose()
        self.runner = self.gate = self.store = None
        if self._key_registered and self.host.auth is not None:
            self.host.auth.unregister_ephemeral_key(self._planner_key)
        self._key_registered = False
        if self.planner_cwd is not None:
            shutil.rmtree(self.planner_cwd, ignore_errors=True)  # ``start`` recreates it

    @property
    def planner_key_sha256(self) -> str:
        return hash_api_key(self._planner_key)

    async def _resume_all(self) -> None:
        assert self.runner is not None
        try:
            resumed = await self.runner.resume_all()
        except Exception:
            log.exception("vsc: resuming unfinished jobs failed")
            return
        if resumed:
            log.info("vsc: resumed %d unfinished job(s)", len(resumed))

    async def _on_wait(self, job_id: str, step: PlanStep) -> None:
        self.host.bus.publish(
            GatewayEvent(
                kind="vsc.job",
                agent_id=DELIVER_AGENT,
                data={
                    "job_id": job_id,
                    "state": "awaiting_approval",
                    "step": step.id,
                    "kind": step.kind,
                },
            )
        )

    async def _on_accepted(self, job_id: str) -> None:
        if self.host.audit is not None:
            await self.receipt(job_id)

    async def receipt(self, job_id: str) -> dict[str, Any]:
        """The job's receipt (built once). KeyError: unknown job; ValueError: not finished;
        RuntimeError: no audit log."""
        if self.store is None:
            raise RuntimeError("not started")
        if self.host.audit is None:
            raise RuntimeError("receipts need the audit log")
        return await build_receipt(self.store, self.host.audit, job_id)

    async def step_kind(self, job_id: str, step_id: str) -> str:
        assert self.store is not None
        rows = {r["step_id"]: r for r in await self.store.steps(job_id)}
        return str(rows[step_id]["kind"]) if step_id in rows else "privileged"

    async def waiting_step(self, job_id: str) -> str | None:
        """The privileged step whose approval the job is waiting for, if any."""
        assert self.store is not None
        for row in await self.store.steps(job_id):
            if row["kind"] in PRIVILEGED_KINDS and row["state"] == "running":
                return str(row["step_id"])
        return None

    async def waiting_detail(self, job_id: str) -> dict[str, Any] | None:
        """The waiting step with what approving it does: its kind and, for a merge, the target
        branch and the verified commit it would fast-forward to."""
        assert self.store is not None
        step_id = await self.waiting_step(job_id)
        job = await self.store.get_job(job_id)
        if step_id is None or job is None:
            return None
        out: dict[str, Any] = {"step_id": step_id, "kind": await self.step_kind(job_id, step_id)}
        plan = Plan.model_validate_json(job["plan_json"]) if job["plan_json"] else None
        step = next((s for s in plan.steps if s.id == step_id), None) if plan else None
        if step is not None and step.kind == "merge":
            heads = json.loads(job["verified_heads_json"] or "{}")
            assert self.runner is not None
            out["system"] = step.system
            out["target_branch"] = step.target_branch
            out["head"] = heads.get(self.runner.repo_id(step.system))
        return out


def _decision(text: str) -> tuple[str, str] | None:
    """``approve [note]`` / ``reject [note]`` -> (verb, note); anything else None."""
    words = text.strip().split(None, 1)
    if not words or words[0].lower() not in ("approve", "reject"):
        return None
    return words[0].lower(), words[1].strip() if len(words) > 1 else ""


_PAST = {"approve": "approved", "reject": "rejected"}


def _ended(job_id: str, state: str, reason: str | None) -> AgentEvent:
    """The event that ends the inbound task of a job in a terminal state."""
    if state == "accepted":
        return Done(f"job {job_id} accepted")
    return Failed(f"job {job_id} {state}" + (f" ({reason})" if reason else ""))


def _ask(job_id: str, detail: dict[str, Any]) -> NeedInput:
    what = f"step {detail['step_id']} ({detail['kind']}"
    if detail.get("target_branch"):
        what += f": fast-forward {detail['target_branch']} to {detail.get('head') or 'unknown'}"
    return NeedInput(
        f"job {job_id} awaits approval of {what}): reply 'approve [note]' or 'reject [note]'"
    )


def _ask_spec(job_id: str, spec_hash: str | None) -> NeedInput:
    return NeedInput(
        f"job {job_id} awaits review of its specification (sha256 {spec_hash}): confirm or "
        f"edit it with PUT /a2agw/admin/vsc/jobs/{job_id}/spec"
    )


def _describe(job: dict[str, Any]) -> str:
    text = f"job {job['job_id']}: {job['state']}"
    return f"{text} ({job['reason']})" if job.get("reason") else text


class VscAgentAdapter:
    """The ``deliver`` agent (see the module docstring)."""

    durable_sessions = True  # an input-required task survives a restart (the job resumes)

    def __init__(self, runtime: VscRuntime) -> None:
        self.runtime = runtime

    async def start(self) -> None:
        await self.runtime.start()

    async def stop(self) -> None:
        await self.runtime.stop()

    async def on_task_cancel(self, task_id: str) -> None:
        """A client cancelled a ``deliver`` task: the job it follows is cancelled too
        (``CancelAwareAdapter``)."""
        runner, store = self.runtime.runner, self.runtime.store
        if runner is None or store is None:
            return
        job_id = await runner.job_for_task(task_id)
        if job_id is None:
            return
        job = await store.get_job(job_id)
        await runner.cancel(job_id, actor=job["owner"] if job else "system")

    async def run(self, ctx: InboundContext) -> AsyncIterator[AgentEvent]:
        rt = self.runtime
        store, runner, gate = rt.store, rt.runner, rt.gate
        if store is None or runner is None or gate is None:
            yield Failed("not started")
            return
        principal = ctx.principal
        if rt.host.auth is not None and not has_scope(principal, VSC_SCOPE):
            yield Failed(f"forbidden: the {VSC_SCOPE} scope is required")
            return
        owner = principal.id if principal is not None else "anonymous"
        job = await store.job_for_context(ctx.context_id, owner)
        if job is None:
            request = ctx.text.strip()
            if not request:
                yield Failed("send the change request as text")
                return
            sub = rt.host.bus.subscribe()  # before the job starts: no event is missed
            try:
                try:
                    job_id = await runner.submit(request, owner=owner, context_id=ctx.context_id)
                except ValueError as e:
                    yield Failed(str(e))
                    return
                await store.set_task(job_id, ctx.task_id)
                runner.start(job_id)
                yield Status(f"job {job_id}: submitted")
                async for ev in self._follow(job_id, sub, ctx):
                    yield ev
            finally:
                sub.close()
            return
        job_id = job["job_id"]
        verdict = _decision(ctx.text)
        step = await rt.waiting_step(job_id) if job["state"] == "awaiting_approval" else None
        if verdict is None or step is None:
            yield Reply(_describe(job))
            return
        verb, note = verdict
        sub = rt.host.bus.subscribe()
        try:
            if verb == "approve":
                admin = principal is not None and ADMIN_SCOPE in principal.scopes
                try:
                    await gate.approve(
                        job_id, step, actor=owner, note=note, owner=job["owner"], admin=admin
                    )
                except NotApprover as e:
                    yield Failed(f"forbidden: {e}")
                    return
            else:
                await gate.reject(job_id, step, actor=owner, note=note)
            await store.set_task(job_id, ctx.task_id)
            yield Status(f"job {job_id}: step {step} {_PAST[verb]}")
            async for ev in self._follow(job_id, sub, ctx, decided=step):
                yield ev
        finally:
            sub.close()

    async def _follow(
        self, job_id: str, sub: Subscription, ctx: InboundContext, *, decided: str | None = None
    ) -> AsyncIterator[AgentEvent]:
        """Mirror the job's state changes until it ends, waits for approval, or the task's
        deadline nears. The job row is re-read every ``POLL_S`` without events, so a dropped
        bus event cannot leave the caller unasked (``decided``: the step this turn just
        decided, still shown as waiting until the runner moves on)."""
        rt = self.runtime
        store = rt.store
        assert store is not None
        deadline = ctx.call.deadline if ctx.call is not None else None
        end = (deadline if deadline is not None else time.time() + 3600.0) - DEADLINE_MARGIN_S
        check = True
        while True:
            if check:
                job = await store.get_job(job_id)
                if job is None:
                    yield Failed(f"job {job_id} gone")
                    return
                if job["state"] in TERMINAL_STATES:
                    yield _ended(job_id, job["state"], job["reason"])
                    return
                if job["state"] == "awaiting_spec":
                    yield _ask_spec(job_id, job["spec_hash"])
                    return
                if job["state"] == "awaiting_approval":
                    detail = await rt.waiting_detail(job_id)
                    if detail is not None and detail["step_id"] != decided:
                        yield _ask(job_id, detail)
                        return
                check = False
            remaining = end - time.time()
            if remaining <= 0:
                yield Done(f"job {job_id} continues")
                return
            try:
                ev = await asyncio.wait_for(anext(sub), min(remaining, POLL_S))
            except TimeoutError:
                check = True
                continue
            except StopAsyncIteration:  # the bus closed: the gateway is stopping
                yield Done(f"job {job_id} continues")
                return
            if ev.kind != "vsc.job" or ev.data.get("job_id") != job_id:
                continue
            state = ev.data.get("state")
            if state in TERMINAL_STATES:
                yield _ended(job_id, state, ev.data.get("reason"))
                return
            if state == "awaiting_spec":
                yield _ask_spec(job_id, ev.data.get("spec_hash"))
                return
            if state == "awaiting_approval" and ev.data.get("step"):
                detail = await rt.waiting_detail(job_id)
                if detail is None or detail["step_id"] != ev.data["step"]:
                    detail = {"step_id": ev.data["step"], "kind": ev.data.get("kind", "privileged")}
                yield _ask(job_id, detail)
                return
            yield Status(f"job {job_id}: {state}")


def deliver_agent(adapter: VscAgentAdapter) -> AgentSpec:
    return AgentSpec(
        id=DELIVER_AGENT,
        name="Deliver",
        description=_DESCRIPTION,
        skills=[SkillSpec(id="deliver", name="Deliver", description=_DESCRIPTION)],
        adapter=adapter,
        input_modes=["text/plain"],
        output_modes=["text/plain"],
    )


def _scripted_planner_reply(_: InboundContext) -> AgentEvent:
    return Failed("this gateway plans with the scripted planner (planner: scripted)")


def attach_vsc(host: AgentHost, cfg: VscConfig, config_dir: Path) -> VscRuntime:
    """Add the ``deliver`` and ``vsc-planner`` agents and the VSC admin routes to ``host``
    (before it starts). ValueError without a worker; ImportError for the claude planner
    without its extra."""
    if not cfg.workers:
        raise ValueError("vsc.workers: at least one worker is required")
    if host.auth is None:
        if not host.admin_without_auth or not cfg.allow_self_approval:
            raise ValueError(
                "vsc needs auth: without it every caller is anonymous (set admin_without_auth "
                "and vsc.allow_self_approval for development only)"
            )
        log.warning(
            "vsc without auth (admin_without_auth): every caller may submit, approve and "
            "cancel jobs; development only"
        )
    runtime = VscRuntime(host, cfg, Path(config_dir))
    if cfg.planner == "scripted":
        planner_adapter: Any = CallableAdapter(_scripted_planner_reply)
    else:
        runtime.planner_cwd = tempfile.mkdtemp(prefix="a2agw-vsc-planner-")
        planner_adapter = claude_planner_adapter(cfg, runtime.planner_cwd)
    host.add(deliver_agent(VscAgentAdapter(runtime)))
    internal = AgentAccess(
        allowed_principals=frozenset({f"key:{INTERNAL_PRINCIPAL}"}),
        api_key_sha256=runtime.planner_key_sha256,
    )
    host.add(planner_agent(planner_adapter, PLANNER_AGENT, access=internal))
    host.admin_extra_routes += vsc_admin_routes(runtime)
    host.vsc = runtime
    return runtime
