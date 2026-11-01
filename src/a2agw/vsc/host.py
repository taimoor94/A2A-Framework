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
  claude planner). With auth configured only the principal ``key:vsc-internal`` may call it:
  an API key minted at startup, held only in this process's memory
  (``AuthConfig.register_ephemeral_key``). With ``planner: scripted`` planning runs in
  process and this agent only says so.
- ``/a2agw/admin/vsc``: jobs, receipts, approvals, cancel, spec edits
  (``a2agw.vsc.admin.vsc_admin_routes``), behind the admin API's rules: the ``a2agw:vsc``
  scope (or ``a2agw:admin``) and the ``X-A2AGW-Admin: 1`` header on every write.

The stores, workspaces, gate and job runner are built when the host starts
(``VscAgentAdapter.start``, a ``LifecycleAdapter``), on the host's engine, audit log and bus;
jobs a previous process left unfinished are then resumed.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from a2agw.adapters.callable import CallableAdapter
from a2agw.core.events import AgentEvent, Done, Failed, NeedInput, Reply, Status
from a2agw.core.spi import InboundContext
from a2agw.ops.bus import GatewayEvent, Subscription
from a2agw.security.auth import VSC_SCOPE, AgentAccess, has_scope
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.vsc.admin import vsc_admin_routes
from a2agw.vsc.config import VscConfig
from a2agw.vsc.gate import Gate
from a2agw.vsc.plan import PRIVILEGED_KINDS, PlanStep
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
INTERNAL_PRINCIPAL = "vsc-internal"
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
        # The planner turns' API key (auth configured only): minted by ``start``, never logged.
        self._planner_key: str | None = None

    def _default_planner(self, job_id: str) -> Planner:
        if self.cfg.planner == "scripted":
            return ScriptedPlanner()
        return AgentPlanner(self.host, PLANNER_AGENT, job_id=job_id, api_key=self._planner_key)

    async def start(self) -> None:
        host = self.host
        if host.engine is None:
            raise RuntimeError("the host has no database engine yet")
        if host.auth is not None and self._planner_key is None:
            self._planner_key = secrets.token_hex(32)
            host.auth.register_ephemeral_key(
                self._planner_key, INTERNAL_PRINCIPAL, {INTERNAL_SCOPE}
            )
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
        if self._planner_key is not None and self.host.auth is not None:
            self.host.auth.unregister_ephemeral_key(self._planner_key)
        self._planner_key = None

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


def _ask(job_id: str, step: str, kind: str) -> NeedInput:
    return NeedInput(
        f"job {job_id} awaits approval of step {step} ({kind}): reply 'approve [note]' or "
        "'reject [note]'"
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
                await gate.approve(job_id, step, actor=owner, note=note)
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
                if job["state"] == "awaiting_approval":
                    step = await rt.waiting_step(job_id)
                    if step is not None and step != decided:
                        yield _ask(job_id, step, await rt.step_kind(job_id, step))
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
            if state == "awaiting_approval" and ev.data.get("step"):
                yield _ask(job_id, ev.data["step"], ev.data.get("kind", "privileged"))
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
    planner_adapter = (
        CallableAdapter(_scripted_planner_reply)
        if cfg.planner == "scripted"
        else claude_planner_adapter(cfg)
    )
    runtime = VscRuntime(host, cfg, Path(config_dir))
    host.add(deliver_agent(VscAgentAdapter(runtime)))
    internal = AgentAccess(allowed_principals=frozenset({f"key:{INTERNAL_PRINCIPAL}"}))
    host.add(planner_agent(planner_adapter, PLANNER_AGENT, access=internal))
    host.admin_extra_routes += vsc_admin_routes(runtime)
    host.vsc = runtime
    return runtime
