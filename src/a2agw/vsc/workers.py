"""Workers: external coding agents launched per step as stdio sidecars inside the step's
worktree, with the call audited and its usage recorded."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from a2a.types import Message, Part, Role
from pydantic import BaseModel, ConfigDict

from a2agw.adapters._sidecar import ConsultFn
from a2agw.adapters.stdio import StdioAdapter
from a2agw.core.events import ArtifactChunk, Done, Failed, Status, Usage
from a2agw.core.spi import InboundContext
from a2agw.ops.audit import AuditEvent, AuditLog
from a2agw.vsc.config import SystemConfig, WorkerConfig
from a2agw.vsc.plan import PlanStep
from a2agw.vsc.spec import ExecutableSpec
from a2agw.vsc.verify import CheckResult
from a2agw.vsc.workspace import Workspace

OUTPUT_MAX_BYTES = 64 * 1024
_STDERR_TAIL_CHARS = 2000


class WorkerTask(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    job_id: str
    step_id: str
    attempt: int
    system: SystemConfig
    spec: ExecutableSpec
    step: PlanStep
    failure: CheckResult | None = None

    def prompt(self) -> str:
        """The step's instructions come last, after the shared spec and the confinement rule."""
        lines = [
            f"Done means: {self.spec.done}",
            f"Request: {self.spec.request}",
            f"You are working on system '{self.system.id}', step '{self.step.id}', "
            + f"attempt {self.attempt}.",
            f"Confinement: edit only under {self.system.path}",
        ]
        if self.step.contracts:
            lines.append("Contracts to honor: " + ", ".join(self.step.contracts))
        if self.failure is not None:
            f = self.failure
            lines += [
                f"The previous attempt failed check {f.id} ({f.kind}): {f.reason or 'failed'}",
                "stderr tail:",
                f.stderr_tail[-_STDERR_TAIL_CHARS:],
            ]
        lines += ["Instructions:", self.step.instructions]
        return "\n".join(lines)


@dataclass
class WorkerResult:
    text: str = ""
    status_lines: list[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    usage_reported: bool = False
    failed: str | None = None


@dataclass(frozen=True)
class WorkerSpec:
    id: str
    command: list[str]
    model: str = ""
    cost_class: Literal["cheap", "standard", "strong"] = "standard"
    reports_usage: bool = True
    env: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 1800.0

    @classmethod
    def from_config(cls, c: WorkerConfig) -> WorkerSpec:
        return cls(
            id=c.id,
            command=list(c.command),
            model=c.model,
            cost_class=c.cost_class,
            reports_usage=c.reports_usage,
            env=dict(c.env),
            timeout_s=c.timeout_s,
        )

    def adapter(self, cwd: Path, consult: ConsultFn | None) -> StdioAdapter:
        return StdioAdapter(
            self.command,
            cwd=cwd,
            env=self.env,
            max_concurrency=1,
            timeout_s=self.timeout_s,
            consult=consult,
            agent_id=f"vsc:{self.id}",
        )


def _cap(text: str) -> str:
    data = text.encode()
    return (
        text if len(data) <= OUTPUT_MAX_BYTES else data[:OUTPUT_MAX_BYTES].decode(errors="ignore")
    )


async def run_worker(
    spec: WorkerSpec,
    task: WorkerTask,
    ws: Workspace,
    *,
    consult: ConsultFn | None,
    audit: AuditLog | None,
    actor: str,
) -> WorkerResult:
    result = WorkerResult()
    parts: list[str] = []
    seen_usage = False
    message = Message(
        message_id=f"{task.job_id}:{task.step_id}:{task.attempt}",
        role=Role.ROLE_USER,
        parts=[Part(text=task.prompt())],
    )
    ctx = InboundContext.from_message(
        f"vsc:{spec.id}",
        message,
        task_id=f"{task.job_id}:{task.step_id}:{task.attempt}",
        context_id=task.job_id,
    )
    adapter = spec.adapter(ws.path, consult)
    try:
        try:
            await adapter.start()
            async for ev in adapter.run(ctx):
                if isinstance(ev, Status):
                    result.status_lines.append(ev.text)
                elif isinstance(ev, ArtifactChunk):
                    parts.extend(p.text for p in ev.parts if p.text)
                elif isinstance(ev, Usage):
                    seen_usage = True
                    result.tokens_in += ev.tokens_in
                    result.tokens_out += ev.tokens_out
                    result.cost += ev.cost
                elif isinstance(ev, Done):
                    if ev.text and ev.text not in parts:
                        parts.append(ev.text)
                elif isinstance(ev, Failed):
                    result.failed = ev.error
        except Exception as exc:  # noqa: BLE001 - worker-side failure; CancelledError propagates
            result.failed = f"{type(exc).__name__}: {str(exc)[:256]}"
        finally:
            result.text = _cap("".join(parts))
            result.usage_reported = spec.reports_usage and seen_usage
            await adapter.stop()
    finally:
        if audit is not None:
            await audit.emit(
                AuditEvent(
                    actor=actor,
                    action="vsc.step",
                    agent_id="deliver",
                    task_id=task.job_id,
                    outcome="worker",
                    detail={
                        "worker": spec.id,
                        "step": task.step_id,
                        "attempt": task.attempt,
                        "tokens_in": result.tokens_in,
                        "tokens_out": result.tokens_out,
                        "cost": result.cost,
                        "usage_reported": result.usage_reported,
                        "reason": result.failed or "",
                    },
                )
            )
    return result
