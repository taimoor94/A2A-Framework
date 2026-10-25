"""Mapping partner responses to ToolResults: task tracking, id validation and size caps.

Everything here is partner-controlled and untrusted. ``Track`` accumulates what one call has
learned about the partner task, refuses ids that do not belong to the call, and stops once the
call has received ``STREAM_BUDGET_BYTES``. ``build_result`` caps the partner text it puts into a
``ToolResult`` at ``TEXT_CAP_BYTES`` (shared with artifact text and data parts).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Literal

from a2a.server.tasks.task_manager import append_artifact_to_task
from a2a.types import Message, Part, StreamResponse, Task, TaskState
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, Field

TEXT_CAP_BYTES = 64 * 1024  # partner text per tool result (UTF-8 bytes)
STREAM_BUDGET_BYTES = 1024 * 1024  # partner events consumed per call

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

STATES: dict[int, ResultState] = {
    TaskState.TASK_STATE_COMPLETED: "completed",
    TaskState.TASK_STATE_WORKING: "working",
    TaskState.TASK_STATE_SUBMITTED: "working",
    TaskState.TASK_STATE_INPUT_REQUIRED: "input_required",
    TaskState.TASK_STATE_AUTH_REQUIRED: "auth_required",
    TaskState.TASK_STATE_FAILED: "failed",
    TaskState.TASK_STATE_CANCELED: "canceled",
    TaskState.TASK_STATE_REJECTED: "rejected",
}
INTERRUPTED = {TaskState.TASK_STATE_INPUT_REQUIRED, TaskState.TASK_STATE_AUTH_REQUIRED}
TERMINAL = {
    TaskState.TASK_STATE_COMPLETED,
    TaskState.TASK_STATE_FAILED,
    TaskState.TASK_STATE_CANCELED,
    TaskState.TASK_STATE_REJECTED,
}
TERMINAL_NAMES = {TaskState.Name(s) for s in TERMINAL}


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
    # ``unavailable`` because the partner's circuit breaker is open: seconds until it is
    # tried again. None otherwise.
    retry_after_s: float | None = None


class ProtocolViolation(Exception):
    """The partner returned a task or context id that does not belong to this call."""


class Track:
    """Accumulates what one call has learned about the partner task."""

    def __init__(self, task_id: str | None, context_id: str | None) -> None:
        self.task_id = task_id or None
        self.context_id = context_id or None
        self.task: Task | None = None
        self.message: Message | None = None
        self.received = 0  # bytes of stream events consumed
        self.over_budget = False
        # On a reply to an interrupted task, the old interrupted status must not end the call.
        self.stale_status: str | None = None

    def _check_ids(self, task_id: str, context_id: str) -> None:
        if task_id and self.task_id is not None and task_id != self.task_id:
            raise ProtocolViolation("task id mismatch")
        if context_id and self.context_id is not None and context_id != self.context_id:
            raise ProtocolViolation("context id mismatch")

    def set_task(self, task: Task) -> None:
        self._check_ids(task.id, task.context_id)
        self.task = task
        self.task_id = task.id or self.task_id
        self.context_id = task.context_id or self.context_id

    def apply(self, ev: StreamResponse) -> None:
        """Fold one stream event in. Past the byte budget the event is dropped and the call
        counts as settled (``over_budget``)."""
        self.received += ev.ByteSize()
        if self.received > STREAM_BUDGET_BYTES:
            self.over_budget = True
            return
        kind = ev.WhichOneof("payload")
        if kind == "task":
            t = Task()
            t.CopyFrom(ev.task)
            self.set_task(t)
        elif kind == "message":
            msg = ev.message
            self._check_ids(msg.task_id, msg.context_id)
            self.message = msg
            self.context_id = msg.context_id or self.context_id
        elif kind in ("status_update", "artifact_update"):
            upd = getattr(ev, kind)
            self._check_ids(upd.task_id, upd.context_id)
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
        if self.task is not None and self.task.status.state in INTERRUPTED:
            self.stale_status = self._status_key()

    @property
    def settled(self) -> bool:
        if self.over_budget:
            return True
        if self.message is not None and self.task is None:
            return True
        if self.task is None:
            return False
        state = self.task.status.state
        if state in TERMINAL:
            return True
        if state in INTERRUPTED:
            return self._status_key() != self.stale_status
        return False

    def state_name(self) -> str | None:
        if self.task is not None:
            return TaskState.Name(self.task.status.state)
        if self.task_id is not None:
            return TaskState.Name(TaskState.TASK_STATE_SUBMITTED)
        return None


def cut_utf8(text: str, limit: int) -> tuple[str, bool]:
    """Cap ``text`` at ``limit`` UTF-8 bytes on a character boundary. Returns (text, cut)."""
    raw = text.encode()
    if len(raw) <= limit:
        return text, False
    return raw[:limit].decode("utf-8", "ignore"), True


def texts(parts: Iterable[Part]) -> list[str]:
    return [p.text for p in parts if p.WhichOneof("content") == "text" and p.text]


class _Budget:
    def __init__(self, limit: int) -> None:
        self.left = limit
        self.truncated = False

    def part(self, p: Part) -> dict[str, Any]:
        kind = p.WhichOneof("content")
        if kind == "text":
            return self._take("text", p.text, {"kind": "text", "text": p.text})
        if kind == "data":
            data = MessageToDict(p.data)
            return self._take("data", json.dumps(data), {"kind": "data", "data": data})
        out: dict[str, Any] = {"kind": "file", "media_type": p.media_type or None}
        if p.filename:
            out["name"] = p.filename
        if kind == "raw":
            out["size"] = len(p.raw)  # raw bytes are never inlined
        elif kind == "url":
            out["url"] = p.url
        return out

    def _take(self, kind: str, content: str, full: dict[str, Any]) -> dict[str, Any]:
        size = len(content.encode())
        if size <= self.left:
            self.left -= size
            return full
        self.truncated = True
        return {"kind": kind, "truncated": True, "size": size}


def build_result(partner: str, provenance: dict[str, Any], track: Track) -> ToolResult:
    if track.task is None and track.message is not None:
        msg = track.message
        parts = list(msg.parts)
        text, cut = cut_utf8("\n".join(texts(parts)), TEXT_CAP_BYTES)
        budget = _Budget(TEXT_CAP_BYTES - len(text.encode()))
        arts = []
        if any(p.WhichOneof("content") != "text" for p in parts):
            summary = [budget.part(p) for p in parts]
            arts = [{"artifact_id": None, "name": "message", "parts": summary}]
        return ToolResult(
            partner=partner,
            task_id=None,
            context_id=msg.context_id or track.context_id,
            state="completed",
            text=text,
            artifacts=arts,
            truncated=cut or budget.truncated or track.over_budget,
            provenance=provenance,
        )
    if track.task is None:
        # Only the id is known (e.g. the deadline hit before any task snapshot arrived).
        return ToolResult(
            partner=partner,
            task_id=track.task_id,
            context_id=track.context_id,
            state="working",
            truncated=track.over_budget,
            provenance=provenance,
        )
    task = track.task
    state = STATES.get(task.status.state, "working")
    status_text = texts(task.status.message.parts) if task.status.HasField("message") else []
    all_text = list(status_text)
    for a in task.artifacts:
        all_text += texts(a.parts)
    text, cut = cut_utf8("\n".join(all_text), TEXT_CAP_BYTES)
    budget = _Budget(TEXT_CAP_BYTES - len(text.encode()))
    artifacts = [
        {
            "artifact_id": a.artifact_id,
            "name": a.name or None,
            "parts": [budget.part(p) for p in a.parts],
        }
        for a in task.artifacts
    ]
    question = None
    if state in ("input_required", "auth_required"):
        question = cut_utf8("\n".join(status_text), TEXT_CAP_BYTES)[0] or None
    return ToolResult(
        partner=partner,
        task_id=task.id or track.task_id,
        context_id=task.context_id or track.context_id,
        state=state,
        text=text,
        artifacts=artifacts,
        question=question,
        truncated=cut or budget.truncated or track.over_budget,
        provenance=provenance,
    )
