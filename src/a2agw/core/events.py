"""Framework-neutral events emitted by inbound agent adapters."""

from __future__ import annotations

from dataclasses import dataclass

from a2a.types import Part


@dataclass(frozen=True)
class Status:
    text: str


@dataclass(frozen=True)
class ArtifactChunk:
    parts: list[Part]
    name: str | None = None
    artifact_id: str | None = None
    append: bool = False
    last: bool = True


@dataclass(frozen=True)
class NeedInput:
    question: str


@dataclass(frozen=True)
class NeedAuth:
    scheme: str
    detail: str = ""


@dataclass(frozen=True)
class Usage:
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0


@dataclass(frozen=True)
class Done:
    text: str | None = None


@dataclass(frozen=True)
class Failed:
    error: str


AgentEvent = Status | ArtifactChunk | NeedInput | NeedAuth | Usage | Done | Failed
