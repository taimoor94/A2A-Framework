"""The sidecar invoke protocol, ``a2agw.invoke/1`` (spec 7.7, ``docs/sidecar.md``).

The gateway sends an external agent one JSON invoke body per turn (``build_invoke``) and reads
back wire events, one JSON object each (``parse_event``). The transports (webhook, stdio)
share this module, so both speak exactly the same body and events.

The invoke body never carries the caller's credentials: only the caller's id and kind.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, field
from typing import Any

from a2a.types import Part
from google.protobuf.json_format import MessageToDict, ParseDict, ParseError

from a2agw.core.events import (
    AgentEvent,
    ArtifactChunk,
    Done,
    Failed,
    NeedAuth,
    NeedInput,
    Reply,
    Status,
    Usage,
)
from a2agw.core.spi import InboundContext

__all__ = [
    "MAX_EVENTS",
    "MAX_LINE_BYTES",
    "MAX_RESPONSE_BYTES",
    "PROTOCOL",
    "TERMINAL",
    "ConsultGrant",
    "ProtocolError",
    "build_invoke",
    "parse_event",
    "sign",
]

PROTOCOL = "a2agw.invoke/1"

MAX_LINE_BYTES = 1 << 20  # one NDJSON event line, without its newline
MAX_RESPONSE_BYTES = 16 << 20  # a whole response body
MAX_EVENTS = 10_000  # wire events in one response

# Events that end the turn: nothing after one is read.
TERMINAL = (Done, Failed, NeedInput, NeedAuth, Reply)


class ProtocolError(ValueError):
    """A wire event or response that breaks the protocol. The message names the problem
    (a type or field name), never a value from the agent."""


@dataclass(frozen=True)
class ConsultGrant:
    """Lets the external agent consult partners through the gateway for this turn: the
    gateway's consult URL, a bearer token scoped to the turn, and its expiry (epoch seconds)."""

    url: str
    token: str = field(repr=False)  # a secret: never in a repr (or a log line built from one)
    expires_at: float


def build_invoke(
    ctx: InboundContext, *, consult: ConsultGrant | None, deadline: float | None
) -> dict[str, Any]:
    """The JSON invoke body for one turn. ``deadline`` is epoch seconds (or None)."""
    p = ctx.principal
    return {
        "protocol": PROTOCOL,
        "agent_id": ctx.agent_id,
        "task_id": ctx.task_id,
        "context_id": ctx.context_id,
        "resumed": ctx.resumed,
        "text": ctx.text,
        "parts": [MessageToDict(part) for part in ctx.parts],
        "metadata": ctx.metadata,
        "caller": None if p is None else {"id": p.id, "kind": p.kind},
        "consult": (
            None
            if consult is None
            else {"url": consult.url, "token": consult.token, "expires_at": consult.expires_at}
        ),
        "deadline": deadline,
    }


def sign(secret: str, ts: str, body: bytes) -> str:
    """``X-A2AGW-Signature`` value: ``v1=`` + hex HMAC-SHA256 of ``ts + "." + body``."""
    mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256)
    return "v1=" + mac.hexdigest()


# -- wire events ----------------------------------------------------------------------

# type -> (required fields, optional fields)
_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "status": (frozenset({"text"}), frozenset()),
    "artifact": (frozenset({"parts"}), frozenset({"name", "artifact_id", "append", "last"})),
    "text": (frozenset({"text"}), frozenset()),
    "need_input": (frozenset({"question"}), frozenset()),
    "need_auth": (frozenset({"scheme"}), frozenset({"detail"})),
    "usage": (frozenset({"tokens_in", "tokens_out", "cost"}), frozenset()),
    "done": (frozenset(), frozenset({"text"})),
    "failed": (frozenset({"error"}), frozenset()),
    "reply": (frozenset({"text"}), frozenset()),
}


def _str(obj: dict[str, Any], key: str, *, optional: bool = False) -> Any:
    v = obj.get(key)
    if v is None and optional:
        return None
    if not isinstance(v, str):
        raise ProtocolError(f"{obj['type']}.{key} must be a string")
    return v


def _bool(obj: dict[str, Any], key: str, default: bool) -> bool:
    v = obj.get(key, default)
    if not isinstance(v, bool):
        raise ProtocolError(f"{obj['type']}.{key} must be a boolean")
    return v


def _count(obj: dict[str, Any], key: str) -> int:
    v = obj[key]
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ProtocolError(f"usage.{key} must be a non-negative integer")
    return v


def _parts(raw: Any) -> list[Part]:
    if not isinstance(raw, list) or not raw:
        raise ProtocolError("artifact.parts must be a non-empty list")
    out = []
    for item in raw:
        if not isinstance(item, dict):
            raise ProtocolError("artifact.parts items must be objects")
        try:
            part = ParseDict(item, Part())
        except (ParseError, TypeError, ValueError):
            raise ProtocolError("artifact.parts item is not a valid A2A Part") from None
        if part.WhichOneof("content") is None:
            raise ProtocolError("artifact.parts item has no content")
        out.append(part)
    return out


def parse_event(obj: Any) -> AgentEvent | str:
    """One wire event as an ``AgentEvent``; a ``text`` event is returned as its ``str`` (a
    delta of the streamed "output" artifact, see ``a2agw.adapters._stream.stream_events``).

    Unknown types, unknown or missing fields and wrong types raise ``ProtocolError``."""
    if not isinstance(obj, dict):
        raise ProtocolError("event must be a JSON object")
    kind = obj.get("type")
    if not isinstance(kind, str) or kind not in _FIELDS:
        raise ProtocolError("unknown event type")
    required, optional = _FIELDS[kind]
    keys = set(obj) - {"type"}
    if keys - required - optional:
        raise ProtocolError(f"{kind}: unknown field")
    if required - keys:
        raise ProtocolError(f"{kind}: missing field {min(required - keys)}")

    if kind == "status":
        return Status(_str(obj, "text"))
    if kind == "artifact":
        return ArtifactChunk(
            parts=_parts(obj["parts"]),
            name=_str(obj, "name", optional=True),
            artifact_id=_str(obj, "artifact_id", optional=True),
            append=_bool(obj, "append", False),
            last=_bool(obj, "last", True),
        )
    if kind == "text":
        return str(_str(obj, "text"))
    if kind == "need_input":
        return NeedInput(_str(obj, "question"))
    if kind == "need_auth":
        detail = _str(obj, "detail", optional=True)
        return NeedAuth(_str(obj, "scheme"), "" if detail is None else detail)
    if kind == "usage":
        cost = obj["cost"]
        if (
            isinstance(cost, bool)
            or not isinstance(cost, int | float)
            or not math.isfinite(cost)
            or cost < 0
        ):
            raise ProtocolError("usage.cost must be a non-negative number")
        return Usage(_count(obj, "tokens_in"), _count(obj, "tokens_out"), float(cost))
    if kind == "done":
        return Done(_str(obj, "text", optional=True))
    if kind == "failed":
        return Failed(_str(obj, "error"))
    return Reply(_str(obj, "text"))
