"""The sidecar invoke protocol: request body, wire events and the request signature."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from a2a.types import Message, Part, Role
from google.protobuf.json_format import ParseDict

from a2agw.core.events import (
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
from a2agw.gateway.protocol import (
    MAX_EVENTS,
    MAX_LINE_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL,
    ConsultGrant,
    ProtocolError,
    build_invoke,
    parse_event,
    sign,
)
from a2agw.security.principal import Principal


def ctx(**kw) -> InboundContext:
    msg = Message(
        message_id="m1",
        role=Role.ROLE_USER,
        parts=[Part(text="hello"), Part(url="https://example.com/a.png", media_type="image/png")],
    )
    return InboundContext.from_message(
        "coder",
        msg,
        task_id="t1",
        context_id="c1",
        principal=Principal("key:alice", "api_key", frozenset({"a2agw:admin"})),
        metadata={"k": "v"},
        **kw,
    )


def test_constants():
    assert PROTOCOL == "a2agw.invoke/1"
    assert MAX_LINE_BYTES == 1 << 20
    assert MAX_RESPONSE_BYTES == 16 << 20
    assert MAX_EVENTS == 10_000


def test_build_invoke_shape():
    c = ctx(resumed=True)
    body = build_invoke(c, consult=None, deadline=1234.5)
    assert set(body) == {
        "protocol",
        "agent_id",
        "task_id",
        "context_id",
        "resumed",
        "text",
        "parts",
        "metadata",
        "caller",
        "consult",
        "deadline",
    }
    assert body["protocol"] == PROTOCOL
    assert (body["agent_id"], body["task_id"], body["context_id"]) == ("coder", "t1", "c1")
    assert body["resumed"] is True and body["text"] == "hello"
    assert body["metadata"] == {"k": "v"}
    assert body["caller"] == {"id": "key:alice", "kind": "api_key"}  # no scopes, no secrets
    assert body["consult"] is None and body["deadline"] == 1234.5
    assert [ParseDict(p, Part()) for p in body["parts"]] == list(c.parts)
    wire = json.dumps(body)  # JSON-serialisable as is
    for word in ("token", "secret", "password", "authorization", "scopes", "a2agw:admin"):
        assert word not in wire.lower()

    grant = ConsultGrant(url="http://gw/a2agw/consult", token="tok", expires_at=99.0)
    body = build_invoke(
        InboundContext.from_message("a", Message(), task_id="t", context_id="c"),
        consult=grant,
        deadline=None,
    )
    assert body["consult"] == {"url": "http://gw/a2agw/consult", "token": "tok", "expires_at": 99.0}
    assert body["caller"] is None and body["deadline"] is None and body["parts"] == []


PART = {"text": "hi"}

CASES = [
    ({"type": "status", "text": "working"}, Status("working")),
    (
        {
            "type": "artifact",
            "parts": [PART],
            "name": "n",
            "artifact_id": "a",
            "append": True,
            "last": False,
        },
        ArtifactChunk([Part(text="hi")], name="n", artifact_id="a", append=True, last=False),
    ),
    ({"type": "artifact", "parts": [PART]}, ArtifactChunk([Part(text="hi")])),
    ({"type": "text", "text": "chunk"}, "chunk"),
    ({"type": "need_input", "question": "which?"}, NeedInput("which?")),
    ({"type": "need_auth", "scheme": "oauth2", "detail": "go"}, NeedAuth("oauth2", "go")),
    ({"type": "need_auth", "scheme": "oauth2"}, NeedAuth("oauth2")),
    ({"type": "usage", "tokens_in": 3, "tokens_out": 4, "cost": 0.5}, Usage(3, 4, 0.5)),
    ({"type": "done", "text": "ok"}, Done("ok")),
    ({"type": "done"}, Done()),
    ({"type": "failed", "error": "boom"}, Failed("boom")),
    ({"type": "reply", "text": "hey"}, Reply("hey")),
]


@pytest.mark.parametrize(
    ("obj", "expected"), CASES, ids=[f"{c[0]['type']}-{i}" for i, c in enumerate(CASES)]
)
def test_parse_each_event_type(obj, expected):
    assert parse_event(obj) == expected


def test_all_nine_types_covered():
    assert {c[0]["type"] for c in CASES} == {
        "status",
        "artifact",
        "text",
        "need_input",
        "need_auth",
        "usage",
        "done",
        "failed",
        "reply",
    }


@pytest.mark.parametrize(
    "obj",
    [
        {"type": "bogus"},
        {"text": "no type"},
        "not an object",
        None,
        [{"type": "done"}],
        {"type": "status"},  # missing field
        {"type": "status", "text": 3},  # wrong type
        {"type": "status", "text": "x", "extra": 1},  # unknown field
        {"type": "artifact", "parts": [{"nope": 1}]},  # bad part
        {"type": "artifact", "parts": [{}]},  # part without content
        {"type": "artifact", "parts": []},
        {"type": "artifact", "parts": "x"},
        {"type": "artifact", "parts": [PART], "append": "yes"},
        {"type": "usage", "tokens_in": True, "tokens_out": 0, "cost": 0},
        {"type": "usage", "tokens_in": -1, "tokens_out": 0, "cost": 0},
        {"type": "usage", "tokens_in": 1, "tokens_out": 0, "cost": float("nan")},
        {"type": "done", "text": 5},
    ],
)
def test_parse_rejects_unknown_type_and_bad_part(obj):
    with pytest.raises(ProtocolError):
        parse_event(obj)
    assert issubclass(ProtocolError, ValueError)


def test_sign_matches_reference():
    secret, ts, body = "s3cret", "1700000000", b'{"a":1}'
    expected = "1698a50bc74d1ff1db85c4e0a5297c2ad9fdba245d5737cdb789e4cc6e098940"
    # The reference value, recomputed with the hmac module: HMAC-SHA256(secret, ts + "." + body).
    assert hmac.new(b"s3cret", b'1700000000.{"a":1}', hashlib.sha256).hexdigest() == expected
    assert sign(secret, ts, body) == "v1=" + expected
