import dataclasses

import pytest
from a2a.types import Message, Part, Role
from google.protobuf.struct_pb2 import Value

from a2agw.core.events import Status
from a2agw.core.spi import InboundAdapter, InboundContext


def test_events_are_frozen():
    ev = Status("x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.text = "y"  # type: ignore[misc]


def test_inbound_context_text_empty_for_data_only():
    data_part = Part(data=Value(string_value="payload"))
    msg = Message(message_id="m1", role=Role.ROLE_USER, parts=[data_part])
    ctx = InboundContext.from_message("agent", msg, task_id="t1", context_id="c1")
    assert ctx.text == ""
    assert len(ctx.parts) == 1
    assert ctx.metadata == {}
    assert ctx.resumed is False
    assert ctx.principal is None and ctx.call is None


def test_inbound_context_joins_text_parts():
    msg = Message(
        message_id="m1",
        role=Role.ROLE_USER,
        parts=[Part(text="a"), Part(data=Value(string_value="d")), Part(text="b")],
    )
    ctx = InboundContext.from_message(
        "agent", msg, task_id="t", context_id="c", metadata={"k": 1}, resumed=True
    )
    assert ctx.text == "a\nb"
    assert ctx.metadata == {"k": 1}
    assert ctx.resumed is True


def test_inbound_adapter_is_runtime_checkable():
    class A:
        durable_sessions = False

        async def run(self, ctx):
            yield Status("x")

    assert isinstance(A(), InboundAdapter)
    assert not isinstance(object(), InboundAdapter)
