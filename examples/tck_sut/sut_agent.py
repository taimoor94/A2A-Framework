"""A2A TCK system under test, built on a2agw.

Reimplements the behaviours of the TCK's generated ``sut/a2a-python`` agent (see the Gherkin
scenarios in a2a-tck ``scenarios/*.feature``) with an ``AgentSpec`` and a ``CallableAdapter``.
The TCK selects a behaviour by the prefix of the incoming ``messageId``.

Run: ``uv run python -m examples.tck_sut.sut_agent`` (HTTP on :9999, no auth). See
``scripts/run_tck.sh`` and ``docs/conformance.md``.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from collections.abc import AsyncIterator

from a2a.types import Part
from google.protobuf.struct_pb2 import Value

from a2agw.adapters.callable import CallableAdapter
from a2agw.core.events import AgentEvent, ArtifactChunk, Done, Failed, NeedInput, Reply, Status
from a2agw.core.spi import InboundContext
from a2agw.serve.agent import AgentSpec, SkillSpec
from a2agw.serve.host import AgentHost

BASE_URL = "http://localhost:9999"
STREAMING_TIMEOUT_S = 2.0  # the TCK's streaming timeout; the resubscribe task waits 2x this


def _text(text: str) -> Part:
    return Part(text=text)


def _file_part() -> Part:
    return Part(raw=b"tck", media_type="text/plain", filename="output.txt")


def _data_part() -> Part:
    value = Value()
    value.struct_value.update({"key": "value", "count": 42})
    return Part(data=value)


async def tck_behaviour(ctx: InboundContext) -> AsyncIterator[AgentEvent]:
    """Route on the messageId prefix, as the reference SUT does. Order matters: longer
    prefixes that share a stem with a shorter one are tested first."""
    mid = ctx.message.message_id
    artifact: list[Part] | None = None  # for the "working, artifact, completed" streams
    if mid.startswith("tck-stream-artifact-chunked"):
        yield Status("working")
        yield ArtifactChunk([_text("chunk-1 ")], artifact_id="chunked", append=False, last=False)
        yield ArtifactChunk([_text("chunk-2")], artifact_id="chunked", append=True, last=True)
        yield Done()
        return
    if mid.startswith("test-resubscribe-message-id"):
        yield Status("working")
        await asyncio.sleep(2 * STREAMING_TIMEOUT_S)
        yield Done()
        return
    if mid.startswith("tck-stream-artifact-text"):
        artifact = [_text("Streamed text content")]
    elif mid.startswith("tck-stream-artifact-file"):
        artifact = [_file_part()]
    elif mid.startswith("tck-stream-ordering-001"):
        artifact = [_text("Ordered output")]
    elif mid.startswith("tck-stream-001"):
        artifact = [_text("Stream hello from TCK")]
    elif mid.startswith("tck-stream-003"):
        artifact = [_text("Stream task lifecycle")]
    if artifact is not None:
        yield Status("working")
        yield ArtifactChunk(artifact)
        yield Done()
        return
    if mid.startswith("tck-stream-002"):
        yield Done()
    elif mid.startswith("tck-artifact-file-url"):
        yield ArtifactChunk(
            [
                Part(
                    url="https://example.com/output.txt",
                    media_type="text/plain",
                    filename="output.txt",
                )
            ]
        )
        yield Done()
    elif mid.startswith("tck-artifact-text"):
        yield ArtifactChunk([_text("Generated text content")])
        yield Done()
    elif mid.startswith("tck-artifact-file"):
        yield ArtifactChunk([_file_part()])
        yield Done()
    elif mid.startswith("tck-artifact-data"):
        yield ArtifactChunk([_data_part()])
        yield Done()
    elif mid.startswith("tck-message-response"):
        yield Reply("Direct message response")  # a bare Message, no task
    elif mid.startswith("tck-input-required"):
        yield NeedInput("input required")
    elif mid.startswith("tck-reject-task"):
        # The reference raises A2AError("rejected"); the adapter SPI reports a failure.
        yield Failed("rejected")
    elif mid.startswith("tck-complete-task"):
        # The reference puts this text in the completed status message; a2agw's Done puts
        # it in a "result" artifact. The TCK checks only the completed state.
        yield Done(text="Hello from TCK")
    else:
        yield Done(text="Unhandled messageId prefix: " + mid)


def sut_spec() -> AgentSpec:
    return AgentSpec(
        id="tck",
        name="a2agw TCK System Under Test",
        description="a2agw agent implementing the A2A TCK reference SUT behaviours",
        version="1.0.0",
        skills=[
            SkillSpec(
                id="tck",
                name="TCK Conformance",
                description="Handles TCK conformance test messages",
                tags=["tck"],
            )
        ],
        adapter=CallableAdapter(tck_behaviour),
        direct_replies=True,  # "tck-message-response" answers with a bare Message
    )


def build_host(base_url: str = BASE_URL, *, db_url: str | None = None) -> AgentHost:
    """A single-agent host with no auth. Without ``db_url`` it uses a fresh temp database."""
    if db_url is None:
        db_url = f"sqlite+aiosqlite:///{os.path.join(tempfile.mkdtemp(), 'tck.db')}"
    host = AgentHost(base_url, db_url=db_url)
    host.add(sut_spec())
    return host


def main() -> None:
    port = int(os.environ.get("SUT_PORT", "9999"))
    build_host(os.environ.get("SUT_BASE_URL", f"http://localhost:{port}")).run(
        host="127.0.0.1", port=port
    )


if __name__ == "__main__":
    main()
