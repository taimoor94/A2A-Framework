"""Adapter contract kit: the checks every native framework adapter must pass.

Inbound, an adapter is driven through ``InboundAdapter.run`` exactly as the executor drives
it. Outbound, ``FakePartnerClient`` stands in for ``PartnerClient`` behind the real
``consult.tools.invoke``, so a projection is tested end to end without a partner.

Usage from an adapter's test module (``pythonpath`` includes ``tests``)::

    from adapters.contract import FakePartnerClient, assert_projection, assert_text_stream, drive
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from a2a.types import Message, Part, Role

from a2agw.consult.handles import owned
from a2agw.consult.registry import PartnerRecord
from a2agw.consult.results import ToolResult
from a2agw.consult.tools import PartnerTool, partner_tools
from a2agw.context.call_context import current_inbound_task, current_principal, use_inbound
from a2agw.core.events import AgentEvent, ArtifactChunk, Done, Failed
from a2agw.core.spi import InboundAdapter, InboundContext
from a2agw.security.principal import Principal

__all__ = [
    "FakePartnerClient",
    "assert_cancellable",
    "assert_failure_maps",
    "assert_isolated_callers",
    "assert_multi_turn",
    "assert_owned_tasks_only",
    "assert_projection",
    "assert_text_stream",
    "caller",
    "drive",
    "make_ctx",
    "output_text",
]


# -- inbound ------------------------------------------------------------------------------


def make_ctx(
    text: str,
    *,
    context_id: str = "c1",
    task_id: str = "t1",
    principal: Principal | None = None,
) -> InboundContext:
    m = Message(message_id=f"m-{task_id}", role=Role.ROLE_USER, parts=[Part(text=text)])
    return InboundContext.from_message(
        "contract", m, task_id=task_id, context_id=context_id, principal=principal
    )


def caller(principal_id: str) -> Principal:
    """An API-key principal with this id."""
    return Principal(id=principal_id, kind="api_key", scopes=frozenset())


async def drive(
    adapter: InboundAdapter,
    text: str,
    *,
    context_id: str = "c1",
    task_id: str = "t1",
    principal: Principal | None = None,
) -> list[AgentEvent]:
    """Run one turn and collect every event the adapter yields."""
    ctx = make_ctx(text, context_id=context_id, task_id=task_id, principal=principal)
    return [ev async for ev in adapter.run(ctx)]


def _chunk_text(c: ArtifactChunk) -> str:
    return "".join(p.text for p in c.parts)


def output_text(events: list[AgentEvent]) -> str:
    """The answer a client sees: the streamed "output" artifact, else the ``Done`` text."""
    chunks = [e for e in events if isinstance(e, ArtifactChunk) and e.artifact_id == "output"]
    if chunks:
        return "".join(_chunk_text(c) for c in chunks)
    done = [e for e in events if isinstance(e, Done)]
    return (done[-1].text or "") if done else ""


def assert_text_stream(events: list[AgentEvent], expected_text: str) -> None:
    """The turn answers ``expected_text`` exactly once: either as one streamed "output"
    artifact (first chunk not appended, later ones appended, only the final chunk ``last``)
    or, when nothing streamed, as the ``Done`` text. At most one ``Done``, and it is the last
    event; no ``Failed``."""
    assert not any(isinstance(e, Failed) for e in events), events
    dones = [e for e in events if isinstance(e, Done)]
    assert len(dones) <= 1, f"more than one Done: {dones}"
    if dones:
        assert events[-1] is dones[0], "Done must be the last event"
    chunks = [e for e in events if isinstance(e, ArtifactChunk) and e.artifact_id == "output"]
    if chunks:
        assert "".join(_chunk_text(c) for c in chunks) == expected_text
        assert [c.last for c in chunks] == [False] * (len(chunks) - 1) + [True]
        assert chunks[0].append is False and all(c.append for c in chunks[1:])
        assert all(c.name == "output" for c in chunks)
        # The streamed text is the answer: a Done must not repeat it.
        assert not dones or not dones[0].text, "text both streamed and in Done"
    else:
        # ``Done()`` (text None) answers an empty text.
        assert dones and (dones[0].text or "") == expected_text, events


async def assert_multi_turn(
    adapter: InboundAdapter, first: str, second: str, expect_memory: str
) -> None:
    """A second turn on the same ``context_id`` sees the first: its answer contains
    ``expect_memory``. A turn on another context must not."""
    one = await drive(adapter, first, context_id="c-mt", task_id="t-mt-1")
    assert not any(isinstance(e, Failed) for e in one), one
    two = await drive(adapter, second, context_id="c-mt", task_id="t-mt-2")
    assert not any(isinstance(e, Failed) for e in two), two
    assert expect_memory in output_text(two), output_text(two)
    other = await drive(adapter, second, context_id="c-mt-other", task_id="t-mt-3")
    assert expect_memory not in output_text(other), "memory leaked across contexts"


async def assert_isolated_callers(
    adapter: InboundAdapter, first: str, second: str, expect_memory: str
) -> None:
    """Memory belongs to the caller as well as the context: another principal sending the
    same ``contextId`` must not see it (nothing ties a ``contextId`` to the caller that
    started it), nor an anonymous turn. The owner's own follow-up does see it."""
    alice, bob = caller("key:alice"), caller("key:bob")
    one = await drive(adapter, first, context_id="c-iso", task_id="t-iso-1", principal=alice)
    assert not any(isinstance(e, Failed) for e in one), one
    other = await drive(adapter, second, context_id="c-iso", task_id="t-iso-2", principal=bob)
    assert not any(isinstance(e, Failed) for e in other), other
    assert expect_memory not in output_text(other), "memory leaked across callers"
    anon = await drive(adapter, second, context_id="c-iso", task_id="t-iso-3")
    assert expect_memory not in output_text(anon), "memory leaked to an anonymous caller"
    own = await drive(adapter, second, context_id="c-iso", task_id="t-iso-4", principal=alice)
    assert expect_memory in output_text(own), output_text(own)


async def assert_failure_maps(adapter_raising: InboundAdapter, *, match: str | None = None) -> None:
    """A framework failure ends the turn as a failure: the exception propagates (the executor
    fails the task) or the adapter yields ``Failed`` as its final event. With ``match``, the
    exception message (or the ``Failed`` error) must match that regex (``re.search``)."""
    try:
        events = await drive(adapter_raising, "fail")
    except asyncio.CancelledError:
        raise AssertionError("a failure must not surface as cancellation") from None
    except Exception as e:  # noqa: BLE001 - any framework error is a valid failure
        if match is not None:
            assert re.search(match, str(e)), f"{type(e).__name__}: {e!s} does not match {match!r}"
        return
    assert events and isinstance(events[-1], Failed), events
    assert not any(isinstance(e, Done) for e in events), events
    if match is not None:
        assert re.search(match, events[-1].error), f"{events[-1]} does not match {match!r}"


_START_YIELDS = 20  # loop iterations a turn gets to start when no ``started`` event is given


async def assert_cancellable(
    adapter: InboundAdapter,
    *,
    within_s: float = 2.0,
    started: asyncio.Event | None = None,
    stopped: asyncio.Event | None = None,
) -> None:
    """Cancelling the task consuming ``run`` ends it promptly with ``CancelledError``.

    ``adapter`` must block until cancelled. ``started`` (set by the framework fake once the
    turn is in flight) is awaited before cancelling; ``stopped`` (set when the framework's own
    work is torn down) must be set within ``within_s`` too, which proves the adapter cancels
    background work and does not just stop reading it."""
    task = asyncio.create_task(drive(adapter, "block", context_id="c-cancel", task_id="t-cancel"))
    if started is not None:
        waiter = asyncio.create_task(started.wait())
        done, _ = await asyncio.wait(
            {task, waiter}, timeout=within_s, return_when=asyncio.FIRST_COMPLETED
        )
        if waiter not in done:
            waiter.cancel()
            task.cancel()
            raise AssertionError("the turn never started")
    else:
        for _ in range(_START_YIELDS):  # let the turn get going (no timed sleep)
            await asyncio.sleep(0)
    assert not task.done(), "the adapter must block until cancelled"
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=within_s)
    assert task in done, f"run did not end within {within_s}s of cancellation"
    assert task.cancelled(), "cancellation must propagate as CancelledError"
    if stopped is not None:
        await asyncio.wait_for(stopped.wait(), within_s)


# -- outbound -----------------------------------------------------------------------------


def _record(pid: str) -> PartnerRecord:
    card = {
        "name": pid.title(),
        "description": f"Fake partner {pid}.",
        "skills": [{"id": "ping", "name": "Ping", "description": "Answers pings"}],
    }
    return PartnerRecord(id=pid, card=card, card_hash=f"hash-{pid}", tier="internal")


class _FakeRegistry:
    def __init__(self, records: list[PartnerRecord]) -> None:
        self._records = records

    def active(self) -> list[PartnerRecord]:
        return list(self._records)


class FakePartnerClient:
    """The ``PartnerClient`` surface ``invoke`` uses: ``consult``, ``check``, ``cancel``,
    ``wait_any``, ``owns`` (same signatures as ``PartnerClient``; ``test_contract.py``
    checks) and ``registry.active()``. Every call except ``owns`` is recorded in ``calls``
    as ``(method, kwargs)``; ``consult`` completes with ``"pong:<message>"`` as task
    ``pt-1`` and records its handle in ``handles`` like ``PartnerClient`` does (inbound
    task, caller id and owner), so ``owns`` answers with the real predicate."""

    def __init__(self, partners: Iterable[str] = ("pinger",)) -> None:
        self.registry = _FakeRegistry([_record(p) for p in partners])
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.handles: dict[tuple[str, str], dict[str, Any]] = {}

    def add_handle(
        self,
        partner_id: str,
        task_id: str,
        *,
        inbound_task_id: str | None = None,
        caller_id: str | None = None,
        owner: str | None = None,
    ) -> None:
        """Record a partner task's handle, as if someone else had started it."""
        self.handles[(partner_id, task_id)] = {
            "partner_id": partner_id,
            "task_id": task_id,
            "inbound_task_id": inbound_task_id,
            "caller_id": caller_id,
            "owner": owner,
        }

    async def owns(
        self,
        partner_id: str,
        task_id: str,
        *,
        inbound_task_id: str | None,
        caller_id: str | None,
        owner: str | None,
    ) -> bool:
        return owned(
            self.handles.get((partner_id, task_id)),
            inbound_task_id=inbound_task_id,
            caller_id=caller_id,
            owner=owner,
        )

    def tools(self) -> list[PartnerTool]:
        """``partner_tools`` for this client's partners (the consult tools first)."""
        return partner_tools(self.registry)  # type: ignore[arg-type]

    @property
    def consults(self) -> list[dict[str, Any]]:
        return [kw for method, kw in self.calls if method == "consult"]

    async def consult(
        self,
        partner_id: str,
        message: str,
        *,
        files: Iterable[tuple[str, bytes, str]] = (),
        data: dict[str, Any] | None = None,
        task_id: str | None = None,
        context_id: str | None = None,
        wait_seconds: float = 30.0,
        inbound_task_id: str | None = None,
        caller: Principal | None = None,
        classification: str | None = None,
        owner: str | None = None,
    ) -> ToolResult:
        self.calls.append(
            (
                "consult",
                {
                    "partner_id": partner_id,
                    "message": message,
                    "files": list(files),
                    "data": data,
                    "task_id": task_id,
                    "context_id": context_id,
                    "wait_seconds": wait_seconds,
                    "inbound_task_id": inbound_task_id,
                    "caller": caller,
                    "classification": classification,
                    "owner": owner,
                },
            )
        )
        if (partner_id, "pt-1") not in self.handles:
            principal = caller if caller is not None else current_principal.get()
            self.add_handle(
                partner_id,
                "pt-1",
                inbound_task_id=inbound_task_id or current_inbound_task.get(),
                caller_id=principal.id if principal is not None else None,
                owner=owner,
            )
        return ToolResult(
            partner=partner_id,
            task_id="pt-1",
            context_id="pc-1",
            state="completed",
            text=f"pong:{message}",
        )

    async def check(
        self, partner_id: str, task_id: str, *, caller: Principal | None = None
    ) -> ToolResult:
        self.calls.append(
            ("check", {"partner_id": partner_id, "task_id": task_id, "caller": caller})
        )
        return ToolResult(partner=partner_id, task_id=task_id, state="completed", text="checked")

    async def cancel(
        self, partner_id: str, task_id: str, *, caller: Principal | None = None
    ) -> ToolResult:
        self.calls.append(
            ("cancel", {"partner_id": partner_id, "task_id": task_id, "caller": caller})
        )
        return ToolResult(partner=partner_id, task_id=task_id, state="canceled")

    async def wait_any(self, handles: list[tuple[str, str]], seconds: float) -> list[ToolResult]:
        self.calls.append(("wait_any", {"handles": list(handles), "seconds": seconds}))
        return [ToolResult(partner=p, task_id=t, state="completed") for p, t in handles]


async def assert_projection(
    tools: list[Any],
    call: Callable[[Any, dict], Awaitable[Any]],
    *,
    client: FakePartnerClient | None = None,
) -> None:
    """Calling the first projected tool (built from ``FakePartnerClient.tools()``) with
    ``{"message": "hi"}`` through ``call(tool, args)`` reaches ``FakePartnerClient.consult``
    and returns the envelope ``invoke`` builds: a JSON string (or the dict itself, for
    projections that return plain dicts). With ``client``, the recorded call is checked too."""
    assert tools, "no projected tools"
    out = await call(tools[0], {"message": "hi"})
    envelope = json.loads(out) if isinstance(out, str) else out
    assert isinstance(envelope, dict), f"envelope is {type(out).__name__}"
    assert envelope["state"] == "completed", envelope
    assert envelope["partner"] == "pinger" and envelope["text"] == "pong:hi", envelope
    assert envelope["task_id"] == "pt-1"
    if client is not None:
        assert [c["message"] for c in client.consults] == ["hi"]
        assert client.consults[0]["partner_id"] == "pinger"


def _envelope(out: Any) -> dict[str, Any]:
    envelope = json.loads(out) if isinstance(out, str) else out
    assert isinstance(envelope, dict), f"envelope is {type(out).__name__}"
    return envelope


async def assert_owned_tasks_only(
    tools: list[Any],
    call: Callable[[Any, dict], Awaitable[Any]],
    client: FakePartnerClient,
) -> None:
    """Partner tasks belong to whoever started them. ``tools`` are the projection of
    ``client.tools()`` (same order), called through ``call(tool, args)``.

    Inside inbound task ``t-owner``, checking, cancelling, waiting on or replying to a
    partner task another inbound task started answers ``unknown task`` (the same envelope
    the sidecar gives) and nothing reaches the client; a partner the tools cannot reach
    answers ``unknown partner``. The task this turn started itself can be checked and
    replied to."""
    ptools = client.tools()
    assert len(tools) == len(ptools), "the projection must keep client.tools() in order"
    by_kind = {p.kind: t for p, t in zip(ptools, tools, strict=True) if p.kind != "consult"}
    consult = next(t for p, t in zip(ptools, tools, strict=True) if p.kind == "consult")
    pid = next(p.partner_id for p in ptools if p.kind == "consult")
    assert pid is not None
    client.add_handle(pid, "foreign", inbound_task_id="t-other", caller_id="key:other")
    foreign = {"partner_id": pid, "task_id": "foreign"}
    unknown_task = {"partner": pid, "state": "unavailable", "reason": "unknown task"}
    with use_inbound("t-owner", caller("key:owner")):
        sent = len(client.calls)
        attempts = [
            (by_kind["check"], foreign),
            (by_kind["cancel"], foreign),
            (by_kind["wait"], {"tasks": [foreign], "seconds": 0}),
            (consult, {"message": "hijack", "task_id": "foreign"}),
        ]
        for tool, args in attempts:
            assert _envelope(await call(tool, args)) == unknown_task, args
        hidden = {"partner_id": "no-such-partner", "task_id": "foreign"}
        out = _envelope(await call(by_kind["check"], hidden))
        assert out == {**unknown_task, "partner": "no-such-partner", "reason": "unknown partner"}
        assert client.calls[sent:] == [], "a foreign partner task reached the client"
        # The turn's own partner task: started here, so follow-ups go through.
        first = _envelope(await call(consult, {"message": "hi"}))
        own = {"partner_id": pid, "task_id": first["task_id"]}
        assert _envelope(await call(by_kind["check"], own))["state"] == "completed"
        reply = {"message": "more", "task_id": own["task_id"]}
        assert _envelope(await call(consult, reply))["state"] == "completed"
        assert [m for m, _ in client.calls[sent:]] == ["consult", "check", "consult"]
