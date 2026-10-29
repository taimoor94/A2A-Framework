"""Run-scoped consult tokens (``a2agw.gateway.tokens``)."""

from __future__ import annotations

import asyncio
import hashlib
import time

import pytest

from a2agw.context.call_context import CallContext
from a2agw.gateway.tokens import Binding, ConsultTokens
from a2agw.security.principal import Principal

ALICE = Principal("key:alice", "api_key", frozenset())


def test_issue_resolve_revoke():
    store = ConsultTokens(url="http://gw/a2agw/v1")
    cc = CallContext.new("coder", deadline_s=600)
    grant = store.issue("coder", "task-1", cc, ALICE)
    assert grant.url == "http://gw/a2agw/v1"
    assert len(grant.token) >= 43
    binding = store.resolve(grant.token)
    assert isinstance(binding, Binding)
    assert (binding.agent_id, binding.inbound_task_id, binding.call, binding.caller) == (
        "coder",
        "task-1",
        cc,
        ALICE,
    )
    assert binding.expires_at == grant.expires_at
    # The earliest of the call deadline and ttl_s.
    assert grant.expires_at == cc.deadline

    other = store.issue("coder", "task-2", None, None)
    assert store.resolve(other.token).inbound_task_id == "task-2"
    assert other.expires_at <= time.time() + 3600

    store.revoke_task("task-1")
    assert store.resolve(grant.token) is None
    assert store.resolve(other.token) is not None  # only that task's grants
    store.revoke(other)
    assert store.resolve(other.token) is None
    assert store.resolve("") is None and store.resolve("not-a-token") is None


def test_expired_token_unresolvable():
    store = ConsultTokens(ttl_s=60)
    grant = store.issue("coder", "task-1", None, None)
    assert store.resolve(grant.token, now=grant.expires_at - 1) is not None
    assert store.resolve(grant.token, now=grant.expires_at) is None
    # A call context whose deadline has passed yields an already-expired grant.
    past = CallContext.new("coder", deadline_s=-1)
    assert store.resolve(store.issue("coder", "task-2", past, None).token) is None


def test_only_digest_stored():
    store = ConsultTokens()
    grant = store.issue("coder", "task-1", None, ALICE)
    assert grant.token not in repr(store)
    assert grant.token not in repr(vars(store))
    digest = hashlib.sha256(grant.token.encode()).hexdigest()
    assert digest in repr(vars(store))


async def test_revocation_cancels_calls_in_flight():
    store = ConsultTokens()
    grant = store.issue("coder", "task-1", None, None)
    binding = store.resolve(grant.token)
    call = asyncio.create_task(asyncio.Event().wait())
    with store.track(binding, call) as live:
        assert live
        store.revoke_task("task-1")
        await asyncio.gather(call, return_exceptions=True)
    assert call.cancelled()
    # A binding whose grant is gone cannot start a tracked call.
    late = asyncio.create_task(asyncio.Event().wait())
    with store.track(binding, late) as live:
        assert not live
    late.cancel()
    await asyncio.gather(late, return_exceptions=True)


async def test_host_consult_url_overrides_the_grant_url(tmp_path):
    from a2agw.serve.host import AgentHost

    db = f"sqlite+aiosqlite:///{tmp_path / 'g.db'}"
    default = AgentHost("http://localhost:8000/", db_url=db)
    assert default.consult_tokens.issue("a", "t", None, None).url == (
        "http://localhost:8000/a2agw/v1"
    )
    host = AgentHost(
        "http://localhost:8000", db_url=db, consult_url="http://gateway:8000/a2agw/v1/"
    )
    grant = host.consult_tokens.issue("coder", "t1", None, None)
    assert grant.url == "http://gateway:8000/a2agw/v1"
    # The cards keep advertising base_url.
    assert host.base_url == "http://localhost:8000"
    for bad in ("gateway:8000/a2agw/v1", "ftp://gw/a2agw/v1", "http:///a2agw/v1", ""):
        with pytest.raises(ValueError):
            AgentHost("http://localhost:8000", db_url=db, consult_url=bad)


async def test_grant_issuer_links_the_trace_without_a_call_context(spans):
    """A turn with no call context still gets a grant whose call carries the turn's span."""
    from opentelemetry import trace

    from a2agw.core.spi import InboundContext
    from a2agw.gateway.tokens import GrantIssuer

    issuer = GrantIssuer(ConsultTokens(url="http://gw/a2agw/v1"))
    ctx = InboundContext(
        agent_id="coder",
        task_id="t1",
        context_id="c1",
        text="hi",
        parts=[],
        message=None,
        principal=None,
        call=None,
        metadata={},
        resumed=False,
    )
    with trace.get_tracer("t").start_as_current_span("a2agw.inbound") as span:
        grant = await issuer(ctx)
    binding = issuer.tokens.resolve(grant.token)
    assert binding.call is not None and binding.call.traceparent
    ctx_ = span.get_span_context()
    _, trace_id, span_id, _ = binding.call.traceparent.split("-")
    assert (trace_id, span_id) == (f"{ctx_.trace_id:032x}", f"{ctx_.span_id:016x}")
