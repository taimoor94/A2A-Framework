"""Run-scoped consult tokens (``a2agw.gateway.tokens``)."""

from __future__ import annotations

import asyncio
import hashlib
import time

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
