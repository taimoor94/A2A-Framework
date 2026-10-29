"""Tests of the adapter contract kit itself."""

from __future__ import annotations

import inspect

import pytest
from adapters.contract import FakePartnerClient, assert_failure_maps, assert_text_stream

from a2agw.adapters._stream import text_chunk
from a2agw.adapters.callable import CallableAdapter
from a2agw.consult.client import PartnerClient
from a2agw.core.events import Done, Failed


@pytest.mark.parametrize(
    "method", ["consult", "check", "cancel", "wait_any", "owns", "owns_context"]
)
def test_fake_partner_client_mirrors_partner_client(method):
    def shape(fn):
        return [(p.name, p.kind, p.default) for p in inspect.signature(fn).parameters.values()]

    assert shape(getattr(FakePartnerClient, method)) == shape(getattr(PartnerClient, method))
    assert inspect.iscoroutinefunction(getattr(FakePartnerClient, method))


def test_text_stream_empty_answer_accepts_bare_done():
    assert_text_stream([Done()], "")
    assert_text_stream([Done(text="")], "")
    with pytest.raises(AssertionError):
        assert_text_stream([], "")
    with pytest.raises(AssertionError):
        assert_text_stream([Done()], "something")


def test_text_stream_rejects_text_both_streamed_and_done():
    with pytest.raises(AssertionError):
        assert_text_stream([text_chunk("x", first=True, last=True), Done(text="x")], "x")


async def test_failure_maps_match():
    def boom(c):
        raise RuntimeError("model exploded")

    async def fails(c):
        yield Failed("partner unreachable")

    await assert_failure_maps(CallableAdapter(boom), match="exploded")
    await assert_failure_maps(CallableAdapter(fails), match="unreachable")
    with pytest.raises(AssertionError):
        await assert_failure_maps(CallableAdapter(boom), match="unrelated")
    with pytest.raises(AssertionError):
        await assert_failure_maps(CallableAdapter(fails), match="unrelated")


async def test_isolated_callers_catches_memory_keyed_on_context_alone():
    from adapters.contract import assert_isolated_callers

    from a2agw.adapters._contexts import context_key

    def remembering(key):
        seen: dict[str, list[str]] = {}

        def fn(c):
            history = seen.setdefault(key(c), [])
            history.append(c.text)
            return "heard: " + ", ".join(history)

        return CallableAdapter(fn)

    await assert_isolated_callers(remembering(context_key), "apples", "pears", "apples")
    with pytest.raises(AssertionError, match="leaked across callers"):
        leaky = remembering(lambda c: c.context_id)
        await assert_isolated_callers(leaky, "apples", "pears", "apples")
    with pytest.raises(AssertionError):  # no memory at all proves nothing
        forgetful = CallableAdapter(lambda c: f"heard: {c.text}")
        await assert_isolated_callers(forgetful, "apples", "pears", "apples")


async def test_owned_tasks_only_catches_a_missing_ownership_check(monkeypatch):
    from adapters.contract import assert_owned_tasks_only

    from a2agw.adapters.callable import as_functions

    client = FakePartnerClient()
    await assert_owned_tasks_only(as_functions(client.tools(), client), lambda f, a: f(**a), client)

    async def everything(self, *args, **kwargs):  # an ownership check that lets all through
        return True

    monkeypatch.setattr(FakePartnerClient, "owns", everything)
    client = FakePartnerClient()
    with pytest.raises(AssertionError):
        await assert_owned_tasks_only(
            as_functions(client.tools(), client), lambda f, a: f(**a), client
        )


def test_messages_separated_needs_the_blank_line():
    from adapters.contract import assert_messages_separated

    def stream(*texts):
        n = len(texts)
        return [text_chunk(t, first=i == 0, last=i == n - 1) for i, t in enumerate(texts)]

    assert_messages_separated(stream("Let me ask.", "\n\nIt is 42."), "Let me ask.", "It is 42.")
    with pytest.raises(AssertionError):
        assert_messages_separated(stream("Let me ask.", "It is 42."), "Let me ask.", "It is 42.")
    with pytest.raises(AssertionError):  # nothing streamed
        assert_messages_separated([Done(text="a\n\nb")], "a", "b")
