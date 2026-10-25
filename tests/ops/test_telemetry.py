"""Tracing across agents, span hygiene and JSON logs."""

from __future__ import annotations

import asyncio
import dataclasses
import io
import json
import logging
import re
import time
from datetime import datetime

import pytest
from a2a.types import SendMessageRequest
from cascade_support import Fn, msg, spec
from opentelemetry import trace
from opentelemetry.trace import StatusCode

from a2agw.context.call_context import CallContext
from a2agw.core.events import Done, Failed
from a2agw.ops.telemetry import JsonFormatter

MARKER = "UNIQUE-MARKER-7f3a9c"
SECRET = "sekrit-token-91d2"


async def test_single_trace_across_two_agents(env, spans):
    async def a_run(ctx):
        res = await e.host.client.consult("b", "hello", wait_seconds=5)
        yield Done(text=res.text or "ok")

    async def b_run(ctx):
        yield Done(text="from b")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    await e.register("b")
    await e.send("a", "start")

    done = spans.get_finished_spans()
    assert len({s.context.trace_id for s in done}) == 1
    by_agent = {s.attributes["a2agw.agent_id"]: s for s in done if s.name == "a2agw.inbound"}
    [call] = [s for s in done if s.name == "a2agw.partner_call"]
    assert by_agent["b"].parent.span_id == call.context.span_id
    assert call.parent.span_id == by_agent["a"].context.span_id
    assert call.attributes["a2agw.partner_id"] == "b"
    assert call.attributes["a2agw.tier"] == "internal"
    assert call.attributes["a2agw.result_state"] == "completed"
    assert by_agent["b"].attributes["a2agw.hop"] == by_agent["a"].attributes["a2agw.hop"] + 1


async def test_no_secrets_in_span_attributes(env, spans, monkeypatch):
    monkeypatch.setenv("PARTNER_TOKEN", SECRET)

    async def a_run(ctx):
        res = await e.host.client.consult("b", f"please {MARKER}", wait_seconds=5)
        yield Done(text=res.text or "ok")

    async def b_run(ctx):
        yield Done(text=f"reply {MARKER}")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    await e.register("b")
    await e.send("a", f"start {MARKER}")
    assert_clean(spans)


async def test_failing_partner_call_leaks_no_exception_text(env, spans, monkeypatch):
    async def a_run(ctx):
        try:
            await e.host.client.consult("b", f"please {MARKER}", wait_seconds=5)
        except RuntimeError:
            pass
        yield Done(text="ok")

    async def b_run(ctx):
        yield Done(text="x")

    async def boom(*args, **kwargs):
        raise RuntimeError(f"failed with {MARKER} {SECRET}")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    await e.register("b")
    monkeypatch.setattr(e.host.client, "_consult", boom)
    await e.send("a", "start")

    [call] = [s for s in spans.get_finished_spans() if s.name == "a2agw.partner_call"]
    assert call.status.status_code == StatusCode.ERROR
    assert call.status.description is None
    assert not call.events
    assert_clean(spans)


def assert_clean(spans) -> None:
    done = spans.get_finished_spans()
    assert done
    for s in done:
        texts = [(k, str(v)) for k, v in s.attributes.items()]
        texts.append(("status", str(s.status.description or "")))
        for ev in s.events:
            texts += [(f"event:{ev.name}", str(v)) for v in (ev.attributes or {}).values()]
            texts.append(("event-name", ev.name))
        for k, v in texts:
            assert MARKER not in v, (s.name, k)
            assert SECRET not in v, (s.name, k)
            assert "traceparent" not in k


def inbound_span(spans, agent_id):
    [span] = [
        s
        for s in spans.get_finished_spans()
        if s.name == "a2agw.inbound" and s.attributes["a2agw.agent_id"] == agent_id
    ]
    return span


async def send_with_traceparent(e, agent_id, traceparent):
    cc = CallContext.new("client")
    cc = dataclasses.replace(cc, traceparent=traceparent)
    m = msg("hi")
    m.metadata.update(cc.to_metadata())
    req = SendMessageRequest(message=m)
    return [ev async for ev in e.client(agent_id).send_message(req)]


@pytest.mark.parametrize(
    "garbage",
    ["zzz", "00-" + "0" * 32 + "-" + "0" * 16 + "-01", "x" * 256],
    ids=["junk", "zero", "long"],
)
async def test_garbage_traceparent_behaves_like_absent(env, spans, garbage):
    async def run(ctx):
        yield Done(text="ok")

    e = await env(spec("a", Fn(run)))
    await send_with_traceparent(e, "a", None)
    baseline = inbound_span(spans, "a")
    base_parent = next(
        s for s in spans.get_finished_spans() if s.context.span_id == baseline.parent.span_id
    )
    spans.clear()

    events = await send_with_traceparent(e, "a", garbage)
    assert events
    got = inbound_span(spans, "a")
    parent = next(s for s in spans.get_finished_spans() if s.context.span_id == got.parent.span_id)
    assert parent.name == base_parent.name
    assert got.context.trace_id == parent.context.trace_id


async def test_inbound_error_status_on_failed_event(env, spans):
    async def run(ctx):
        yield Failed(error=f"bad {MARKER}")

    e = await env(spec("a", Fn(run)))
    await e.send("a", "go")
    span = inbound_span(spans, "a")
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description is None
    assert_clean(spans)


async def test_inbound_error_status_on_exception(env, spans):
    async def run(ctx):
        raise RuntimeError(f"boom {MARKER}")
        yield

    e = await env(spec("a", Fn(run)))
    await e.send("a", "go")
    span = inbound_span(spans, "a")
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description is None
    assert not span.events
    assert_clean(spans)


async def test_inbound_error_status_on_unrequested_cancel(env, spans):
    async def run(ctx):
        raise asyncio.CancelledError
        yield

    e = await env(spec("a", Fn(run)))
    await e.send("a", "go")
    span = inbound_span(spans, "a")
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description is None


async def test_inbound_status_unset_on_success(env, spans):
    async def run(ctx):
        yield Done(text="ok")

    e = await env(spec("a", Fn(run)))
    await e.send("a", "go")
    assert inbound_span(spans, "a").status.status_code == StatusCode.UNSET


def test_json_log_carries_trace_ids(spans):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    log = logging.getLogger("a2agw.test.jsonlog")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        with trace.get_tracer("t").start_as_current_span("x") as span:
            log.info("inside %s", "span")
            try:
                raise ValueError("boom")
            except ValueError:
                log.exception("failed")
        log.info("outside")
    finally:
        log.removeHandler(handler)
    inside, failed, outside = (json.loads(line) for line in stream.getvalue().splitlines())
    ctx = span.get_span_context()
    assert inside["trace_id"] == format(ctx.trace_id, "032x")
    assert inside["span_id"] == format(ctx.span_id, "016x")
    assert inside["msg"] == "inside span" and inside["level"] == "INFO"
    assert inside["logger"] == "a2agw.test.jsonlog"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00", inside["ts"])
    created = datetime.fromisoformat(inside["ts"])
    assert abs(created.timestamp() - time.time()) < 60
    assert "ValueError" in failed["exc"] and "exc" not in inside
    assert outside["trace_id"] == "" and outside["span_id"] == ""


def test_setup_telemetry_returns_existing_provider(spans, caplog):
    from opentelemetry.sdk.trace import TracerProvider

    from a2agw.ops.telemetry import setup_telemetry

    installed = trace.get_tracer_provider()
    assert isinstance(installed, TracerProvider)  # the session fixture's
    with caplog.at_level(logging.WARNING, logger="a2agw.ops.telemetry"):
        assert setup_telemetry("svc", json_logs=False) is installed
    assert "already installed" in caplog.text


def test_setup_twice_adds_no_duplicate_handler(spans):
    from a2agw.ops.telemetry import setup_telemetry

    root = logging.getLogger()
    before = list(root.handlers)
    formatters = {h: h.formatter for h in before}  # setup_telemetry re-formats these too
    try:
        setup_telemetry("svc")
        after_first = list(root.handlers)
        setup_telemetry("svc")
        assert root.handlers == after_first
        assert all(isinstance(h.formatter, JsonFormatter) for h in root.handlers)
    finally:
        root.handlers[:] = before
        for h, fmt in formatters.items():
            h.setFormatter(fmt)


async def test_sdk_debug_logs_never_carry_request_data(env, caplog):
    """The a2a SDK logs request bodies, headers and events at DEBUG, aiosqlite every SQL
    statement with its parameters. The gateway caps those loggers at INFO (unless the
    application set their level), so root DEBUG logging puts no message text in the logs."""
    caplog.set_level(logging.DEBUG)

    async def run(ctx):
        yield Done(text="reply-text-77c1")

    e = await env(spec("a", Fn(run)))
    await e.send("a", "secret-text-91f2")
    assert logging.getLogger("a2a").level == logging.getLogger("aiosqlite").level == logging.INFO
    assert "secret-text-91f2" not in caplog.text and "reply-text-77c1" not in caplog.text
    quiet = [r for r in caplog.records if r.name.split(".")[0] in ("a2a", "aiosqlite")]
    assert not [r for r in quiet if r.levelno < logging.INFO]


def test_library_logger_level_set_by_the_application_is_kept():
    from a2agw.ops.telemetry import cap_library_logging

    lg = logging.getLogger("a2a")
    before = lg.level
    try:
        lg.setLevel(logging.DEBUG)  # an explicit opt-in to SDK debug logs
        cap_library_logging()
        assert lg.level == logging.DEBUG
        lg.setLevel(logging.NOTSET)
        cap_library_logging()
        assert lg.level == logging.INFO
    finally:
        lg.setLevel(before)
