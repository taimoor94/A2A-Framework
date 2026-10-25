"""Tracing across agents, span hygiene and JSON logs."""

from __future__ import annotations

import io
import json
import logging

from opentelemetry import trace

from a2agw.core.events import Done
from a2agw.ops.telemetry import JsonFormatter
from tests.integration.test_cascade import Fn, env, fast, spec  # noqa: F401

MARKER = "UNIQUE-MARKER-7f3a9c"
SECRET = "sekrit-token-91d2"


async def test_single_trace_across_two_agents(env, spans):  # noqa: F811
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


async def test_no_secrets_in_span_attributes(env, spans, monkeypatch):  # noqa: F811
    monkeypatch.setenv("PARTNER_TOKEN", SECRET)

    async def a_run(ctx):
        res = await e.host.client.consult("b", f"please {MARKER}", wait_seconds=5)
        yield Done(text=res.text or "ok")

    async def b_run(ctx):
        yield Done(text=f"reply {MARKER}")

    e = await env(spec("a", Fn(a_run)), spec("b", Fn(b_run)))
    await e.register("b")
    await e.send("a", f"start {MARKER}")

    done = spans.get_finished_spans()
    assert done
    for s in done:
        for k, v in s.attributes.items():
            assert MARKER not in str(v), (s.name, k)
            assert SECRET not in str(v), (s.name, k)
            assert "traceparent" not in str(k)


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
    assert inside["logger"] == "a2agw.test.jsonlog" and inside["ts"]
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
