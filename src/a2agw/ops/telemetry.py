"""OpenTelemetry tracing and JSON logs.

One distributed trace covers a whole agent network: every inbound task is an
``a2agw.inbound`` span, every partner call an ``a2agw.partner_call`` span, and the trace
context travels between agents in the call-context extension's ``traceparent`` field.

Spans carry identifiers and states only, never message text, credentials, headers or the
call-context contents. To export over OTLP, build an ``OTLPSpanExporter`` yourself and pass
it as ``exporter``; this package adds no OTLP dependency.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

if TYPE_CHECKING:
    from opentelemetry.context import Context
    from opentelemetry.sdk.trace.export import SpanExporter

    from a2agw.context.call_context import CallContext

logger = logging.getLogger(__name__)

_PROPAGATOR = TraceContextTextMapPropagator()


def get_tracer() -> trace.Tracer:
    """Fetched at call time so a provider installed later still applies."""
    return trace.get_tracer("a2agw")


def extract_parent(traceparent: str | None) -> Context | None:
    """The parent context carried by a ``traceparent`` value, or None to start a new root."""
    if not traceparent:
        return None
    return _PROPAGATOR.extract({"traceparent": traceparent}, otel_context.get_current())


def with_current_traceparent(cc: CallContext) -> CallContext:
    """``cc`` with its traceparent replaced by the current span's (unchanged if no span)."""
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)
    tp = carrier.get("traceparent")
    return dataclasses.replace(cc, traceparent=tp) if tp else cc


class JsonFormatter(logging.Formatter):
    """One JSON object per record, with the active trace and span ids (hex, or empty)."""

    def format(self, record: logging.LogRecord) -> str:
        ctx = trace.get_current_span().get_span_context()
        valid = ctx.is_valid
        out = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "trace_id": format(ctx.trace_id, "032x") if valid else "",
            "span_id": format(ctx.span_id, "016x") if valid else "",
        }
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            out["stack"] = self.formatStack(record.stack_info)
        return json.dumps(out, default=str)


def _install_json_logs() -> None:
    """Format every root-logger handler as JSON; add a stderr handler if there are none.

    The root logger's level is left unchanged. Calling this repeatedly adds nothing.
    """
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    for handler in root.handlers:
        handler.setFormatter(JsonFormatter())


def setup_telemetry(
    service_name: str,
    *,
    exporter: SpanExporter | None = None,
    json_logs: bool = True,
) -> TracerProvider:
    """Create a tracer provider and install it globally unless one is already set.

    OpenTelemetry allows one global provider per process: if one exists, a warning is logged
    and the existing provider is returned (with ``exporter`` not attached).

    ``json_logs`` applies to all root-logger handlers (see ``_install_json_logs``).
    """
    current = trace.get_tracer_provider()
    # The default is a proxy (or no-op) provider, not an SDK one.
    if isinstance(current, TracerProvider):
        logger.warning("a tracer provider is already installed; telemetry setup ignored")
        result = current
    else:
        result = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if exporter is not None:
            result.add_span_processor(
                SimpleSpanProcessor(exporter)
                if isinstance(exporter, InMemorySpanExporter)
                else BatchSpanProcessor(exporter)
            )
        trace.set_tracer_provider(result)
    if json_logs:
        _install_json_logs()
    return result
