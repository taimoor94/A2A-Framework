import pytest
from conftest import INSTALLED_EXPORTERS
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


@pytest.fixture(scope="session")
def _span_exporter():
    """One global provider per process: installed once for the whole session."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    INSTALLED_EXPORTERS.append(exporter)
    return exporter


@pytest.fixture
def spans(_span_exporter):
    _span_exporter.clear()
    yield _span_exporter
    _span_exporter.clear()
