"""
Opt-in OpenTelemetry tracing shared by both services (ENABLE_OTEL=true).

Off by default: a full attack campaign already produces a lot of log
noise, and most people running this locally don't have a trace backend
to send spans to. When enabled, FastAPIInstrumentor auto-traces every
HTTP request (chat turns, campaign runs, regression runs) and
`get_tracer()` lets call sites (planner.py, target_agent/agents.py) add
finer-grained spans around individual attack attempts / LLM calls.

Exports to the console by default (zero extra setup), or to any OTLP/HTTP
collector (Jaeger, Tempo, Honeycomb, ...) if OTEL_EXPORTER_OTLP_ENDPOINT
is set.

Every import in here is defensive: if the optional `opentelemetry-*`
packages aren't installed, `get_tracer()` still returns something
call sites can use unconditionally (a no-op tracer), and
`setup_tracing()` just does nothing instead of crashing either service.
"""
from __future__ import annotations

import contextlib
import os


def _enabled() -> bool:
    return os.getenv("ENABLE_OTEL", "false").lower() == "true"


class _NoOpSpan:
    def set_attribute(self, *args, **kwargs):
        pass

    def record_exception(self, *args, **kwargs):
        pass


class _NoOpTracer:
    @contextlib.contextmanager
    def start_as_current_span(self, name, **kwargs):
        yield _NoOpSpan()


def get_tracer(name: str):
    """Safe to call unconditionally, whether or not OTel is installed or
    enabled -- returns a real tracer only when both are true."""
    if not _enabled():
        return _NoOpTracer()
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except Exception:
        return _NoOpTracer()


def setup_tracing(service_name: str, app) -> None:
    """Call once per service, right after constructing the FastAPI app."""
    if not _enabled():
        return
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))

        otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if otlp_endpoint:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
        else:
            exporter = ConsoleSpanExporter()

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        # Missing/incompatible otel packages, bad OTLP endpoint, etc. --
        # tracing just stays off; never take down either service for this.
        pass
