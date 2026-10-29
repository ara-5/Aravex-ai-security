"""OpenTelemetry tracing setup.

Every gateway request becomes a span carrying the full identity chain and
decision as attributes, so a trace backend (Jaeger/Tempo/etc.) shows exactly
which agent did what, and why the policy engine decided what it decided.

Defaults to a console exporter so the demo runs with zero external
dependencies; point OTEL_EXPORTER_OTLP_ENDPOINT at a collector to ship
spans out in a real deployment.

Both exporters go through BatchSpanProcessor, never SimpleSpanProcessor.
SimpleSpanProcessor exports synchronously, in the request-handling thread,
before the response can be returned -- for the console exporter that means
a full pretty-printed JSON dump to stdout on every single request. A load
test (scripts/loadtest.py) caught exactly this: p50 latency under
concurrency 20 went from single-digit milliseconds to multiple seconds.
BatchSpanProcessor exports on a background thread instead, which is the
correct choice for a console exporter too, not just OTLP.
"""
from __future__ import annotations

import os

from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

_configured = False


def configure_tracing(service_name: str = "aegisai-gateway") -> None:
    global _configured
    if _configured:
        return

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    else:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _configured = True


def get_tracer():
    configure_tracing()
    return trace.get_tracer("aegisai.gateway")
