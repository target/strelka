import logging
import os
import sys
from typing import Optional, Dict

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

from . import get_resource

default_traces_sampling = 0.1

def get_sampler(rate: float) -> TraceIdRatioBased:
    """
    Ensures the provided sampling rate is valid and within range.
    If invalid, defaults to `default_traces_sampling`.
    """
    try:
        rate = float(rate)
        assert 0.0 < rate <= 1.0, "Rate out of range"
        return TraceIdRatioBased(rate)
    except (ValueError, TypeError, AssertionError):
        logging.exception(f"Invalid trace sampling value: {rate}, using default {default_traces_sampling}")
        return TraceIdRatioBased(default_traces_sampling)

def get_exporter(traces_config: Dict) -> Optional[BatchSpanProcessor]:
    """
    Returns the appropriate span processor based on the provided tracing configuration.
    Uses a mapping approach to improve readability and maintainability.
    """
    exporter_map = {
        "otlp-grpc": lambda addr, auth: _create_otlp_grpc_exporter(addr, auth),
        "otlp-http": lambda addr, _: _create_otlp_http_exporter(addr),
        "jaeger-http-thrift": lambda addr, _: _create_jaeger_http_exporter(addr),
        "jaeger-udp-thrift": lambda addr, _: _create_jaeger_udp_exporter(addr),
    }
    
    exporter_type = traces_config.get("exporter")
    addr = traces_config.get("addr", "")
    auth = traces_config.get("auth", {})
    
    return exporter_map.get(exporter_type, lambda *_: _log_no_exporter())(addr, auth)

def _create_otlp_grpc_exporter(addr: str, auth: dict) -> BatchSpanProcessor:
    """Creates and returns an OTLP gRPC exporter."""
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    return BatchSpanProcessor(OTLPSpanExporter(endpoint=addr, insecure=not auth))

def _create_otlp_http_exporter(addr: str) -> BatchSpanProcessor:
    """Creates and returns an OTLP HTTP exporter."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    return BatchSpanProcessor(OTLPSpanExporter(endpoint=addr))

def _create_jaeger_http_exporter(addr: str) -> BatchSpanProcessor:
    """Creates and returns a Jaeger HTTP Thrift exporter."""
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    return BatchSpanProcessor(JaegerExporter(collector_endpoint=addr))

def _create_jaeger_udp_exporter(addr: str) -> Optional[BatchSpanProcessor]:
    """Creates and returns a Jaeger UDP Thrift exporter. Validates host:port format."""
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    try:
        host, port = addr.split(":")
        return BatchSpanProcessor(JaegerExporter(agent_host_name=host, agent_port=int(port), udp_split_oversized_batches=True))
    except ValueError:
        logging.error("Invalid Jaeger UDP address format. Expected host:port")
        return None

def _log_no_exporter():
    """Logs when no valid exporter is found, disabling tracing."""
    logging.info("No valid exporter specified, disabling tracing.")
    return None

def get_tracer(traces_config: dict, meta: Optional[dict] = None) -> trace.Tracer:
    """
    Initializes and returns an OpenTelemetry tracer.
    - If testing (`pytest` detected), returns a no-op tracer.
    - If no exporter is configured, tracing is disabled.
    - Otherwise, sets up a `TracerProvider` with a configured exporter and sampler.
    """
    if "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules or not traces_config.get("exporter"):
        return trace.get_tracer(__name__)
    
    sampler = get_sampler(traces_config.get("sampling", default_traces_sampling))
    provider = TracerProvider(resource=get_resource(meta), sampler=sampler)
    processor = get_exporter(traces_config)
    
    if processor:
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logging.info(f"Tracer initialized with sampling rate: {sampler.rate}")
    
    return trace.get_tracer(__name__)
