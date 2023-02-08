import logging
import os
import sys
from typing import Optional

from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

from . import get_resource

default_traces_sampling = 0.1


def get_tracer(traces_config: dict, meta: Optional[dict] = None) -> trace.Tracer:
    if (
        "PYTEST_CURRENT_TEST" not in os.environ
        and "pytest" not in sys.modules
        and traces_config.get("enabled")
    ):
        resource = get_resource(meta)

        try:
            rate = float(traces_config.get("sampling", default_traces_sampling))
            if 0.0 < rate <= 1.0:
                sampler = TraceIdRatioBased(rate)
            else:
                raise Exception(
                    f"trace sampling value (float) missing/out-of-range {traces_config.get('sampling')}, setting to {default_traces_sampling}"
                )
        except Exception:
            logging.exception(
                f"trace sampling value (float) missing/out-of-range {traces_config.get('sampling')}, setting to {default_traces_sampling}"
            )
            sampler = TraceIdRatioBased(default_traces_sampling)

        if traces_config.get("exporter") == "otlp":
            logging.info(f"tracer sampling at {sampler.rate}")

            provider = TracerProvider(resource=resource, sampler=sampler)
            processor = BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=traces_config.get("addr", ""),
                    insecure=traces_config.get("insecure", False),
                )
            )
            provider.add_span_processor(processor)
        elif traces_config.get("exporter") == "jaeger":
            provider = TracerProvider(resource=resource)
            JaegerExporter(
                agent_host_name=traces_config.get("addr", "").split(":")[0],
                agent_port=int(traces_config.get("addr", "").split(":")[1]),
            )
            processor = BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=traces_config.get("addr", ""),
                    insecure=traces_config.get("insecure", False),
                )
            )
            provider.add_span_processor(processor)
        else:
            logging.info("no exporter for tracer, disabling")
            return trace.get_tracer(__name__)

        # Sets the global default tracer provider
        trace.set_tracer_provider(provider)

    # Creates a tracer from the global tracer provider
    # If no provider/exporter is specified, tracing will be effectively disabled
    return trace.get_tracer(__name__)
