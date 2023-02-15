import logging
import os
import sys
from typing import Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

from . import get_resource

default_traces_sampling = 0.1


def get_tracer(traces_config: dict, meta: Optional[dict] = None) -> trace.Tracer:
    if (
        "PYTEST_CURRENT_TEST" not in os.environ
        and "pytest" not in sys.modules
        and traces_config.get("exporter")
    ):
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

        resource = get_resource(meta)
        provider = TracerProvider(resource=resource, sampler=sampler)

        if traces_config.get("exporter") == "otlp-grpc":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            processor = BatchSpanProcessor(
                OTLPSpanExporter(
                    endpoint=traces_config.get("addr", ""),
                    insecure=False if traces_config.get("auth", {}) else True,
                )
            )

        elif traces_config.get("exporter") == "otlp-http":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            processor = BatchSpanProcessor(
                OTLPSpanExporter(endpoint=traces_config.get("addr", ""))
            )

        elif traces_config.get("exporter") == "jaeger-http-thrift":
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter

            processor = BatchSpanProcessor(
                JaegerExporter(collector_endpoint=traces_config.get("addr", ""))
            )

        elif traces_config.get("exporter") == "jaeger-udp-thrift":
            from opentelemetry.exporter.jaeger.thrift import JaegerExporter

            processor = BatchSpanProcessor(
                JaegerExporter(
                    agent_host_name=traces_config.get("addr", "").split(":")[0],
                    agent_port=int(traces_config.get("addr", "").split(":")[1]),
                    udp_split_oversized_batches=True,
                )
            )

        else:
            logging.info("no exporter for tracer, disabling")

            return trace.get_tracer(__name__)

        logging.info(f"tracer sampling at {sampler.rate}")
        provider.add_span_processor(processor)

        # Sets the global default tracer provider
        trace.set_tracer_provider(provider)

    # Creates a tracer from the global tracer provider
    # If no provider/exporter is specified, tracing will be effectively disabled
    return trace.get_tracer(__name__)
