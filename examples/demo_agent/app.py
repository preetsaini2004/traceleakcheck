"""Toy agent instrumented the way real apps are: OTel SDK configured from OTEL_* env vars.

It redacts API keys from the prompt before recording it, and that redaction has a passing unit
test. The key still leaks: an HTTP error message echoes it, and the SDK copies exception text
into the span's exception event AND its status message.
"""

import re

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))  # endpoint from env
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("demo-agent")

_KEY = re.compile(r"sk-[A-Za-z0-9_-]{20,}")


def redact(text: str) -> str:
    return _KEY.sub("[REDACTED]", text)


def call_llm(prompt: str, api_key: str) -> str:
    # Stand-in for an HTTP client error that includes the request URL, query string and all.
    raise ConnectionError(f"Max retries exceeded with url: /v1/chat?key={api_key}")


def run_agent(prompt: str, api_key: str) -> str:
    with tracer.start_as_current_span("agent.run") as span:
        span.set_attribute("gen_ai.prompt", redact(prompt))
        try:
            with tracer.start_as_current_span("llm.call"):
                return call_llm(prompt, api_key)
        except ConnectionError:
            return "sorry, the model is unavailable"
