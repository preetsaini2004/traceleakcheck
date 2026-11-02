"""A stand-in for "an app in another language": a separate process that sets up OpenTelemetry only
from the standard OTEL_* env vars. Modes: leak, clean, silent, server <port>."""

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

mode = sys.argv[1]
if mode == "silent":  # never sets up an exporter
    sys.exit(0)

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
tracer = provider.get_tracer("otel_app")
key = os.environ.get("OPENAI_API_KEY", "")

if mode == "leak":
    try:
        with tracer.start_as_current_span("llm.call"):
            raise PermissionError(f"gateway rejected key {key}")
    except PermissionError:
        pass  # the span recorded it on the way out
elif mode == "clean":
    with tracer.start_as_current_span("llm.call") as span:
        span.set_attribute("model", "gpt-4o-mini")
elif mode == "server":
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with tracer.start_as_current_span("chat") as span:
                span.set_attribute("prompt", parse_qs(urlparse(self.path).query).get("m", [""])[0])
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    try:
        HTTPServer(("127.0.0.1", int(sys.argv[2])), Handler).serve_forever()
    except KeyboardInterrupt:
        pass

provider.shutdown()  # flush, as the README asks every app to
