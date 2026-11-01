"""Survey harness: one GenAI instrumentation per process, an OpenAI SDK client pointed at a local
fake OpenAI server, and the OTel SDK exporting over OTLP to traceleakcheck's receiver.

SURVEY_LIB  = none | otel-openai-v2 | openllmetry | openinference | logfire | httpx
SURVEY_MODE = default | content | private
  content = the library's content-capture opt-in, set so it actually takes effect
  private = the library's documented opt-out (does it really keep secrets out?)
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

LIB = os.environ.get("SURVEY_LIB", "none")
MODE = os.environ.get("SURVEY_MODE", "default")

MODE_ENV = {
    "content": {
        # The README's `=true` is rejected by 2.4b0 ("Must be one of NO_CONTENT, SPAN_ONLY,
        # EVENT_ONLY, SPAN_AND_EVENT. Defaulting to NO_CONTENT"); the enum needs the opt-in below.
        "otel-openai-v2": {"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "SPAN_AND_EVENT",
                           "OTEL_SEMCONV_STABILITY_OPT_IN": "gen_ai_latest_experimental"},
        "openllmetry": {"TRACELOOP_TRACE_CONTENT": "true"},
    },
    "private": {
        "otel-openai-v2": {"OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": "NO_CONTENT"},
        "openllmetry": {"TRACELOOP_TRACE_CONTENT": "false"},
        "openinference": {"OPENINFERENCE_HIDE_INPUTS": "true", "OPENINFERENCE_HIDE_OUTPUTS": "true"},
    },
}


def _setup_sdk():
    from opentelemetry import _logs, metrics, trace
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    tp = TracerProvider()
    tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tp)
    lp = LoggerProvider()
    lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter()))
    _logs.set_logger_provider(lp)
    try:  # older GenAI instrumentations emit content as events
        from opentelemetry._events import set_event_logger_provider
        from opentelemetry.sdk._events import EventLoggerProvider

        set_event_logger_provider(EventLoggerProvider(lp))
    except ImportError:
        pass
    metrics.set_meter_provider(MeterProvider(metric_readers=[
        PeriodicExportingMetricReader(OTLPMetricExporter(), export_interval_millis=3_600_000)]))


def _instrument():
    os.environ.update(MODE_ENV.get(MODE, {}).get(LIB, {}))
    if LIB == "logfire":
        import logfire  # sets up its own providers; exports to OTEL_EXPORTER_OTLP_* when given

        logfire.configure(send_to_logfire=False, console=False)
        logfire.instrument_openai()
        return
    _setup_sdk()
    if LIB == "otel-openai-v2":
        from opentelemetry.instrumentation.openai_v2 import OpenAIInstrumentor
    elif LIB == "openllmetry":
        from opentelemetry.instrumentation.openai import OpenAIInstrumentor
    elif LIB == "openinference":
        from openinference.instrumentation.openai import OpenAIInstrumentor
    elif LIB == "httpx":
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor as OpenAIInstrumentor
    elif LIB == "none":
        return
    else:
        raise SystemExit(f"unknown SURVEY_LIB {LIB!r}")
    OpenAIInstrumentor().instrument()


_instrument()


# --- fake OpenAI API ---------------------------------------------------------------------------


class _FakeOpenAI(BaseHTTPRequestHandler):
    reply: tuple[int, dict] = (500, {})

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status, body = _FakeOpenAI.reply
        out = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *args):
        pass


class Fake:
    def __init__(self, server):
        self.base_url = f"http://127.0.0.1:{server.server_address[1]}/v1"

    def reply(self, status: int, body: dict) -> None:
        _FakeOpenAI.reply = (status, body)


@pytest.fixture(scope="session")
def fake():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Fake(server)
    server.shutdown()


@pytest.fixture
def client(fake):
    import openai

    def make(api_key: str = "sk-dummy-not-a-canary", **kw):
        return openai.OpenAI(api_key=api_key, base_url=fake.base_url, max_retries=0, **kw)

    return make


def completion(message: dict, finish: str = "stop") -> dict:
    return {
        "id": "chatcmpl-1", "object": "chat.completion", "created": 0, "model": "gpt-4o-mini",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
