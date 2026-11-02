"""The safety filter, proven with the same canaries and receiver traceleakcheck uses."""

import base64
import logging

import pytest
from opentelemetry._logs import LogRecord
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from traceleakcheck import OTLPReceiver, make_canary, scan
from traceleakcheck.guard import REDACTED, Scrubber, add_secret, scrub


def _spans(rx, body, wrap=True, **kw):
    exp = OTLPSpanExporter(endpoint=rx.endpoint + "/v1/traces")
    p = TracerProvider()
    p.add_span_processor(SimpleSpanProcessor(scrub(exp, **kw) if wrap else exp))
    body(p.get_tracer("t"))
    p.shutdown()


def _error_with(value):
    def body(tracer):
        with pytest.raises(ConnectionError):
            with tracer.start_as_current_span("llm.call") as s:
                s.set_attribute("prompt", f"use {value}")
                raise ConnectionError(f"Max retries exceeded with url: /v1/chat?key={value}")
    return body


def test_unwrapped_exporter_leaks_baseline():
    c = make_canary("password")
    with OTLPReceiver() as rx:
        _spans(rx, _error_with(c.value), wrap=False)
        assert len(scan(rx.snapshot(), [c])) >= 3  # attribute, exception event, status


def test_password_from_env_scrubbed_everywhere(monkeypatch):
    c = make_canary("password")  # matches no key pattern: only the env-name rule can catch it
    monkeypatch.setenv("MY_SERVICE_PASSWORD", c.value)
    with OTLPReceiver() as rx:
        _spans(rx, _error_with(c.value))
        payloads = rx.snapshot()
    assert scan(payloads, [c]) == []
    assert REDACTED in str(payloads)


def test_explicit_and_registered_secrets(monkeypatch):
    a, b = make_canary("password"), make_canary("password")
    add_secret(b.value)
    with OTLPReceiver() as rx:
        _spans(rx, _error_with(a.value + " " + b.value), secrets=[a.value], env=False, patterns=False)
        assert scan(rx.snapshot(), [a, b]) == []


@pytest.mark.parametrize("kind", ["openai", "anthropic", "aws", "github", "jwt"])
def test_known_formats_scrubbed_without_registration(kind):
    c = make_canary(kind)
    with OTLPReceiver() as rx:
        _spans(rx, _error_with(c.value), env=False)
        assert scan(rx.snapshot(), [c]) == []


def test_encoded_known_secret_scrubbed():
    c = make_canary("password")
    blob = base64.b64encode(f"x{c.value}y".encode()).decode()
    with OTLPReceiver() as rx:
        _spans(rx, lambda t: t.start_span("s", attributes={"blob": blob}).end(), secrets=[c.value])
        assert scan(rx.snapshot(), [c]) == []


def test_log_body_and_attributes_scrubbed():
    c = make_canary("password")
    with OTLPReceiver() as rx:
        lp = LoggerProvider()
        lp.add_log_record_processor(SimpleLogRecordProcessor(
            scrub(OTLPLogExporter(endpoint=rx.endpoint + "/v1/logs"), secrets=[c.value])))
        lp.get_logger("t").emit(LogRecord(body=f"login {c.value}", attributes={"pw": c.value}))
        lp.shutdown()
        payloads = rx.snapshot()
    assert payloads and scan(payloads, [c]) == []


def test_ordinary_text_untouched():
    s = Scrubber(env=False)
    for text in ("What telescopes do you sell?", "https://shop.example/items?page=2&sort=price",
                 "skip-this-word", "Bearer short"):
        assert s.text(text) == text
    assert s.text("GET /v1/chat?key=abc123&page=2") == f"GET /v1/chat?key={REDACTED}&page=2"


def test_rejects_non_exporters():
    with pytest.raises(TypeError):
        scrub(object())
