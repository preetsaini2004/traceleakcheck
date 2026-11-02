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


def test_sigv4_presigned_url_scrubbed():
    # The URL from opentelemetry-python-contrib#5279: every credential parameter must go.
    url = ("https://bucket.s3.amazonaws.com/obj?X-Amz-Algorithm=AWS4-HMAC-SHA256"
           "&X-Amz-Credential=AKIAEXAMPLE%2F20261101%2Fus-east-1%2Fs3%2Faws4_request"
           "&X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLETOKEN&X-Amz-Signature=abc123")
    assert Scrubber(env=False).text(url) == (
        "https://bucket.s3.amazonaws.com/obj?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={REDACTED}&X-Amz-Security-Token={REDACTED}&X-Amz-Signature={REDACTED}")


@pytest.mark.parametrize("param", ["AWSAccessKeyId", "Signature", "sig", "X-Goog-Signature",
                                   "X-Goog-Credential", "x-amz-signature"])
def test_semconv_query_params_scrubbed(param):
    assert Scrubber(env=False).text(f"https://x.example/o?a=1&{param}=s3cr3tval") == \
        f"https://x.example/o?a=1&{param}={REDACTED}"


def test_plain_env_values_not_scrubbed(monkeypatch):
    plain = {
        "DEPLOY_KEY_NAME": "production",
        "KMS_KEY_REGION": "us-east-1",
        "TOKEN_AUDIENCE": "My-Service",
        "TOKEN_TTL_SECONDS": "86400000",
        "SSH_AUTH_SOCK": "/run/user/1000/ssh-agent.socket",
        "DB_PASSWORD_FILE": "/run/secrets/db_password",
        "SSH_KEY_PATH": "~/.ssh/id_ed25519",
        "TLS_KEY_FILE": "./certs/server.key",
        "WIN_KEY_FILE": "C:\\keys\\server.pem",
        "SHARE_AUTH_PATH": "\\\\fileserver\\keys",
        "AUTH_URL": "https://auth.example.com/login",
    }
    for k, v in plain.items():
        monkeypatch.setenv(k, v)
    s = Scrubber()
    for v in plain.values():
        assert s.text(f"value={v}!") == f"value={v}!"


@pytest.mark.parametrize("name,value", [
    ("SERVICE_API_KEY", "Zx81kQp2Lm9vRt4W"),          # random-looking
    ("DB_PASSWORD", "correcthorsebattery"),           # plain word, but the name is unambiguous
    ("ADMIN_PASSWORD", "correct horse battery"),      # a passphrase with spaces
    ("CLIENT_SECRET", "production"),
    ("REDIS_AUTH_URL", "redis://:hunter2hunter2@cache:6379/0"),  # a URL carrying a password
    ("DB_PASSWORD", "/Xy9!secretpw"),                 # starts like a path, but isn't one
    ("ADMIN_PASSWORD", "~kQp2Lm9vRt"),
    ("SERVICE_API_KEY", ".Zx81kQp2Lm9v"),
    ("API_KEY", "12345678901234"),                   # long all-digit key
    ("ACCESS_TOKEN", "QWERTYUIOPASDFGHJKLZ"),        # long all-capitals key
    ("API_KEY", "qwertyuiopasdfghjklz"),             # long all-lowercase key
    ("AUTH_TOKEN", "Abcdefghijklmnop"),              # looks like one long word
])
def test_secret_env_values_still_scrubbed(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    assert Scrubber().text(f"got {value} here") == f"got {REDACTED} here"


def test_env_read_once_per_export_not_per_string(monkeypatch):
    c, d = make_canary("password"), make_canary("password")
    monkeypatch.setenv("MY_SERVICE_PASSWORD", c.value)
    s = Scrubber()
    assert s.text(c.value) == REDACTED
    monkeypatch.setenv("LATE_PASSWORD", d.value)
    assert s.text(d.value) == d.value  # cached: no environment scan per string
    s.refresh()  # what every export() does
    assert s.text(d.value) == REDACTED


def test_secret_set_while_running_scrubbed_on_next_export(monkeypatch):
    c = make_canary("password")
    with OTLPReceiver() as rx:
        exp = scrub(OTLPSpanExporter(endpoint=rx.endpoint + "/v1/traces"))
        p = TracerProvider()
        p.add_span_processor(SimpleSpanProcessor(exp))
        t = p.get_tracer("t")
        t.start_span("first").end()
        monkeypatch.setenv("LATE_SECRET", c.value)
        t.start_span("second", attributes={"x": c.value}).end()
        p.shutdown()
        assert scan(rx.snapshot(), [c]) == []


def test_resource_and_link_attributes_scrubbed():
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Link

    c = make_canary("password")
    res = Resource({"service.name": "shop", "deploy.token": c.value})
    with OTLPReceiver() as rx:
        p = TracerProvider(resource=res)
        p.add_span_processor(SimpleSpanProcessor(
            scrub(OTLPSpanExporter(endpoint=rx.endpoint + "/v1/traces"), secrets=[c.value])))
        t = p.get_tracer("t")
        parent = t.start_span("parent")
        t.start_span("child", links=[Link(parent.get_span_context(), {"why": c.value})]).end()
        parent.end()
        lp = LoggerProvider(resource=res)
        lp.add_log_record_processor(SimpleLogRecordProcessor(
            scrub(OTLPLogExporter(endpoint=rx.endpoint + "/v1/logs"), secrets=[c.value])))
        lp.get_logger("t").emit(LogRecord(body="hello"))
        p.shutdown()
        lp.shutdown()
        payloads = rx.snapshot()
    assert {sig for sig, _ in payloads} >= {"traces", "logs"}
    assert scan(payloads, [c]) == []
    assert "shop" in str(payloads)  # the rest of the resource survives


def test_dropped_counts_survive_scrubbing(monkeypatch):
    # An app that hits its limits must still tell its backend how much it dropped.
    from opentelemetry.sdk.trace import SpanLimits
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.trace import Link

    c = make_canary("password")
    inner = InMemorySpanExporter()
    p = TracerProvider(span_limits=SpanLimits(
        max_span_attributes=2, max_events=1, max_links=1, max_event_attributes=1, max_link_attributes=1))
    p.add_span_processor(SimpleSpanProcessor(scrub(inner, secrets=[c.value], env=False)))
    t = p.get_tracer("t")
    other = t.start_span("other")
    ctx = other.get_span_context()
    sp = t.start_span("s", attributes={"a": 1, "b": 2, "c": 3, "secret": c.value},
                      links=[Link(ctx), Link(ctx, {"x": 1, "y": c.value})])  # the SDK keeps the newest
    sp.add_event("e1")
    sp.add_event("e2")
    sp.add_event("e3", {"m": 1, "n": c.value})
    sp.end()
    other.end()
    out = next(s for s in inner.get_finished_spans() if s.name == "s")

    assert (out.dropped_attributes, out.dropped_events, out.dropped_links) == (2, 2, 1)
    assert out.links[0].dropped_attributes == 1
    assert out.events[0].dropped_attributes == 1
    assert out.attributes["secret"] == out.links[0].attributes["y"] == out.events[0].attributes["n"] == REDACTED

    monkeypatch.setenv("OTEL_ATTRIBUTE_COUNT_LIMIT", "1")
    with OTLPReceiver() as rx:
        lp = LoggerProvider()
        lp.add_log_record_processor(SimpleLogRecordProcessor(
            scrub(OTLPLogExporter(endpoint=rx.endpoint + "/v1/logs"), secrets=[c.value], env=False)))
        lp.get_logger("t").emit(LogRecord(body="x", attributes={"a": 1, "b": 2, "pw": c.value}))
        lp.shutdown()
        payloads = rx.snapshot()
    assert scan(payloads, [c]) == []
    assert "'droppedAttributesCount': 2" in str(payloads)


def test_rejects_non_exporters():
    with pytest.raises(TypeError):
        scrub(object())
