import base64
import gzip
import json
import logging
import urllib.request

import pytest
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
from opentelemetry.sdk.trace import SpanLimits, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from traceleakcheck import OTLPReceiver, make_canary, scan
from traceleakcheck.canary import KINDS


@pytest.fixture
def rx():
    with OTLPReceiver() as r:
        yield r


def _tracer(rx):
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=rx.endpoint + "/v1/traces")))
    return provider


def test_raw_leak_in_span_attribute_found_with_path(rx):
    c = make_canary("openai")
    provider = _tracer(rx)
    with provider.get_tracer("t").start_as_current_span("chat gpt-4o") as span:
        span.set_attribute("gen_ai.prompt", f"use key {c.value} please")
    provider.shutdown()

    findings = scan(rx.snapshot(), [c])
    assert len(findings) == 1
    f = findings[0]
    assert (f.canary_kind, f.variant, f.signal, f.span) == ("openai", "raw", "traces", "chat gpt-4o")
    assert f.path.endswith("spans[0].attributes[gen_ai.prompt].stringValue")


@pytest.mark.parametrize("prefix", ["", "a", "ab", "header:"])
def test_base64_leak_found_at_any_byte_offset(rx, prefix):
    c = make_canary("aws")
    blob = base64.b64encode(f"{prefix}{c.value} trailing".encode()).decode()
    provider = _tracer(rx)
    with provider.get_tracer("t").start_as_current_span("tool call") as span:
        span.set_attribute("tool.args", blob)
    provider.shutdown()

    findings = scan(rx.snapshot(), [c])
    assert [f.variant.startswith("base64") for f in findings] == [True]


def test_exception_stacktrace_leak_found(rx):
    c = make_canary("github")
    provider = _tracer(rx)
    with pytest.raises(RuntimeError):
        with provider.get_tracer("t").start_as_current_span("agent step"):
            raise RuntimeError(f"auth failed for token {c.value}")
    provider.shutdown()

    paths = {f.path.split("spans[0].", 1)[1] for f in scan(rx.snapshot(), [c])}
    # The SDK copies the exception text into both the exception event AND the span status.
    assert "status.message" in paths
    assert any(p.startswith("events[0].attributes[exception.") for p in paths)


def test_clean_export_has_no_findings_but_telemetry_arrived(rx):
    c = make_canary("password")
    provider = _tracer(rx)
    with provider.get_tracer("t").start_as_current_span("safe") as span:
        span.set_attribute("gen_ai.prompt", "[REDACTED]")
    provider.shutdown()

    assert rx.snapshot(), "positive control: telemetry must arrive"
    assert scan(rx.snapshot(), [c]) == []


def test_log_record_leak_found(rx):
    c = make_canary("anthropic")
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(OTLPLogExporter(endpoint=rx.endpoint + "/v1/logs")))
    log = logging.getLogger("tlc-test")
    handler = LoggingHandler(logger_provider=provider)
    log.addHandler(handler)
    try:
        log.warning("calling api with %s", c.value)
    finally:
        log.removeHandler(handler)
        provider.shutdown()

    findings = scan(rx.snapshot(), [c])
    assert [(f.signal, f.variant) for f in findings] == [("logs", "raw")]


def _post(url, body, headers):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.status


def test_json_and_gzip_requests_decoded(rx):
    c = make_canary("jwt")
    payload = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"name": "s", "spanId": "01", "attributes": [{"key": "auth", "value": {"stringValue": c.value}}]}
    ]}]}]}
    body = json.dumps(payload).encode()
    assert _post(rx.endpoint + "/v1/traces", body, {"Content-Type": "application/json"}) == 200
    assert _post(rx.endpoint + "/v1/traces", gzip.compress(body),
                 {"Content-Type": "application/json", "Content-Encoding": "gzip"}) == 200

    findings = scan(rx.snapshot(), [c])
    assert [f.path for f in findings] == ["resourceSpans[0].scopeSpans[0].spans[0].attributes[auth].stringValue"] * 2


def test_undecodable_request_recorded_as_error(rx):
    with pytest.raises(urllib.error.HTTPError):
        _post(rx.endpoint + "/v1/traces", b"\xff\x00garbage", {"Content-Type": "application/x-protobuf"})
    assert rx.errors and not rx.payloads


def test_truncated_leak_found(rx):
    c = make_canary("anthropic")
    provider = TracerProvider(span_limits=SpanLimits(max_attribute_length=40))
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=rx.endpoint + "/v1/traces")))
    with provider.get_tracer("t").start_as_current_span("chat") as span:
        span.set_attribute("gen_ai.prompt", c.value)
    provider.shutdown()

    assert [f.variant for f in scan(rx.snapshot(), [c])] == ["truncated"]


@pytest.mark.parametrize("kind", KINDS)
def test_canaries_unique_and_variants_long_enough(kind):
    a, b = make_canary(kind), make_canary(kind)
    assert a.value != b.value
    assert all(len(v) >= 16 for v in a.variants.values())


# --- regressions from Codex review ---------------------------------------------------------

import http.client

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from traceleakcheck.receiver import ReceiverError
from traceleakcheck.scanner import RAW_PATH


def _request_with_attr(key, value) -> bytes:
    req = ExportTraceServiceRequest()
    span = req.resource_spans.add().scope_spans.add().spans.add()
    span.name, span.span_id = "s", b"\x01" * 8
    attr = span.attributes.add()
    attr.key, attr.value.string_value = key, value
    return req.SerializeToString()


def _conn(rx):
    host, port = rx.endpoint.removeprefix("http://").split(":")
    return http.client.HTTPConnection(host, int(port), timeout=5)


def test_chunked_protobuf_body_decoded(rx):
    c = make_canary("openai")
    body = _request_with_attr("prompt", c.value)
    conn = _conn(rx)
    conn.request("POST", "/v1/traces", body=iter([body[:7], body[7:]]),
                 headers={"Content-Type": "application/x-protobuf"}, encode_chunked=True)
    assert conn.getresponse().status == 200
    assert [f.variant for f in scan(rx.snapshot(), [c])] == ["raw"]


def test_snapshot_refuses_to_scan_after_decode_error(rx):
    with pytest.raises(urllib.error.HTTPError):
        _post(rx.endpoint + "/v1/traces", b"\xff\x00garbage", {"Content-Type": "application/x-protobuf"})
    with pytest.raises(ReceiverError):
        rx.snapshot()


def test_canary_used_as_attribute_key_found(rx):
    c = make_canary("password")
    _post(rx.endpoint + "/v1/traces", _request_with_attr(c.value, "x"), {"Content-Type": "application/x-protobuf"})
    assert [f.path.endswith("#key") for f in scan(rx.snapshot(), [c])] == [True]


def test_canary_in_unknown_protobuf_field_found_via_raw_body(rx):
    c = make_canary("github")
    secret = c.value.encode()
    unknown = bytes([0x9A, 0x06, len(secret)]) + secret  # field 99, wire type 2 (length-delimited)
    _post(rx.endpoint + "/v1/traces", _request_with_attr("k", "v") + unknown, {"Content-Type": "application/x-protobuf"})
    assert [f.path for f in scan(rx.snapshot(), [c])] == [RAW_PATH]


def test_mixed_case_hex_leak_found(rx):
    c = make_canary("aws")
    hexed = "".join(ch.upper() if i % 2 else ch for i, ch in enumerate(c.value.encode().hex()))
    _post(rx.endpoint + "/v1/traces", _request_with_attr("blob", hexed), {"Content-Type": "application/x-protobuf"})
    assert [f.variant for f in scan(rx.snapshot(), [c])] == ["hex"]


def test_bad_content_length_recorded(rx):
    conn = _conn(rx)
    conn.putrequest("POST", "/v1/traces")
    conn.putheader("Content-Type", "application/x-protobuf")
    conn.putheader("Content-Length", "abc")
    conn.endheaders()
    assert conn.getresponse().status == 400
    assert rx.errors


def test_unknown_route_recorded(rx):
    with pytest.raises(urllib.error.HTTPError):
        _post(rx.endpoint + "/v2/traces", b"", {"Content-Type": "application/x-protobuf"})
    assert rx.errors


def test_non_otlp_json_rejected(rx):
    with pytest.raises(urllib.error.HTTPError):
        _post(rx.endpoint + "/v1/traces", b"123", {"Content-Type": "application/json"})
    assert rx.errors and not rx.payloads


def test_canary_leaked_as_key_is_masked_in_path(rx):
    c = make_canary("github")
    _post(rx.endpoint + "/v1/traces", _request_with_attr(c.value, "x"), {"Content-Type": "application/x-protobuf"})
    (f,) = scan(rx.snapshot(), [c])
    assert c.value not in f.path and "<github canary>" in f.path
