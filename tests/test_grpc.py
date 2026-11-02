"""OTLP over gRPC, served on the same port as OTLP/HTTP."""

import socket
import time

import pytest
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from traceleakcheck import OTLPReceiver, make_canary, scan
from traceleakcheck.receiver import ReceiverError


def _export_span(rx, value, **kw):
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=rx.endpoint, insecure=True, **kw)))
    with provider.get_tracer("t").start_as_current_span("chat") as span:
        span.set_attribute("prompt", value)
    provider.shutdown()


@pytest.mark.parametrize("compression", [None, "gzip"])
def test_grpc_trace_leak_found(compression):
    from grpc import Compression
    kw = {"compression": Compression.Gzip} if compression else {}
    c = make_canary("aws")
    with OTLPReceiver() as rx:
        _export_span(rx, c.value, **kw)
        findings = scan(rx.snapshot(), [c])
    assert [(f.signal, f.span, f.variant) for f in findings] == [("traces", "chat", "raw")]


def test_grpc_log_leak_found():
    c = make_canary("github")
    with OTLPReceiver() as rx:
        lp = LoggerProvider()
        lp.add_log_record_processor(SimpleLogRecordProcessor(OTLPLogExporter(endpoint=rx.endpoint, insecure=True)))
        from opentelemetry._logs import LogRecord
        lp.get_logger("t").emit(LogRecord(body=f"token {c.value}"))
        lp.shutdown()
        assert [f.signal for f in scan(rx.snapshot(), [c])] == ["logs"]


def test_http_and_grpc_share_one_port():
    c = make_canary()
    with OTLPReceiver() as rx:
        _export_span(rx, c.value)  # gRPC
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as Http
        p = TracerProvider()
        p.add_span_processor(SimpleSpanProcessor(Http(endpoint=rx.endpoint + "/v1/traces")))
        with p.get_tracer("t").start_as_current_span("chat") as s:
            s.set_attribute("prompt", c.value)
        p.shutdown()
        assert len(scan(rx.snapshot(), [c])) == 2


def test_grpc_without_grpcio_is_an_error_not_clean(monkeypatch):
    monkeypatch.setattr(OTLPReceiver, "_start_grpc", lambda self: None)
    with OTLPReceiver() as rx:
        host, port = rx.endpoint.removeprefix("http://").split(":")
        with socket.create_connection((host, int(port))) as s:
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            try:
                s.recv(1)  # the receiver closes the connection (Windows reports a reset)
            except ConnectionResetError:
                pass
        deadline = time.time() + 5
        while not rx.errors and time.time() < deadline:
            time.sleep(0.05)
        with pytest.raises(ReceiverError, match="grpcio isn't installed"):
            rx.snapshot()
