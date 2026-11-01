"""In-process OTLP/HTTP receiver that records every export request it gets."""

from __future__ import annotations

import gzip
import json
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1 import logs_service_pb2
from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
from opentelemetry.proto.collector.trace.v1 import trace_service_pb2

from .scanner import RAW_KEY

# path -> (signal name, request message class, response message class)
_ROUTES = {
    "/v1/traces": (
        "traces",
        trace_service_pb2.ExportTraceServiceRequest,
        trace_service_pb2.ExportTraceServiceResponse,
    ),
    "/v1/logs": (
        "logs",
        logs_service_pb2.ExportLogsServiceRequest,
        logs_service_pb2.ExportLogsServiceResponse,
    ),
    "/v1/metrics": (
        "metrics",
        metrics_service_pb2.ExportMetricsServiceRequest,
        metrics_service_pb2.ExportMetricsServiceResponse,
    ),
}
_JSON_ROOT = {"traces": "resourceSpans", "logs": "resourceLogs", "metrics": "resourceMetrics"}
_MAX_LINE = 65537


class ReceiverError(RuntimeError):
    """Some exports could not be decoded, so a scan of what did decode would under-report."""


def _decompress(body: bytes, encoding: str) -> bytes:
    encoding = encoding.lower()
    if encoding == "gzip":
        return gzip.decompress(body)
    if encoding == "deflate":
        return zlib.decompress(body)
    return body


def _read_exact(rfile, n: int) -> bytes:
    data = rfile.read(n)
    if len(data) != n:
        raise ValueError(f"short body: got {len(data)} of {n} bytes")
    return data


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    if "chunked" in (handler.headers.get("Transfer-Encoding") or "").lower():
        chunks = []
        while True:
            size = int(handler.rfile.readline(_MAX_LINE).split(b";")[0].strip(), 16)
            if size == 0:
                while handler.rfile.readline(_MAX_LINE) not in (b"\r\n", b"\n", b""):
                    pass  # skip trailers
                return b"".join(chunks)
            chunks.append(_read_exact(handler.rfile, size))
            handler.rfile.readline(_MAX_LINE)  # CRLF after each chunk
    length = int(handler.headers.get("Content-Length") or 0)
    if length < 0:
        raise ValueError(f"invalid Content-Length {length}")
    return _read_exact(handler.rfile, length)


class _Server(ThreadingHTTPServer):
    # Non-daemon handler threads let server_close() join in-flight requests,
    # so no payload can land after stop() returns.
    daemon_threads = False


class OTLPReceiver:
    """Run with `with OTLPReceiver() as rx:`; point exporters at `rx.endpoint`.

    `rx.snapshot()` returns `(signal, dict)` pairs using OTLP/JSON field names, and raises
    `ReceiverError` if any export failed to decode, so a broken export can never look like
    "nothing leaked". The failures themselves are in `rx.errors`.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.payloads: list[tuple[str, dict]] = []
        self.errors: list[str] = []
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            timeout = 10  # bound reads so a stalled client can't hang stop()

            def _fail(self, code: int, why: str):
                with receiver._lock:
                    receiver.errors.append(f"{self.path}: {why}")
                self.send_error(code)

            def do_POST(self):  # noqa: N802 (http.server API)
                route = _ROUTES.get(self.path.split("?")[0])
                if route is None:
                    self._fail(404, "unknown OTLP route")
                    return
                signal, req_cls, resp_cls = route
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
                try:
                    body = _decompress(_read_body(self), self.headers.get("Content-Encoding") or "")
                    if ctype == "application/json":
                        data = json.loads(body)
                        if not isinstance(data, dict) or (data and _JSON_ROOT[signal] not in data):
                            raise ValueError(f"not an OTLP/JSON {signal} request")
                    else:
                        msg = req_cls()
                        msg.ParseFromString(body)
                        data = MessageToDict(msg)
                    # Keep the raw body: the decoder silently drops unknown protobuf fields.
                    data[RAW_KEY] = body.decode("latin-1")
                except Exception as exc:  # record, don't crash the exporter's thread
                    self._fail(400, repr(exc))
                    return
                with receiver._lock:
                    receiver.payloads.append((signal, data))
                if ctype == "application/json":
                    out, out_type = b"{}", "application/json"
                else:
                    out, out_type = resp_cls().SerializeToString(), "application/x-protobuf"
                self.send_response(200)
                self.send_header("Content-Type", out_type)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args):  # keep test output quiet
                pass

        self._server = _Server((host, port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def endpoint(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def snapshot(self) -> list[tuple[str, dict]]:
        with self._lock:
            if self.errors:
                raise ReceiverError(
                    "some exports failed to decode; scanning the rest would under-report:\n  "
                    + "\n  ".join(self.errors)
                )
            return list(self.payloads)

    def clear(self) -> None:
        with self._lock:
            self.payloads.clear()
            self.errors.clear()

    def start(self) -> "OTLPReceiver":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()  # joins in-flight handler threads

    def __enter__(self) -> "OTLPReceiver":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
