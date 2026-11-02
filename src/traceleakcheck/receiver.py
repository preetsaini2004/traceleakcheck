"""In-process OTLP/HTTP receiver that records every export request it gets."""

from __future__ import annotations

import gzip
import json
import socket
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


_GRPC_SERVICES = {
    "traces": "opentelemetry.proto.collector.trace.v1.TraceService",
    "logs": "opentelemetry.proto.collector.logs.v1.LogsService",
    "metrics": "opentelemetry.proto.collector.metrics.v1.MetricsService",
}


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    """Copy bytes one way until either side closes; then close both."""
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except OSError:
                pass


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
                    receiver._ingest(signal, req_cls, body, as_json=ctype == "application/json")
                except Exception as exc:  # record, don't crash the exporter's thread
                    self._fail(400, repr(exc))
                    return
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

        # One public port for both protocols: HTTP and gRPC exporters read the same
        # OTEL_EXPORTER_OTLP_ENDPOINT, so they can't be given different ports. Each connection is
        # routed by its first bytes: HTTP/1 connections go to the HTTP handler, gRPC (HTTP/2,
        # which always opens with "PRI * HTTP/2.0") is relayed to an internal grpcio server.
        self._http = _Server((host, 0), Handler, bind_and_activate=False)  # fed sockets directly
        self._sock = socket.create_server((host, port))
        self._sock.settimeout(0.2)  # accept loop polls _stopping, so stop() never blocks
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._grpc = self._grpc_port = None

    def _ingest(self, signal: str, req_cls, body: bytes, as_json: bool = False) -> None:
        if as_json:
            data = json.loads(body)
            if not isinstance(data, dict) or (data and _JSON_ROOT[signal] not in data):
                raise ValueError(f"not an OTLP/JSON {signal} request")
        else:
            msg = req_cls()
            msg.ParseFromString(body)
            data = MessageToDict(msg)
        # Keep the raw body: the decoder silently drops unknown protobuf fields.
        data[RAW_KEY] = body.decode("latin-1")
        with self._lock:
            self.payloads.append((signal, data))

    def _record_error(self, why: str) -> None:
        with self._lock:
            self.errors.append(why)

    def _start_grpc(self) -> None:
        try:
            import grpc
        except ImportError:
            return  # gRPC connections are then recorded as errors, never as "clean"
        from concurrent.futures import ThreadPoolExecutor

        def handler(signal, req_cls):
            def export(body: bytes, context):
                try:
                    self._ingest(signal, req_cls, body)  # grpcio has already decompressed it
                except Exception as exc:
                    self._record_error(f"gRPC {signal}: {exc!r}")
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, "undecodable OTLP request")
                return b""  # an empty Export*ServiceResponse
            # No (de)serializers: we get the exact wire bytes, decoded by the same path as HTTP.
            return grpc.unary_unary_rpc_method_handler(export)

        services = [grpc.method_handlers_generic_handler(_GRPC_SERVICES[signal], {"Export": handler(signal, req)})
                    for signal, req, _ in _ROUTES.values()]
        self._grpc = grpc.server(ThreadPoolExecutor(max_workers=4), handlers=services)
        self._grpc_port = self._grpc.add_insecure_port("127.0.0.1:0")
        self._grpc.start()

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._route, args=(conn, addr), daemon=True).start()

    def _route(self, conn: socket.socket, addr) -> None:
        conn.settimeout(10)
        try:
            head = b""
            while len(head) < 3:
                head = conn.recv(3, socket.MSG_PEEK)
                if not head:
                    conn.close()
                    return
        except OSError:
            conn.close()
            return
        conn.settimeout(None)
        if head != b"PRI":
            self._http.process_request(conn, addr)
            return
        if self._grpc_port is None:
            self._record_error("an exporter sent OTLP over gRPC, but grpcio isn't installed here "
                               "(pip install traceleakcheck[grpc]), so that data couldn't be checked")
            conn.close()
            return
        upstream = socket.create_connection(("127.0.0.1", self._grpc_port))
        for src, dst in ((conn, upstream), (upstream, conn)):
            threading.Thread(target=_pipe, args=(src, dst), daemon=True).start()

    @property
    def endpoint(self) -> str:
        host, port = self._sock.getsockname()[:2]
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
        self._start_grpc()
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stopping.set()
        self._thread.join()
        self._sock.close()
        self._http.server_close()  # joins in-flight HTTP handler threads
        if self._grpc is not None:
            self._grpc.stop(grace=1).wait()

    def __enter__(self) -> "OTLPReceiver":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
