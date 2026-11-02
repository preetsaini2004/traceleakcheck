"""`traceleakcheck run -- <command>`: check an app in any language from the outside.

Starts the receiver, gives the app fake secrets through env vars, points its OpenTelemetry SDK at the
receiver with the standard OTEL_* settings every language reads, runs it, and scans what arrived.
The positive control is weaker than the pytest plugin's (we can't emit a marker inside another
process): telemetry must have arrived on every expected signal, and the result says what was checked.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict

from .canary import KINDS, make_canary
from .explain import terminal_lines
from .scanner import scan

SIGNALS = ("traces", "logs", "metrics")
# Inherited settings that would send the app's telemetry somewhere else or switch it off.
_DROP_ENV = [f"OTEL_EXPORTER_OTLP_{s}_{k}" for s in ("TRACES", "LOGS", "METRICS") for k in ("ENDPOINT", "PROTOCOL")]
_DROP_ENV.append("OTEL_SDK_DISABLED")
WIN = os.name == "nt"


def child_env(endpoint: str, secrets: dict[str, str], base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    for k in _DROP_ENV:
        env.pop(k, None)
    env.update({
        # The base endpoint only: HTTP exporters append /v1/<signal>, gRPC exporters use it as-is
        # (the receiver serves both on one port).
        "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        "OTEL_TRACES_EXPORTER": "otlp",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_METRICS_EXPORTER": "otlp",
        "OTEL_TRACES_SAMPLER": "always_on",
        # Export soon after work ends, so a short-lived app or a server we stop loses less.
        "OTEL_BSP_SCHEDULE_DELAY": "200",
        "OTEL_BLRP_SCHEDULE_DELAY": "200",
        "OTEL_METRIC_EXPORT_INTERVAL": "1000",
        "TRACELOOP_BASE_URL": endpoint,
    })
    env.update(secrets)
    return env


def count_items(payloads: list[tuple[str, dict]]) -> dict[str, int]:
    """Spans / log records / metrics per signal. Counting payloads isn't enough: an empty export
    still decodes to {}."""
    path = {"traces": ("resourceSpans", "scopeSpans", "spans"),
            "logs": ("resourceLogs", "scopeLogs", "logRecords"),
            "metrics": ("resourceMetrics", "scopeMetrics", "metrics")}
    counts = dict.fromkeys(SIGNALS, 0)
    for sig, data in payloads:
        if sig not in path:
            continue
        top, mid, leaf = path[sig]
        for r in data.get(top, []):
            for s in r.get(mid, []):
                counts[sig] += len(s.get(leaf, []))
    return counts


def _popen(cmd: list[str], env: dict[str, str], **kw) -> subprocess.Popen:
    # Own process group, so we can stop the whole tree (`npm start` runs node as a grandchild).
    if WIN:
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(cmd, env=env, **kw)


def _stop_tree(proc: subprocess.Popen, grace: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    try:  # graceful first: apps with shutdown hooks flush their telemetry
        if WIN:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(grace)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if WIN:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        proc.wait(grace)
    except subprocess.TimeoutExpired:
        pass


def _settle(rx, quiet: float, cap: float) -> None:
    """Wait until no new export has arrived for `quiet` seconds (at most `cap`)."""
    end = time.monotonic() + cap
    last_n, last_change = -1, time.monotonic()
    while time.monotonic() < end:
        n = len(rx.payloads)
        if n != last_n:
            last_n, last_change = n, time.monotonic()
        elif time.monotonic() - last_change >= quiet:
            return
        time.sleep(0.1)


def _wait_ready(url: str, deadline: float, proc: subprocess.Popen) -> bool:
    while time.monotonic() < deadline and proc.poll() is None:
        try:
            urllib.request.urlopen(url, timeout=1).close()
            return True
        except urllib.error.HTTPError:
            return True  # it answered; a 404 still means it's up
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    return False


def parse_secrets(specs: list[str] | None) -> dict[str, str]:
    """"ENV" or "ENV=kind" -> {ENV: kind}."""
    out = {}
    for spec in specs or ["OPENAI_API_KEY=openai"]:
        name, _, kind = spec.partition("=")
        kind = kind or "openai"
        if not name or kind not in KINDS:
            raise SystemExit(f"traceleakcheck: bad --secret {spec!r}: use ENV or ENV=KIND, KIND one of {', '.join(KINDS)}")
        out[name] = kind
    return out


def run(args: argparse.Namespace) -> int:
    from .receiver import OTLPReceiver, ReceiverError

    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("traceleakcheck: give the app command after --, e.g. traceleakcheck run -- node app.js")
    exe = shutil.which(cmd[0])  # Windows: finds npm.cmd / npx.cmd, which Popen can't on its own
    if exe is None:
        raise SystemExit(f"traceleakcheck: can't find {cmd[0]!r} on PATH")
    shown = " ".join(cmd)
    cmd[0] = exe
    expect = [s.strip() for s in args.expect.split(",") if s.strip()]
    if bad := [s for s in expect if s not in SIGNALS]:
        raise SystemExit(f"traceleakcheck: unknown --expect signal(s): {', '.join(bad)}")

    canaries, secret_env = [], {}
    for name, kind in parse_secrets(args.secret).items():
        c = make_canary(kind)
        canaries.append(c)
        secret_env[name] = c.value

    rx = OTLPReceiver(host=args.host, port=args.port).start()
    port = rx.endpoint.rsplit(":", 1)[1]
    # What a local app dials, even when bound to 0.0.0.0; or a Collector that forwards to us.
    endpoint = args.app_endpoint or f"http://127.0.0.1:{port}"
    env = child_env(endpoint, secret_env)
    print(f"traceleakcheck: receiver on {rx.endpoint}; planted {', '.join(secret_env)}", flush=True)

    deadline = time.monotonic() + args.timeout
    timed_out = False
    app_exit = drive_exit = None
    proc = _popen(cmd, env)
    try:
        if args.drive:
            if args.ready_url:
                if not _wait_ready(args.ready_url, deadline, proc):
                    print(f"traceleakcheck: {args.ready_url} never answered", file=sys.stderr)
            else:
                time.sleep(1.0)
            drive = args.drive
            for name, value in secret_env.items():  # {NAME} works in every shell; $NAME / %NAME% don't
                drive = drive.replace("{" + name + "}", value)
            try:
                drive_exit = subprocess.run(drive, shell=True, env=env,
                                            timeout=max(1.0, deadline - time.monotonic())).returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            _settle(rx, args.settle, max(0.0, deadline - time.monotonic()) + args.settle)
            _stop_tree(proc)
        else:
            try:
                proc.wait(max(1.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _stop_tree(proc)
        _settle(rx, args.settle, args.settle * 5)
    finally:
        _stop_tree(proc)
        app_exit = proc.returncode
        rx.stop()

    result = {"nodeid": shown, "status": "clean", "findings": [], "detail": "", "runner": "cli",
              "app_exit": app_exit, "drive_exit": drive_exit}
    try:
        payloads = rx.snapshot()
    except ReceiverError as exc:
        result |= {"status": "error", "detail": str(exc)}
        payloads = []
    counts = result["counts"] = count_items(payloads)
    if result["status"] == "clean":
        findings = scan(payloads, canaries)
        missing = [s for s in expect if counts[s] == 0]
        if findings:
            result |= {"status": "leak", "findings": [asdict(f) for f in findings]}
        elif timed_out:
            result |= {"status": "incomplete", "detail": f"the app didn't finish within {args.timeout:g}s. "
                       "Work still in progress is never exported, so it couldn't be checked."}
        elif missing:
            result |= {"status": "incomplete", "detail": f"no {', '.join(missing)} arrived from the app. Is "
                       "OpenTelemetry set up with an OTLP exporter that reads OTEL_EXPORTER_OTLP_ENDPOINT, and "
                       "does the app flush it before exiting (Node: await sdk.shutdown())? Skip signals the "
                       "app doesn't send with --expect."}
    _report(result, args)
    return {"clean": 0, "leak": 1}.get(result["status"], 2)


def _report(result: dict, args: argparse.Namespace) -> None:
    c = result["counts"]
    print()
    print(f"traceleakcheck: {result['nodeid']}")
    for line in terminal_lines(result, verbose=args.verbose):
        print("  " + line)
    print(f"  Checked: {c['traces']} span(s), {c['logs']} log record(s), {c['metrics']} metric(s). "
          f"App exit code: {result['app_exit']}" + (f", driver exit code: {result['drive_exit']}"
                                                     if result["drive_exit"] is not None else "") + ".")
    if result["status"] == "clean":
        print("  Note: outside pytest the control is weaker: it proves telemetry arrived, not that every "
              "batch did. Make sure the app flushes before it exits.")
    report = {"summary": {s: int(result["status"] == s) for s in ("clean", "leak", "incomplete", "error")},
              "results": [result]}
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    if args.html:
        from .html_report import render

        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render(report))
        print(f"  HTML report: {os.path.abspath(args.html)}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        from .plugin import _markdown

        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(_markdown(report))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="traceleakcheck",
                                description="Catch secrets leaking through an app's OpenTelemetry export.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run an app (any language) with fake secrets and check its telemetry",
                       usage="traceleakcheck run [options] -- COMMAND [ARGS...]")
    r.add_argument("--secret", action="append", metavar="ENV[=KIND]",
                   help=f"env var to fill with a fake secret; KIND one of {', '.join(KINDS)} "
                   "(default: OPENAI_API_KEY=openai). Repeatable.")
    r.add_argument("--drive", metavar="SHELL_CMD",
                   help="treat the app as a server: once it's up, run this command against it, then stop "
                   "the app. {ENV} in it is replaced by that secret's value.")
    r.add_argument("--ready-url", metavar="URL", help="with --drive: wait until this URL answers")
    r.add_argument("--expect", default="traces", metavar="SIGNALS",
                   help="comma list of signals that must arrive (default: traces)")
    r.add_argument("--settle", type=float, default=2.0, metavar="SEC",
                   help="wait until no export has arrived for this long (default: 2)")
    r.add_argument("--timeout", type=float, default=120.0, metavar="SEC", help="overall limit (default: 120)")
    r.add_argument("--host", default="127.0.0.1",
                   help="receiver bind address; 0.0.0.0 lets a container reach it")
    r.add_argument("--port", type=int, default=0, help="receiver port (default: any free port)")
    r.add_argument("--app-endpoint", metavar="URL",
                   help="point the app here instead of at the receiver, e.g. an OpenTelemetry Collector "
                   "that forwards to the receiver (use with --port)")
    r.add_argument("--report", metavar="PATH", help="write a JSON report")
    r.add_argument("--html", metavar="PATH", help="write a plain-English HTML report")
    r.add_argument("-v", "--verbose", action="store_true", help="show exact field paths")
    r.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
