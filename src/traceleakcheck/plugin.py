"""pytest plugin. Run `pytest --traceleak`; every test that uses the `canary` fixture fails if a
canary shows up in what the app exports over OTLP, or if no telemetry reached us at all.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict

import pytest

from .canary import Canary, make_canary
from .scanner import RAW_KEY, scan

MARKER_SPAN = "traceleakcheck.marker"
MARKER_ATTR = "traceleakcheck.nonce"
_PROP = "traceleakcheck"  # user_properties key: carries results from xdist workers to the controller
_STATE = pytest.StashKey["TraceLeak"]()
_CANARIES = pytest.StashKey[list]()
STATUSES = ("clean", "leak", "incomplete", "error")


class TraceLeak:
    """Session state; also the `traceleak` fixture. `watch(provider)` registers providers the app
    built without making them global, so they get flushed and carry the positive-control span."""

    def __init__(self):
        from .receiver import OTLPReceiver  # lazy: keep plain `pytest` runs free of protobuf imports

        self.receiver = OTLPReceiver().start()
        self.providers: list = []
        self._saved_env: dict[str, str | None] = {}

    @property
    def endpoint(self) -> str:
        return self.receiver.endpoint

    def watch(self, provider) -> None:
        self.providers.append(provider)

    def install_env(self) -> None:
        env = {
            "OTEL_EXPORTER_OTLP_ENDPOINT": self.endpoint,
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            # Signal-specific vars win over the base one, so pin them too.
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": self.endpoint + "/v1/traces",
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": self.endpoint + "/v1/logs",
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": self.endpoint + "/v1/metrics",
            # A ratio sampler could drop the leaking span (false "clean") or the marker (flaky "incomplete").
            "OTEL_TRACES_SAMPLER": "always_on",
        }
        for k, v in env.items():
            self._saved_env[k] = os.environ.get(k)
            os.environ[k] = v

    def close(self) -> None:
        self._flush(self._all_providers())
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # Deliberately not stopping the receiver: SDK providers export once more from their
        # atexit shutdown (metric readers always do), and a closed port turns that into retry
        # noise and delay. Its serve thread is a daemon and dies with the process.

    def _all_providers(self) -> list:
        found = list(self.providers)
        try:
            from opentelemetry import _logs, metrics, trace

            found += [trace.get_tracer_provider(), _logs.get_logger_provider(), metrics.get_meter_provider()]
        except ImportError:
            pass
        return list({id(p): p for p in found}.values())

    @staticmethod
    def _flush(providers) -> None:
        for p in providers:
            flush = getattr(p, "force_flush", None)
            if flush is not None:
                flush(timeout_millis=5000)

    def _pipelines(self, ignore: set[str]) -> list[tuple[str, object]]:
        """(signal, provider) for each SDK provider the app configured. API no-op/proxy
        providers have no force_flush: the app set nothing up for that signal."""
        out = []
        for p in self._all_providers():
            if not hasattr(p, "force_flush"):
                continue
            for signal, method in (("traces", "get_tracer"), ("logs", "get_logger"), ("metrics", "get_meter")):
                if hasattr(p, method) and signal not in ignore:
                    out.append((signal, p))
                    break
        return out

    def check(self, nodeid: str, canaries: list[Canary], ignore: set[str] = frozenset()) -> dict:
        from .receiver import ReceiverError

        pipelines = self._pipelines(ignore)
        # Positive control: a marker sent through EVERY configured pipeline must arrive, or a
        # broken logs pipeline could hide a leak behind a working traces pipeline. The nonce is
        # unique per check, so a late export from another test can't satisfy it.
        nonce = secrets.token_hex(8)
        unverifiable = []
        for signal, p in pipelines:
            try:
                _emit_marker(signal, p, nonce)
            except Exception as exc:  # e.g. an SDK whose logs API predates LogRecord(body=...)
                unverifiable.append(f"{signal} ({exc!r})")
        self._flush(self._all_providers())
        result = {"nodeid": nodeid, "status": "clean", "findings": [], "detail": ""}
        try:
            payloads = self.receiver.snapshot()
        except ReceiverError as exc:
            return result | {"status": "error", "detail": str(exc)}
        findings = scan(payloads, canaries)
        if findings:
            return result | {"status": "leak", "findings": [asdict(f) for f in findings]}
        if not pipelines:
            return result | {
                "status": "incomplete",
                "detail": "no OTel SDK provider is configured, so nothing could be exported and a clean "
                "result can't be claimed. Configure the SDK, or register providers with traceleak.watch().",
            }
        arrived = {s for s, data in payloads if nonce in data.get(RAW_KEY, "")}
        missing = sorted({s for s, _ in pipelines} - arrived)
        if missing or unverifiable:
            why = [f"the control marker never arrived on: {', '.join(missing)}"] if missing else []
            why += [f"couldn't send the control marker on {u}" for u in unverifiable]
            return result | {
                "status": "incomplete",
                "detail": "; ".join(why) + ". Is that exporter pointed at OTEL_EXPORTER_OTLP_* "
                "(or skip the signal with --traceleak-ignore)?",
            }
        return result


def _emit_marker(signal: str, provider, nonce: str) -> None:
    attrs = {MARKER_ATTR: nonce}
    if signal == "traces":
        provider.get_tracer("traceleakcheck").start_span(MARKER_SPAN, attributes=attrs).end()
    elif signal == "logs":
        from opentelemetry._logs import LogRecord

        provider.get_logger("traceleakcheck").emit(LogRecord(body=MARKER_SPAN, attributes=attrs))
    else:
        provider.get_meter("traceleakcheck").create_counter(MARKER_SPAN).add(1, attrs)


def _describe(f: dict) -> str:
    where = f"span '{f['span']}'" if f["span"] else f["signal"]
    return f"{f['canary_kind']} canary ({f['variant']}) in {where} at {f['path']}"


# --- hooks -------------------------------------------------------------------------------------


def pytest_addoption(parser):
    group = parser.getgroup("traceleakcheck")
    group.addoption("--traceleak", action="store_true",
                    help="point OTLP exporters at a local receiver and fail tests whose canaries leak")
    group.addoption("--traceleak-report", metavar="PATH", help="write a JSON report of every checked test")
    group.addoption("--traceleak-ignore", metavar="SIGNALS", default="",
                    help="comma list of signals (traces,logs,metrics) not to require a control marker on, "
                    "e.g. metrics exported by a Prometheus reader instead of OTLP")


@pytest.hookimpl(tryfirst=True)
def pytest_load_initial_conftests(early_config, parser, args):
    # Runs before conftest.py files import the app, so exporters built at import time
    # already read our endpoint. Under xdist each worker runs this too, getting its own receiver.
    if early_config.known_args_namespace.traceleak:
        tl = TraceLeak()
        tl.install_env()
        early_config.stash[_STATE] = tl


def pytest_unconfigure(config):
    tl = config.stash.get(_STATE, None)
    if tl is not None:
        tl.close()


@pytest.fixture(scope="session")
def traceleak(pytestconfig) -> TraceLeak:
    tl = pytestconfig.stash.get(_STATE, None)
    if tl is None:
        pytest.fail("traceleakcheck is off: run pytest with --traceleak", pytrace=False)
    return tl


@pytest.fixture
def canary(request, traceleak):
    """Factory: `canary("aws").value` is a fresh fake secret this test is checked for."""
    made = request.node.stash.setdefault(_CANARIES, [])

    def make(kind: str = "openai") -> Canary:
        c = make_canary(kind)
        made.append(c)
        return c

    return make


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item):
    tl = item.config.stash.get(_STATE, None)
    if tl is not None:
        tl.receiver.clear()  # each test only sees its own exports
    return (yield)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item, nextitem):
    # Check after fixtures finalize: clients closing or flushing in teardown can leak too.
    out = yield
    tl = item.config.stash.get(_STATE, None)
    canaries = item.stash.get(_CANARIES, None)
    if tl is None or not canaries:
        return out
    ignore = {s.strip() for s in item.config.getoption("traceleak_ignore").split(",") if s.strip()}
    result = tl.check(item.nodeid, canaries, ignore)
    item.user_properties.append((_PROP, result))
    if result["status"] == "leak":
        lines = "\n  - ".join(_describe(f) for f in result["findings"])
        pytest.fail(f"TRACELEAK LEAK: canary secret found in exported telemetry:\n  - {lines}", pytrace=False)
    if result["status"] != "clean":
        pytest.fail(f"TRACELEAK {result['status'].upper()}: {result['detail']}", pytrace=False)
    return out


def pytest_runtest_logreport(report):
    # Fires on the controller for xdist worker reports too.
    if report.when == "teardown":
        for name, value in report.user_properties:
            if name == _PROP:
                _results_sink.append(value)


_results_sink: list[dict] = []  # module-level: pytest_runtest_logreport gets no config


def pytest_terminal_summary(terminalreporter, config):
    if not config.getoption("traceleak"):
        return
    results = list(_results_sink)
    counts = {s: sum(r["status"] == s for r in results) for s in STATUSES}
    terminalreporter.section("traceleakcheck")
    terminalreporter.write_line(", ".join(f"{n} {s}" for s, n in counts.items()))
    for r in results:
        if r["status"] != "clean":
            terminalreporter.write_line(f"{r['status'].upper()} {r['nodeid']}")
            for f in r["findings"]:
                terminalreporter.write_line(f"    {_describe(f)}")

    report = {"summary": counts, "results": results}
    path = config.getoption("traceleak_report")
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(_markdown(report))


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def _markdown(report: dict) -> str:
    s = report["summary"]
    out = ["## traceleakcheck", "",
           f"**{s['leak']} leak · {s['incomplete']} incomplete · {s['error']} error · {s['clean']} clean**", ""]
    bad = [r for r in report["results"] if r["status"] != "clean"]
    if bad:
        out += ["| Test | Verdict | Where |", "|---|---|---|"]
        for r in bad:
            where = "<br>".join(f"`{_cell(f['path'])}` ({f['canary_kind']}, {f['variant']})" for f in r["findings"])
            out.append(f"| `{_cell(r['nodeid'])}` | {r['status']} | {where or _cell(r['detail'])} |")
    return "\n".join(out) + "\n"
