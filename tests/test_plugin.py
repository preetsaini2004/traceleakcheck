"""End-to-end plugin tests. Subprocess runs: the OTel global provider can be set once per process."""

import json

APP_HEADER = """
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("app")
"""


def _make(pytester, app_body, test_body, header=APP_HEADER):
    pytester.makepyfile(app=header + app_body, test_app=test_body)


def test_leak_fails_test_and_names_field(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('prompt', k)\n",
          "from app import run\ndef test_it(canary):\n    run(canary('aws').value)\n")
    r = pytester.runpytest_subprocess("--traceleak", "-v")
    r.assert_outcomes(passed=1, errors=1)
    r.stdout.fnmatch_lines(["*LEAK FOUND: Your AWS access key leaked*", '*In step "chat"*',
                            "*the saved prompt (prompt) (in plain text)*", "*attributes[[]prompt]*"])


def test_leak_found_even_when_app_env_samples_nothing(pytester, monkeypatch):
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "0")
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('prompt', k)\n",
          "from app import run\ndef test_it(canary):\n    run(canary().value)\n")
    r = pytester.runpytest_subprocess("--traceleak")
    r.stdout.fnmatch_lines(["*LEAK FOUND*"])


def test_redacted_app_is_clean(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('prompt', '[REDACTED]')\n",
          "from app import run\ndef test_it(canary):\n    run(canary().value)\n")
    r = pytester.runpytest_subprocess("--traceleak")
    r.assert_outcomes(passed=1)
    r.stdout.fnmatch_lines(["*1 clean, 0 leak, 0 incomplete, 0 error*"])


def test_unconfigured_app_is_incomplete_not_clean(pytester):
    _make(pytester, "def run(k):\n    pass\n", "from app import run\ndef test_it(canary):\n    run(canary().value)\n",
          header="")
    r = pytester.runpytest_subprocess("--traceleak")
    r.assert_outcomes(passed=1, errors=1)
    r.stdout.fnmatch_lines(["*COULDN'T CHECK*"])


def test_canary_without_flag_errors_clearly(pytester):
    pytester.makepyfile(test_app="def test_it(canary):\n    canary()\n")
    r = pytester.runpytest_subprocess()
    r.assert_outcomes(errors=1)
    r.stdout.fnmatch_lines(["*run pytest with --traceleak*"])


def test_leak_in_failing_test_still_reported(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('p', k)\n",
          "from app import run\ndef test_it(canary):\n    run(canary().value)\n    assert False\n")
    r = pytester.runpytest_subprocess("--traceleak", "--traceleak-report=rep.json")
    r.assert_outcomes(failed=1, errors=1)
    rep = json.loads((pytester.path / "rep.json").read_text())
    assert rep["summary"]["leak"] == 1


def test_demo_agent_leaks_via_exception(pytester):
    import pathlib
    demo = pathlib.Path(__file__).parent.parent / "examples" / "demo_agent"
    for f in ("app.py", "test_agent.py"):
        (pytester.path / f).write_text((demo / f).read_text())
    r = pytester.runpytest_subprocess("--traceleak")
    r.assert_outcomes(passed=2, errors=1)
    r.stdout.fnmatch_lines(["*the step's status message (in plain text)*"])


def test_leak_during_fixture_teardown_caught(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('close') as s:\n        s.set_attribute('p', k)\n",
          "import pytest\nfrom app import run\n"
          "@pytest.fixture\ndef client(canary):\n    c = canary()\n    yield c\n    run(c.value)  # leaks on close\n"
          "def test_it(client):\n    pass\n")
    r = pytester.runpytest_subprocess("--traceleak")
    r.assert_outcomes(passed=1, errors=1)
    r.stdout.fnmatch_lines(['*In step "close"*'])


def test_xdist_workers_report_to_controller(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('p', k)\n",
          "from app import run\ndef test_a(canary):\n    run(canary().value)\n"
          "def test_b(canary):\n    canary()\n    run('safe')\n")
    r = pytester.runpytest_subprocess("--traceleak", "-n", "2", "--traceleak-report=rep.json")
    r.stdout.fnmatch_lines(["*1 clean, 1 leak, 0 incomplete, 0 error*"])
    rep = json.loads((pytester.path / "rep.json").read_text())
    assert rep["summary"]["leak"] == 1 and rep["summary"]["clean"] == 1


LOGS_HEADER = """
import logging
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

ENDPOINT = None  # None = from env
lp = LoggerProvider()
lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=ENDPOINT)))
set_logger_provider(lp)
log = logging.getLogger("app")
log.addHandler(LoggingHandler(logger_provider=lp))
log.setLevel(logging.INFO)
"""
LOG_RUN = "def run(k):\n    log.info('calling with %s', k)\n"
TEST_RUN = "from app import run\ndef test_it(canary):\n    run(canary().value)\n"


def test_logs_only_app_leak_found(pytester):
    _make(pytester, LOG_RUN, TEST_RUN, header=LOGS_HEADER)
    r = pytester.runpytest_subprocess("--traceleak", "-W", "ignore::DeprecationWarning")
    r.stdout.fnmatch_lines(["*LEAK FOUND*", "*In a log record*"])


def test_logs_only_app_clean(pytester):
    _make(pytester, "def run(k):\n    log.info('calling model')\n", TEST_RUN, header=LOGS_HEADER)
    r = pytester.runpytest_subprocess("--traceleak", "-W", "ignore::DeprecationWarning")
    r.assert_outcomes(passed=1)
    r.stdout.fnmatch_lines(["*1 clean, 0 leak*"])


def test_broken_logs_pipeline_is_incomplete_even_with_working_traces(pytester):
    header = APP_HEADER + LOGS_HEADER.replace("ENDPOINT = None", "ENDPOINT = 'http://127.0.0.1:9/v1/logs'")
    _make(pytester, LOG_RUN, TEST_RUN, header=header)
    r = pytester.runpytest_subprocess("--traceleak", "-W", "ignore::DeprecationWarning")
    r.assert_outcomes(passed=1, errors=1)
    r.stdout.fnmatch_lines(["*Details: the control marker never arrived on: logs*"])


METRICS_HEADER = APP_HEADER + """
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

metrics.set_meter_provider(MeterProvider(metric_readers=[InMemoryMetricReader()]))  # not OTLP
"""
TRACE_RUN = "def run(k):\n    with tracer.start_as_current_span('chat'):\n        pass\n"


def test_non_otlp_metrics_reader_is_incomplete_unless_ignored(pytester):
    _make(pytester, TRACE_RUN, TEST_RUN, header=METRICS_HEADER)
    r = pytester.runpytest_subprocess("--traceleak")
    r.stdout.fnmatch_lines(["*never arrived on: metrics*"])
    r = pytester.runpytest_subprocess("--traceleak", "--traceleak-ignore=metrics")
    r.assert_outcomes(passed=1)


def test_html_report_written(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('prompt', k)\n",
          "from app import run\ndef test_it(canary):\n    run(canary('aws').value)\n")
    r = pytester.runpytest_subprocess("--traceleak", "--traceleak-html=out.html")
    r.stdout.fnmatch_lines(["*HTML report:*out.html*"])
    html = (pytester.path / "out.html").read_text(encoding="utf-8")
    assert "Your AWS access key leaked" in html and "How to fix" in html


def test_vendor_endpoint_env_points_at_receiver(pytester):
    pytester.makepyfile(test_env="""
import os
def test_it(traceleak):
    assert os.environ["TRACELOOP_BASE_URL"] == traceleak.endpoint
    assert os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] == traceleak.endpoint
""")
    pytester.runpytest_subprocess("--traceleak").assert_outcomes(passed=1)


GRPC_HEADER = APP_HEADER.replace("opentelemetry.exporter.otlp.proto.http.trace_exporter",
                                 "opentelemetry.exporter.otlp.proto.grpc.trace_exporter")


def test_app_hardwired_to_grpc_exporter_is_checked(pytester):
    _make(pytester,
          "def run(k):\n    with tracer.start_as_current_span('chat') as s:\n        s.set_attribute('prompt', k)\n",
          "from app import run\ndef test_leak(canary):\n    run(canary().value)\n"
          "def test_clean(canary):\n    canary()\n    run('safe')\n",
          header=GRPC_HEADER)
    r = pytester.runpytest_subprocess("--traceleak", timeout=120)
    r.stdout.fnmatch_lines(["*Result: 1 clean, 1 leak, 0 incomplete, 0 error*"])


def test_demo_agent_is_clean_with_safety_filter(pytester):
    import pathlib
    demo = pathlib.Path(__file__).parent.parent / "examples" / "demo_agent"
    app = (demo / "app.py").read_text()
    fixed = app.replace("BatchSpanProcessor(OTLPSpanExporter())",
                        "BatchSpanProcessor(__import__('traceleakcheck.guard').guard.scrub(OTLPSpanExporter()))")
    assert fixed != app
    pytester.makepyfile(app=fixed, test_agent=(demo / "test_agent.py").read_text())
    r = pytester.runpytest_subprocess("--traceleak", timeout=120)
    r.assert_outcomes(passed=2)
    r.stdout.fnmatch_lines(["*Result: 1 clean, 0 leak, 0 incomplete, 0 error*"])
