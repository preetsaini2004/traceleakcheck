<p align="center"><img src="docs/readme/banner.svg" alt="TraceLeakCheck: catch secrets leaking through your AI app's OpenTelemetry, before they ship" width="100%"></p>

<p align="center">
  <a href="https://github.com/preetsaini2004/traceleakcheck/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/preetsaini2004/traceleakcheck/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.10 to 3.14" src="https://img.shields.io/badge/python-3.10%E2%80%933.14-3776ab?logo=python&logoColor=white">
  <img alt="pytest plugin" src="https://img.shields.io/badge/pytest-plugin-0a9edc?logo=pytest&logoColor=white">
  <img alt="OpenTelemetry" src="https://img.shields.io/badge/OpenTelemetry-OTLP%20HTTP%20%2B%20gRPC-f5a800?logo=opentelemetry&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#fix-it-the-safety-filter">Safety filter</a> ·
  <a href="#tested-on-real-code">Real-world test</a> ·
  <a href="survey/FINDINGS.md">Survey</a>
</p>

---

Your AI app's monitoring data (OpenTelemetry traces and logs) records prompts, tool calls and errors, and sends them to a dashboard. Secrets ride along: an API key in an error message, a password a user pasted into the chat, a token in a URL. Redaction code passes its unit tests while the key still leaks through a field nobody thought about.

**TraceLeakCheck plants a fake secret, captures everything your app really exports, and tells you in plain English exactly where it leaked.**

<p align="center"><img src="docs/readme/terminal.png" alt="Before: 1 leak found in the error message, stack trace and status of step llm.call. After wrapping the exporter with scrub(): 1 clean." width="900"></p>

## What you get

| | |
|---|---|
| 🔎 **Find** | `pytest --traceleak` checks every test that uses the `canary` fixture: traces, logs and metrics, over HTTP or gRPC, raw or encoded (base64 at any offset, URL, hex, truncated). |
| 🛠️ **Fix** | `scrub()` wraps your exporter and removes secrets before anything leaves your app. Every report comes with how-to-fix tips. |
| ✅ **Prove** | Re-run and get `clean`, backed by a control check showing your telemetry really arrived. "Nothing arrived" is never "nothing leaked". |

## Quick start

```sh
pip install git+https://github.com/preetsaini2004/traceleakcheck
```

```python
def test_agent_does_not_leak_key(canary):
    key = canary("openai").value          # a fresh fake secret; this test is now checked
    run_agent("summarize this", api_key=key)
```

```sh
pytest --traceleak                                 # plain-English results in the terminal
pytest --traceleak --traceleak-html=report.html    # + a report page for your browser
pytest --traceleak -v                              # + exact technical field paths
```

If your app configures OpenTelemetry from the standard `OTEL_EXPORTER_OTLP_*` settings, it needs no changes. Traceloop's `TRACELOOP_BASE_URL` is set too. If your app builds a provider by hand, register it with `traceleak.watch(provider)`.

<details>
<summary><b>The HTML report</b></summary>
<br>
<p align="center"><img src="docs/readme/report.png" alt="HTML report: a red card says your OpenAI API key leaked in 3 places in step llm.call, with how-to-fix tips and copyable code" width="720"></p>
</details>

## How it works

<p align="center"><img src="docs/readme/how-it-works.svg" alt="How it works: a canary fake key goes into your unchanged app, the app exports OTLP over HTTP or gRPC to a local receiver, every field is scanned, and the result is leak, clean or incomplete" width="100%"></p>

1. **Before your `conftest.py` loads**, `--traceleak` starts a receiver and points the app's exporters at it.
2. **Each test** that asks for a `canary` gets unique fake secrets in realistic formats: OpenAI, Anthropic, AWS, GitHub, JWT or password.
3. **After the test and its fixtures finish**, a control marker is sent through every configured pipeline (traces, logs, metrics), everything is flushed, and every exported field is searched.

Each test gets one verdict:

| Verdict | Meaning | Test |
|---|---|---|
| ✅ `clean` | Every pipeline delivered its control marker, and no canary was found | passes |
| 🚨 `leak` | A canary was found; the report names the step and field | fails |
| ⚠️ `incomplete` | A pipeline's control marker never arrived, so "clean" can't be claimed | fails |
| ⚠️ `error` | An export couldn't be decoded, so a scan would under-report | fails |

pytest shows a failed check as `ERROR at teardown`, because it runs after the fixtures finish. It works with `pytest -n` (xdist). In GitHub Actions the verdicts also go to the job summary, and there's a ready-made [action](action.yml).

## Fix it: the safety filter

```python
from traceleakcheck.guard import scrub

tracer_provider.add_span_processor(BatchSpanProcessor(scrub(OTLPSpanExporter())))
logger_provider.add_log_record_processor(BatchLogRecordProcessor(scrub(OTLPLogExporter())))
```

Before anything is exported, the filter removes:
- **Known secrets:** the values of environment variables named like `*KEY*`, `*TOKEN*`, `*SECRET*` or `*PASSWORD*`, plus anything registered with `add_secret()`. Their base64, URL and hex forms are removed too.
- **Well-known key formats:** OpenAI, Anthropic, AWS, GitHub, Google, Slack, JWT and Bearer tokens, and credential query parameters such as `?key=`.

It covers span names, attributes, exception events, status messages, log bodies and log attributes.

A filter can't recognize a secret that matches none of these rules, such as an unusual password a user types. That's why the two go together: **the filter is the fix, and `pytest --traceleak` is the proof.**

## Tested on real code

We pointed TraceLeakCheck at the [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo)'s AI shop assistant (LangGraph + Traceloop), unmodified, talking to a fake LLM:

| Scenario | Without the filter | With `scrub()` |
|---|---|---|
| A shopper pastes a key into the chat | 🚨 leaked in **9** places | ✅ clean |
| The service's own API key | ✅ clean | ✅ clean |
| The LLM gateway rejects the key and echoes it | 🚨 leaked in **15** places | ✅ clean |

One secret becomes many copies, because every layer of an agent (chat step, agent step, workflow) records its own copy. The run also surfaced a real integration bug in TraceLeakCheck: the Traceloop SDK ignores `OTEL_EXPORTER_OTLP_*`. That's now fixed.

## Survey: do GenAI instrumentations leak secrets?

[survey/FINDINGS.md](survey/FINDINGS.md) runs the OpenAI SDK under OTel openai-v2, OpenLLMetry, OpenInference, Logfire and httpx instrumentation, across 6 leak scenarios:

- **No content opt-out we tested stops a secret in an error message.** That includes `TRACELOOP_TRACE_CONTENT=false`, `OPENINFERENCE_HIDE_*` and `NO_CONTENT`.
- **`?key=` query auth is exported verbatim** in `http.url`.
- **Logfire's default scrubbing skips LLM messages and exception messages**, even when they contain "API key".
- **OTel openai-v2's documented legacy `CAPTURE_MESSAGE_CONTENT=true` falls back to `NO_CONTENT`** on util-genai 1.x, with only a log warning.

## Limits

- **Python and pytest only** for now.
- **Sampling is forced on** with `OTEL_TRACES_SAMPLER=always_on`. An app that passes an explicit sampler in code can still drop the span that leaks.
- **Telemetry that isn't OTLP**, such as metrics read by a Prometheus reader, can't be checked. Skip it with `--traceleak-ignore=metrics`.

## Compared to Weir

[Weir](https://github.com/IdoGol24/weir) uses the same canary idea, and it covers more ground: it runs agent flows against a fake model and checks console output and network requests as well as telemetry. TraceLeakCheck focuses on the OTLP export boundary, needs no fake model, and ships a fix (`scrub()`) alongside the check.

Weir's README says it "finds whole values only, not hashed, split or truncated ones". TraceLeakCheck catches truncated secrets. It also has tests for base64 at any byte offset, secrets used as attribute keys, protobuf fields the decoder drops, and mixed-case hex. As of 2026-11-01, Weir's README doesn't say either way whether it handles these.

<details>
<summary><b>Library API</b></summary>

```python
from traceleakcheck import OTLPReceiver, make_canary, scan

with OTLPReceiver() as rx:
    canary = make_canary("openai")
    # point your OTLP exporter at rx.endpoint, run your app with canary.value as the API key...
    findings = scan(rx.snapshot(), [canary])
```
</details>

## Develop

```sh
uv sync
uv run pytest
```
