# TraceLeakCheck

> Prove your AI app's OpenTelemetry export doesn't leak secrets.

Redaction processors pass their unit tests while secrets still leave through an exception span, a log record or a tool-call attribute. TraceLeakCheck tests the **export boundary itself**:

1. It plants unique **canary secrets** in realistic formats (OpenAI, Anthropic, AWS, GitHub, JWT, password).
2. It captures what your app's real instrumentation exports, using an in-process **OTLP/HTTP receiver** (traces, logs and metrics, protobuf or JSON, gzip).
3. It **scans** every exported field for the canary: raw, base64 at any byte offset, base64url, URL-encoded or hex. Each finding gives the exact attribute path.

The receiver records undecodable requests as errors, and an empty capture is never treated as a pass. "Nothing arrived" is not "nothing leaked".

## Use it in pytest

```python
def test_agent_does_not_leak_key(canary):
    key = canary("openai").value          # fresh fake secret; this test is now checked
    run_agent("summarize this", api_key=key)
```

```sh
pytest --traceleak                        # optional: --traceleak-report=leaks.json
```

`--traceleak` starts the receiver and points the standard `OTEL_EXPORTER_OTLP_*` env vars at it before your `conftest.py` loads. Any app that configures OTel from the environment needs no changes. If your app builds a provider by hand, register it with `traceleak.watch(provider)`.

Every test that uses `canary` is checked after its fixtures tear down, so leaks from clients closing count too. A failed check is reported as an error in the test's teardown. It works with `pytest -n` (xdist). Each test gets one of four verdicts:

| Verdict | Meaning | Test |
|---|---|---|
| `clean` | The traces pipeline delivered the control span, and no canary was found in any signal | passes |
| `leak` | A canary was found; the report names each field | fails |
| `incomplete` | The positive-control span never arrived, so "clean" can't be claimed | fails |
| `error` | An export couldn't be decoded, so the scan would under-report | fails |

In GitHub Actions, the verdict table is also written to the job summary.

Limits:
- **The positive control covers traces only.** A logs pipeline that is broken or turned off (`OTEL_LOGS_EXPORTER=none`) is not detected.
- **Sampling is forced on through `OTEL_TRACES_SAMPLER=always_on`.** An app that passes an explicit sampler in code can still drop the span that leaks.

### Demo

[examples/demo_agent](examples/demo_agent/) redacts API keys from its prompts, and that redaction passes its unit test. The key still leaks:

```
$ pytest examples/demo_agent --traceleak
TRACELEAK LEAK: canary secret found in exported telemetry:
  - openai canary (raw) in span 'llm.call' at ...events[0].attributes[exception.message].stringValue
  - openai canary (raw) in span 'llm.call' at ...events[0].attributes[exception.stacktrace].stringValue
  - openai canary (raw) in span 'llm.call' at ...spans[0].status.message
```

An HTTP error echoed the key, and the OTel SDK copied the exception text into both the exception event and the span status.

### Library API

```python
from traceleakcheck import OTLPReceiver, make_canary, scan

with OTLPReceiver() as rx:
    canary = make_canary("openai")
    # point your OTLP exporter at rx.endpoint, run your app with canary.value as the API key...
    findings = scan(rx.snapshot(), [canary])
```

## Compared to Weir

[Weir](https://github.com/IdoGol24/weir) uses the same canary idea. It is broader: it runs agent flows against a fake model and checks console output and network requests as well as telemetry. TraceLeakCheck focuses on the OTLP export boundary and needs no fake model.

Weir's README says it "finds whole values only, not hashed, split or truncated ones". TraceLeakCheck catches truncated secrets. It also has tests for the forms below, which Weir's README doesn't document either way as of 2026-11-01:

- base64 at any byte offset
- a secret used as an attribute key
- protobuf fields the decoder drops
- mixed-case hex

## Develop

```sh
uv sync
uv run pytest
```
