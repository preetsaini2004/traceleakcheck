# Changelog

## 0.1.0 (2026-11-02)

First release.

### Find
- `pytest --traceleak` plugin: the `canary` fixture plants fake secrets (OpenAI, Anthropic, AWS, GitHub, JWT, password). Each test that uses it is checked after its fixtures finish.
- An in-process OTLP receiver takes traces, logs and metrics on one port, over HTTP (protobuf or JSON, gzip) or gRPC.
- Detection catches raw, truncated, base64 at any byte offset, base64url, URL-encoded and hex forms, as well as secrets used as attribute keys or hidden in protobuf fields the decoder drops.
- Verdicts are `clean`, `leak`, `incomplete` and `error`. `clean` is given only when a control marker arrived through every configured pipeline and no span was left open.
- `OTEL_EXPORTER_OTLP_*` and `TRACELOOP_BASE_URL` are set before `conftest.py` loads, and sampling is forced on. xdist is supported.

### Explain
- Plain-English results in the terminal: which secret, which step, which field, and how to fix it. Repeated leaks are grouped. `-v` adds field paths.
- `--traceleak-html` writes a report page, `--traceleak-report` writes JSON, and GitHub Actions gets a job summary.

### Fix
- `traceleakcheck.guard.scrub()` wraps a span or log exporter. It removes secret-named environment variables, registered secrets and well-known key formats, plus credential query parameters, before anything is exported.

### Research
- `survey/`: the OpenAI SDK under OTel openai-v2, OpenLLMetry, OpenInference, Logfire and httpx instrumentation, across 8 leak scenarios. See `survey/FINDINGS.md`.
- Tested on the OpenTelemetry Demo's AI agent: 24 leaked copies without the filter, 0 with it.
