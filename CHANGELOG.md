# Changelog

## Unreleased (0.2.0)

### Any language
- `traceleakcheck run -- <command>` checks an app in any language from the outside. It plants fake secrets in env vars (`--secret`), points the app's SDK at the receiver with the standard `OTEL_*` settings, runs the app, and scans what arrived. Exit codes: 0 clean, 1 leak, 2 couldn't check.
- Server mode: `--drive` runs a command against the app (with `{ENV}` replaced by the fake secret) once `--ready-url` answers. Then it stops the whole process tree, gracefully first.
- The control for outside apps requires spans, logs or metrics (`--expect`) to have arrived, counted per item rather than per payload. A clean result prints what was scanned.
- `--port` and `--app-endpoint` let the app send through an OpenTelemetry Collector that forwards to traceleakcheck.
- Inherited per-signal endpoints and `OTEL_SDK_DISABLED` are removed from the app's environment, so its telemetry can't silently go elsewhere.
- The GitHub Action has a `command:` input.
- `pip install traceleakcheck[grpc]` adds gRPC support for apps whose exporters use OTLP over gRPC.

### Fix for any language
- `examples/collector/redact.yaml`: a Collector `transform` config that removes well-known key formats and credential query parameters from span names, attributes, error events, status messages, logs and metrics.

### Examples
- `examples/node_agent`: a Node app (official OTel SDK) whose error message leaks its key. CI proves the Action catches it. `node app.js --proof` also leaks it through a span attribute, a `?key=` URL, a log record and a metric. `examples/collector/prove.ps1` uses it to test the Collector config.

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
