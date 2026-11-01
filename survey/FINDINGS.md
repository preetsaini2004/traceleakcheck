# Do GenAI instrumentations leak your secrets? A survey

*traceleakcheck survey, 2026-11-01. Raw matrix: [RESULTS.md](RESULTS.md). Reproduce: `uv sync --group survey && uv run python survey/run.py`.*

We ran the OpenAI Python SDK under five OpenTelemetry instrumentations, plus a bare baseline. Six scenarios each plant a canary secret. traceleakcheck captured every OTLP export (traces, logs, metrics) and searched it for the canary in raw and encoded forms. Every run passed the positive control, so telemetry provably arrived. "Clean" therefore means the canary was in nothing that was exported. As #4 shows, that only means something if the library was really configured to capture content. `run.py` therefore marks any capture-enabled config whose content scenarios come back clean as `MISCONFIGURED`.

Versions tested: openai 2.54.0, opentelemetry-sdk 1.45.2, opentelemetry-instrumentation-openai-v2 2.4b0, OpenLLMetry `opentelemetry-instrumentation-openai` 0.62.4, `openinference-instrumentation-openai` 0.1.69, logfire 5.4.0, `opentelemetry-instrumentation-httpx` 0.66b2.

## Results

| Scenario | OTel openai-v2 default | OTel openai-v2 content | OTel openai-v2 `NO_CONTENT` | OpenLLMetry default | OpenLLMetry `TRACE_CONTENT=false` | OpenInference default | OpenInference `HIDE_INPUTS/OUTPUTS` | Logfire default | httpx |
|---|---|---|---|---|---|---|---|---|---|
| Secret pasted in the prompt | clean | **leak** | clean | **leak** | clean | **leak** | clean | **leak** | clean |
| Secret repeated in the completion | clean | **leak** | clean | **leak** | clean | **leak** | clean | **leak** | clean |
| Secret in tool-call arguments | clean | **leak** | clean | **leak** | clean | **leak** | clean | **leak** | clean |
| API key in `Authorization` header | clean | clean | clean | clean | clean | clean | clean | clean | clean |
| API key in URL query (`?key=`) | clean | clean | clean | clean | clean | clean | clean | clean | **leak** |
| Error message echoes the API key | **leak** | **leak** | **leak** | **leak** | **leak** | **leak** | **leak** | **leak** | clean |

## Findings

### 1. Content opt-outs do not cover exceptions

Every privacy setting we tested kept prompts, completions and tool arguments out of telemetry:

- OpenLLMetry `TRACELOOP_TRACE_CONTENT=false`
- OpenInference `OPENINFERENCE_HIDE_INPUTS` / `_OUTPUTS`
- OTel openai-v2 `NO_CONTENT`

None of them stopped a secret inside an **error message**. Every instrumentation records the exception: it copies the message into `exception.message`, `exception.stacktrace` and the span's `status.message`. openai-v2 sets `status.message` only. The secret travels with them.

- **When this happens:** whenever an error string contains a secret. Examples are a gateway or proxy that echoes the rejected key, an HTTP client error that includes a URL with a key in it, or a validation error that quotes user input.
- **Caveat:** the OpenAI API itself masks keys in its 401 messages. This scenario stands for gateways and proxies that don't.
- **Mitigation:** none of these settings help. You need a span processor or exporter that scrubs exception events and status, or the error has to be fixed at its source.

### 2. `?key=` query parameters are exported verbatim by the httpx instrumentation

`opentelemetry-util-http` 0.66b2 redacts only `AWSAccessKeyId`, `Signature`, `sig` and `X-Goog-Signature` (`PARAMS_TO_REDACT`). That is a subset of the 7 keys the [semantic conventions](https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/url.md) say SHOULD be redacted; the three `X-Amz-*` keys are missing. Neither list includes `key`.

APIs that take their key as `?key=` therefore get it written into `http.url` / `url.full`. Examples are gateways and several Google REST APIs. The GenAI instrumentations didn't record URLs at all in our runs.

### 3. Logfire does not scrub LLM messages or exception messages

Logfire scrubs by pattern by default, and `api[._ -]?key` is one of its patterns. Even so, both of these left the process unscrubbed:

- the prompt `OPENAI_API_KEY=<secret>`;
- the error `Invalid API key: <secret>`.

Both are deliberate, according to `logfire/_internal/scrubbing.py` in 5.4.0:
- `gen_ai.input.messages` and `gen_ai.output.messages` are on its `SAFE_KEYS` list, which exempts them from scrubbing.
- A comment there says: *"We used to scrub exception messages here, git blame this line if you want to restore that logic."*

Don't rely on default scrubbing for secrets inside LLM content or errors.

### 4. OTel openai-v2's documented legacy `=true` captures nothing on current util-genai

The 2.4b0 README documents `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` as the *"Legacy"* value, for event-based capture when the experimental semconv is off. With `opentelemetry-util-genai` 1.0b0 or 1.1b0, the value is rejected. Capture falls back to `NO_CONTENT`, and the only sign is a log warning: *"true is not a valid option … Must be one of NO_CONTENT, SPAN_ONLY, EVENT_ONLY, SPAN_AND_EVENT. Defaulting to `NO_CONTENT`."* With util-genai 0.4b0, `=true` works.

The README describes `span_only` as applying only when `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental` is set. In our runs (util-genai 1.1b0), `SPAN_ONLY` captured content without that setting.

This failure goes the safe direction (less data). But a team that thinks it is auditing captured content is auditing nothing. It also nearly fooled this survey: our first run reported openai-v2 "content" as clean. traceleakcheck's positive control proves telemetry *arrived*; it can't tell that a library was configured to capture nothing. That's why the survey now checks that captures were expected.

Related but different: [#4038](https://github.com/open-telemetry/opentelemetry-python-contrib/issues/4038), where `span_and_event` captured nothing, fixed in July 2026. A search on 2026-11-01 found no existing issue for the `=true` rejection.

### 5. A fresh install of OTel openai-v2 fails to import

`pip install opentelemetry-instrumentation-openai-v2` (2.4b0) resolves `opentelemetry-util-genai` 1.3b0. That version doesn't ship `opentelemetry.util.genai.instruments` (1.2b0 doesn't either), so the import fails with `ModuleNotFoundError`. The cause is that openai-v2 requires only `opentelemetry-util-genai>=0.4b0.dev`, with no upper bound. Pinning `opentelemetry-util-genai==1.1b0` works. openai-v2 2.4b0 (2026-05-01) is the latest release. A search on 2026-11-01 found no existing issue for this.

Separately, openai-v2 imports `httpx`, which the `openai` SDK 3.x no longer depends on (it moved to `httpx2`). We tested on openai 2.54.0 for that reason.

## What was clean everywhere

The client's own API key in the `Authorization` header never appeared in any export. No instrumentation records request headers by default.

## Method and limits

- **Fake server:** a local fake OpenAI server returns canned completions, tool calls and errors. No real API was called.
- **Non-streaming only:** we tested only non-streaming chat completions, plus a 401 error path.
- **Fresh secrets:** each scenario plants a fresh canary in a realistic `sk-proj-…` format.
- **Encoded leaks counted:** findings include encoded forms, but every leak above was raw.
- **Default exporter settings:** attribute length limits weren't changed, so nothing was truncated.
- **Versions matter:** these results describe the versions listed above. Re-run `survey/run.py` to check yours.
