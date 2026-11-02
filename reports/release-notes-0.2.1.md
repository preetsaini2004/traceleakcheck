### Safety filter (`scrub()`)
- Removes every query parameter the OpenTelemetry semantic conventions say to redact. Before, `X-Amz-Signature`, `X-Amz-Security-Token` and `X-Goog-Signature` in S3/GCS presigned URLs were exported unchanged: the same gap as [opentelemetry-python-contrib#5279](https://github.com/open-telemetry/opentelemetry-python-contrib/issues/5279).
- Env values that are plainly not secrets are no longer scrubbed from every string. Before, `DEPLOY_KEY_NAME=production` turned `region=production-eu` into `region=[REDACTED]-eu`. Skipped: file paths, URLs without a password, and plain words, slugs and numbers under `*KEY*` / `*TOKEN*` / `*AUTH*` / `*CREDENTIAL*` names. `*SECRET*` and `*PASSWORD*` values are still always scrubbed.
- About 48x faster: the environment is read once per export batch, not once per string (258 µs to 5.4 µs per string).
- Also scrubs resource attributes and span link attributes.
- Keeps the SDK's dropped attribute, event and link counts. Before, a span that hit its limits was exported with `dropped_*_count` 0, hiding the data loss from the backend.

### Collector config (`examples/collector/redact.yaml`)
- The credential query-parameter rule now runs on every field: span names and status messages, error event names, log bodies and attributes, metric attributes and resource attributes. Before, it covered only span and error-event attributes, so a `?token=` URL in a log message passed through.
- The rule's parameter list matches `scrub()`: adds `auth`, `secret`, `password`, `apikey`, `AWSAccessKeyId`, `X-Goog-Signature` and `X-Goog-Credential`.
- Resource attributes of logs and metrics are scrubbed too (before: traces only).
- The Node demo's `--proof` mode sends a shapeless password in a `?token=` URL through every channel, and CI now runs the Collector proof on every push.

