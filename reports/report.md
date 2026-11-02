# TraceLeakCheck: progress report

*From the first commit (1 Nov 2026, 15:30) to now (2 Nov 2026). All times are the repo's commit times, US Pacific.*

**Repo:** https://github.com/preetsaini2004/traceleakcheck · **PyPI:** `pip install traceleakcheck` · **Survey page:** https://preetsaini2004.github.io/traceleakcheck/

---

## 1. Summary

- **Built:** TraceLeakCheck, a tool that checks whether an app's OpenTelemetry monitoring data leaks secrets. It has three parts: a pytest plugin, a command that checks apps in any language, and a safety filter.
- **How long:** about 22 hours from first commit to version 0.2.1. That's 31 commits and 3 releases (0.1.0, 0.2.0 and 0.2.1).
- **What it found:**
  - A real bug in OpenTelemetry itself. It was reported upstream as [opentelemetry-python-contrib#5279](https://github.com/open-telemetry/opentelemetry-python-contrib/issues/5279).
  - Five more findings about popular AI monitoring libraries, published as a survey.
- **Today's review:**
  - The checker part was solid.
  - The safety filter had 4 bugs, and the Collector config had a coverage gap. One of the filter bugs was the same one reported upstream.
  - All of them are now fixed, tested and released.

---

## 2. What the tool does

Apps send monitoring data (traces, logs, metrics) to dashboards, and secrets often ride along. Examples: an API key inside an error message, a password a user pasted into a chat, a token in a URL.

TraceLeakCheck:
1. **Plants a fake secret** (a "canary") in the app.
2. **Catches everything the app actually exports**, using a local OpenTelemetry receiver.
3. **Searches every field** for the canary, including encoded copies (base64, URL, hex, truncated).
4. **Reports in plain English** where it leaked, with tips on how to fix it.

It has a **control check**: a marker must arrive through every pipeline. Without that, "nothing arrived" could look like "nothing leaked", and the result can never be a false "clean".

| Part | What it's for |
|---|---|
| `pytest --traceleak` | Check Python apps inside their tests |
| `traceleakcheck run -- <cmd>` | Check an app in any language from outside |
| `scrub()` safety filter | Remove secrets inside a Python app before export |
| `examples/collector/redact.yaml` | Remove secrets for any language, using an OpenTelemetry Collector |
| GitHub Action | Fail CI when a leak is found |

---

## 3. Timeline

### Day 1: 1 Nov 2026, building it (15:30 to 19:40)

| Time | What happened |
|---|---|
| 15:30 | First commit: canary-based leak detection plus the pytest plugin |
| 15:34 | Per-signal control check, teardown check, xdist support, GitHub Action |
| 15:46 | **Survey** started: 5 AI monitoring libraries tested with 8 scenarios |
| 15:51 | Survey findings checked against library source code, plus a guard against misconfigured runs |
| 16:07 | Plain-English results and HTML report |
| 16:18 | Fix: Traceloop SDK ignored the standard settings, now pointed at the receiver |
| 16:41 | OTLP over gRPC as well as HTTP |
| 16:46 | **Safety filter** `scrub()` added |
| 17:06 | README redesign: banner, screenshots, diagram, license |
| 17:15 | Spans left open are reported as "incomplete"; streaming scenarios added |
| 17:16 | **Release 0.1.0** |
| 17:17 | Automatic PyPI publishing from GitHub releases |
| 18:15 | Survey: linked upstream issues, **confirmed the X-Amz redaction gap** |
| 18:40 | **Reported the bug upstream: [opentelemetry-python-contrib#5279](https://github.com/open-telemetry/opentelemetry-python-contrib/issues/5279)** |
| 18:46 | Survey page published on GitHub Pages |
| 19:33 | `traceleakcheck run`: check apps in **any language** |
| 19:37 | Node demo with a `--proof` mode that leaks through every channel |
| 19:40 | **Release 0.2.0** |

### Day 2: 2 Nov 2026, review and fixes

| Step | What happened |
|---|---|
| Upstream check | Looked into PR #5280 on your issue (section 5) and posted a polite co-author request |
| Code review | Read the code, ran the 73 tests and tested the filter by hand. Found 4 filter bugs (section 6) |
| PR #1 (merged) | Fixed all 4 filter bugs, then also a path-detection bug introduced along the way |
| Second review | Found a Collector config gap and a "dropped count" bug |
| PR #2 (merged) | Fixed both, plus a new CI job that proves the Collector config works |
| Release 0.2.1 | All fixes released |

---

## 4. Survey findings (Day 1)

TraceLeakCheck was run against the OpenAI SDK under 5 OpenTelemetry instrumentations, with 8 secret-leak scenarios each. Full results are in `survey/FINDINGS.md`.

1. **Privacy settings don't cover errors.** Every library's "don't record content" setting still records error messages. A secret inside an error leaks in all of them.
2. **The httpx instrumentation exports `?key=` and S3 signature URLs verbatim.** This is the bug reported upstream as **#5279**.
3. **Logfire doesn't scrub LLM messages or error messages**, on purpose according to its source code.
4. **OTel openai-v2's documented `=true` setting silently captures nothing** on current versions.
5. **A fresh install of OTel openai-v2 fails to import.** This was already reported upstream as genai#997.
6. **Streaming:** a secret split across stream chunks gets reassembled, and an abandoned stream can hide a leak.

**Real-world test:** on the OpenTelemetry Demo's AI shop assistant, one pasted key leaked in **9** places and a key echoed by the gateway leaked in **15**. With `scrub()`, both came out clean.

---

## 5. The upstream issue and PR #5280

- **#5279 (your issue):** `PARAMS_TO_REDACT` in `opentelemetry-util-http` is missing `X-Amz-Signature`, `X-Amz-Credential` and `X-Amz-Security-Token`. So S3 presigned URLs leak their signature and session token into traces. You found it with TraceLeakCheck and offered to write the fix.
- **PR #5280 by Akshaay1:**
  - It was opened about 4.5 hours after your issue.
  - It reuses your repro values word for word, and the code change is the fix you suggested.
  - He didn't ask on the issue first. The PR is AI-assisted and says so.
  - It links your issue with `Fixes #5279`.
- **What we did:** posted a polite comment asking to be added as `Co-authored-by: preetsaini2004`, using your noreply address.
- **Status:** the PR is still a draft, with no reply yet.

---

## 6. Problems found in review, and the fixes

### PR #1: safety filter (`scrub()`)

| # | Problem | How big | Fix |
|---|---|---|---|
| 1 | **The same bug as #5279.** S3 links leaked `X-Amz-Security-Token` and `X-Amz-Signature` | 🟡 Medium, and embarrassing | Now redacts every query parameter the OTel semantic conventions list, plus the Google ones |
| 2 | **Redacted too much.** `DEPLOY_KEY_NAME=production` erased "production" from every trace | 🟢 Small | Plain words, region names, file paths and URLs without a password are left alone. `*PASSWORD*` and `*SECRET*` values are always scrubbed |
| 3 | **Slow.** Re-read every environment variable for every single string | 🟢 Small | Reads them once per export batch: **258 µs to 5.4 µs per string (about 48× faster)** |
| 4 | **Missed fields.** Resource and link attributes weren't checked | 🟢 Tiny | Both are scrubbed now |
| 4b | **Bug from fix #2:** a password starting with `/`, `~` or `.` was mistaken for a file path | 🟢 Small | A value only counts as a path if it has a folder in it |

### PR #2: Collector config and dropped counts

| # | Problem | How big | Fix |
|---|---|---|---|
| 5 | **The Collector config was weaker than the README said.** The `?token=` rule ran only on span attributes, so it leaked in logs, metrics and status messages | 🟡 Medium | The rule now runs on every field, with the same parameter list as `scrub()`. Log and metric resource attributes are covered too |
| 6 | **`scrub()` reset "dropped" counts to 0**, hiding data loss from dashboards | 🟢 Small | The counts are carried over for attributes, events and links |

---

## 7. How each fix was proven

- **Tests that fail first:** every bug got a test that **fails on the old code** and passes on the new code.
  - PR #1: 8 such tests out of 19 new ones.
  - PR #2: `(0, 0, 0) != (2, 2, 1)` on the old code.
- **Test suite:** 73 passing tests at the start of Day 2, **93** now (1 skipped).
- **CI:** all checks green on both PRs. That covers Python 3.10 to 3.14 on Ubuntu and Windows, the Node demo and the GitHub Action.
- **Collector proof, now in CI:** a new CI job runs otelcol-contrib 0.164.0 on every push:

  | Run | Result |
  |---|---|
  | Node `--proof` **without** the Collector | 🚨 leaked in **15** places (spans, errors, status, logs, metrics) |
  | Node `--proof` **through** the Collector | ✅ clean |

---

## 8. Releases

| Version | Date | Highlights |
|---|---|---|
| 0.1.0 | 1 Nov | pytest plugin, receiver, plain-English and HTML reports, `scrub()`, GitHub Action |
| 0.2.0 | 1 Nov | `traceleakcheck run` for any language, gRPC extra, Collector config, Node demo |
| 0.2.1 | 2 Nov | All the fixes in section 6 |

**0.2.1 status (2 Nov): ✅ live.**
- Release commit `7b69db6` on `main`, CI passed (10/10 jobs).
- GitHub release: https://github.com/preetsaini2004/traceleakcheck/releases/tag/v0.2.1
- The publish workflow succeeded, and `pip install traceleakcheck` now installs **0.2.1**: https://pypi.org/project/traceleakcheck/0.2.1/

---

## 9. What's left

- **Upstream PR #5280:** waiting for a reply about co-authorship.
- **Small tidy-ups:** ruff reports a few auto-fixable warnings (unused imports and the like) that were already there. None of them affect users.
- **Known limit, by design:** a plain-word secret under a `*KEY*` or `*TOKEN*` env name (e.g. `API_TOKEN=correcthorsebattery`) isn't scrubbed automatically. Register it with `add_secret()`. The README documents this.
- **Ideas:**
  - Upstream finding #2 notes that OTel's list doesn't include `key` either. That could be a follow-up proposal.
  - The survey could be re-run on the new `opentelemetry-instrumentation-genai-openai` package.
