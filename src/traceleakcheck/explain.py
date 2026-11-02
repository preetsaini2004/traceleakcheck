"""Turn findings into plain English: what leaked, where, and how to fix it.

Shared by the terminal output and the HTML report. Never includes secret values: finding paths
are already masked by the scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

KIND_NAMES = {
    "openai": "OpenAI API key",
    "anthropic": "Anthropic API key",
    "aws": "AWS access key",
    "github": "GitHub token",
    "jwt": "login token (JWT)",
    "password": "password",
}

VARIANT_NAMES = {
    "raw": "in plain text",
    "truncated": "cut short, but still recognizable",
    "url": "URL-encoded",
    "hex": "hex-encoded",
}


@dataclass
class Tip:
    title: str
    text: str
    code: str = ""


TIPS = {
    "error": Tip(
        "An error message is carrying the secret",
        "When something fails, the error text gets recorded, and here it contains the secret. Hide "
        "secrets before raising the error, or don't put them in URLs or messages in the first place.",
        'raise ConnectionError(redact(message))  # hide secrets before raising',
    ),
    "content": Tip(
        "Prompts or AI replies are being recorded",
        "Your AI monitoring library saves message text, and a secret was in that text. Turn content "
        "capture off, or remove secrets before sending messages to the model.",
        "TRACELOOP_TRACE_CONTENT=false             # OpenLLMetry\n"
        "OPENINFERENCE_HIDE_INPUTS=true            # OpenInference\n"
        "OPENINFERENCE_HIDE_OUTPUTS=true",
    ),
    "url": Tip(
        "The secret is inside a web address",
        "Web addresses get recorded in full. Send keys in a request header, never as ?key=... in the URL.",
        'client = OpenAI(api_key=key)  # sent as a header, not ?key=',
    ),
    "log": Tip(
        "A log line contains the secret",
        "Something logs the secret. Remove it from the log message, or redact it first.",
        'log.info("calling the API")  # don\'t include the key',
    ),
    "field": Tip(
        "A monitoring field is set to the secret",
        "Your code or a library stores the secret in a monitoring field. Redact it before it's set.",
        'span.set_attribute("prompt", redact(prompt))',
    ),
    "hidden": Tip(
        "The secret is in data the decoder couldn't read",
        "It's inside the exported data but not in any standard field, so we can't name the exact spot. "
        "Check custom exporters or instrumentation that add their own fields.",
    ),
}

SAFETY_NET = Tip(
    "Add a safety net for the whole app",
    "Wrap your exporter with traceleakcheck's filter. It removes known secrets (secret-named env vars, "
    "common key formats, ?key= in URLs) from everything before it leaves your app. Then re-run "
    "pytest --traceleak to prove it worked.",
    "from traceleakcheck.guard import scrub\n"
    "provider.add_span_processor(BatchSpanProcessor(scrub(OTLPSpanExporter())))",
)

INCOMPLETE_TIP = Tip(
    "We couldn't check",
    "Some or all of your app's monitoring data never reached TraceLeakCheck, so it can't promise "
    "anything is clean. Make sure your "
    "app sets up OpenTelemetry from the standard OTEL_EXPORTER_OTLP_* settings, or register it with "
    "traceleak.watch(provider). Skip signals you don't send over OTLP with --traceleak-ignore.",
)
# `traceleakcheck run` checks apps in any language, so its tips can't point at Python-only fixes.
RUN_INCOMPLETE_TIP = Tip(
    "We couldn't check",
    "Your app's monitoring data never reached TraceLeakCheck, so it can't promise anything is clean. "
    "Make sure the app sets up OpenTelemetry with an OTLP exporter that reads OTEL_EXPORTER_OTLP_ENDPOINT, "
    "and that it shuts the SDK down before exiting so the last batch is sent.",
)
RUN_SAFETY_NET = Tip(
    "Add a safety net that works for any language",
    "Send your telemetry through an OpenTelemetry Collector that removes secrets before they reach your "
    "dashboard (see examples/collector/redact.yaml). Then re-run traceleakcheck run to prove it worked.",
)
ERROR_TIP = Tip(
    "Some monitoring data couldn't be read",
    "Part of what your app exported was unreadable, so a leak could be hiding in it. Check that your "
    "exporter speaks standard OTLP over HTTP.",
)


@dataclass
class Place:
    what: str  # "the error message"
    how: str  # "in plain text"
    tip: str  # key into TIPS
    path: str  # technical path, for -v and the HTML details


@dataclass
class Group:
    """Steps that leaked in exactly the same places, shown once instead of once per step."""

    steps: list[str]
    places: list[Place]  # as seen in the first step
    paths: list[str]  # every technical path across all the steps, for -v and HTML details

    def where(self) -> str:
        if len(self.steps) == 1:
            s = self.steps[0]
            return f"In {s}" if s.startswith(("a ", "exported")) else f'In step "{s}"'
        return f"In {len(self.steps)} steps: " + ", ".join(f'"{s}"' for s in self.steps)


@dataclass
class Explanation:
    status: str
    headline: str
    groups: list[Group] = field(default_factory=list)
    tips: list[Tip] = field(default_factory=list)


def _place(f: dict) -> Place:
    path = f["path"]
    how = VARIANT_NAMES.get(f["variant"].split("[")[0], "encoded")
    if f["variant"].startswith("base64"):
        how = "base64-encoded"
    if path.startswith("<raw body"):
        return Place("a field the decoder couldn't name", how, "hidden", path)
    keys = re.findall(r"attributes\[([^\]]+)\]", path)
    attr = keys[-1] if keys else ""
    low = attr.lower()
    if path.endswith("#key"):
        return Place(f"the name of a field ({attr})", how, "field", path)
    if path.endswith("status.message"):
        return Place("the step's status message", how, "error", path)
    if low == "exception.message":
        return Place("the error message", how, "error", path)
    if low == "exception.stacktrace":
        return Place("the error's stack trace", how, "error", path)
    if "url" in low:
        return Place(f"the request web address ({attr})", how, "url", path)
    if any(w in low for w in ("input", "prompt")):
        return Place(f"the saved prompt ({attr})", how, "content", path)
    if any(w in low for w in ("output", "completion", "response", "choice")):
        return Place(f"the saved AI reply ({attr})", how, "content", path)
    if f["signal"] == "logs" and not attr:
        return Place("a log message", how, "log", path)
    if f["signal"] == "metrics":
        return Place(f"a metric label ({attr or 'unknown'})", how, "field", path)
    return Place(f"the '{attr}' field" if attr else "an exported field", how, "field", path)


def explain(result: dict) -> Explanation:
    status = result["status"]
    cli = result.get("runner") == "cli"
    if status == "clean":
        return Explanation(status, "No leak: your secrets stayed out of the monitoring data.")
    if status == "incomplete":
        return Explanation(status, "Couldn't check: expected monitoring data never arrived.",
                           tips=[RUN_INCOMPLETE_TIP if cli else INCOMPLETE_TIP])
    if status == "error":
        return Explanation(status, "Couldn't fully check: some monitoring data was unreadable.", tips=[ERROR_TIP])

    findings = result["findings"]
    kinds = sorted({KIND_NAMES.get(f["canary_kind"], f["canary_kind"]) for f in findings})
    n = len(findings)
    headline = f"Your {' and '.join(kinds)} leaked into your app's monitoring data ({n} place{'s' * (n != 1)})."
    exp = Explanation(status, headline)
    tip_keys = []
    by_step: dict[str, list[Place]] = {}
    for f in findings:
        p = _place(f)
        step = f["span"] or {"logs": "a log record", "metrics": "a metric"}.get(f["signal"], "exported data")
        by_step.setdefault(step, []).append(p)
        if p.tip not in tip_keys:
            tip_keys.append(p.tip)
    groups: dict[tuple, Group] = {}
    for step, places in by_step.items():
        sig = tuple((p.what, p.how) for p in places)
        if sig in groups:
            groups[sig].steps.append(step)
            groups[sig].paths += [p.path for p in places]
        else:
            groups[sig] = Group([step], places, [p.path for p in places])
    exp.groups = list(groups.values())
    exp.tips = [TIPS[k] for k in tip_keys] + [RUN_SAFETY_NET if cli else SAFETY_NET]
    return exp


def terminal_lines(result: dict, verbose: bool = False) -> list[str]:
    """ASCII-only: Windows consoles redirected to a file can't always encode emoji."""
    exp = explain(result)
    label = {"leak": "LEAK FOUND", "incomplete": "COULDN'T CHECK", "error": "COULDN'T FULLY CHECK"}.get(
        exp.status, "CLEAN")
    out = [f"{label}: {exp.headline}"]
    for g in exp.groups:
        out.append(f"  {g.where()}:")
        for p in g.places:
            out.append(f"    - {p.what} ({p.how})")
        if verbose:
            out += [f"        {path}" for path in g.paths]
    if exp.status in ("incomplete", "error") and result.get("detail"):
        out.append(f"  Details: {result['detail']}")
    for t in exp.tips:
        out.append(f"  How to fix: {t.title}. {t.text}")
    return out
