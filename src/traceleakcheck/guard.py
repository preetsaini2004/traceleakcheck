"""Safety filter: scrub secrets out of telemetry before it leaves the app.

Wrap the exporter you already use, in your app (not just in tests):

    from traceleakcheck.guard import scrub
    tracer_provider.add_span_processor(BatchSpanProcessor(scrub(OTLPSpanExporter())))
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(scrub(OTLPLogExporter())))

What gets removed, everywhere in a span (name, attributes, event attributes such as
exception.message / exception.stacktrace, status message) and in log records (body, attributes):
  1. Known secrets: values of environment variables whose name contains KEY, TOKEN, SECRET,
     PASSWORD, CREDENTIAL or AUTH, plus anything passed to add_secret() or scrub(secrets=...),
     including their base64 / URL / hex forms.
  2. Well-known key formats (OpenAI, Anthropic, AWS, GitHub, Google, Slack, JWT, Bearer) and
     credential query parameters such as ?key=... in URLs.

It cannot know about secrets that match neither, so keep running `pytest --traceleak`: the filter
is the fix, traceleakcheck is the proof. Metrics are not filtered.
"""

from __future__ import annotations

import copy
import dataclasses
import os
import re
from collections.abc import Iterable, Mapping, Sequence

from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import Status

from .canary import encoded_forms

REDACTED = "[REDACTED]"

_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_\-]{19,}"),  # OpenAI / Anthropic style
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key ids
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),  # Google API keys
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),  # Slack
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),  # JWT
]
_KEEP_PREFIX = [  # keep the label, drop the value
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=\-]{16,}"),
    re.compile(r"(?i)([?&](?:key|api[_\-]?key|apikey|token|access_token|auth|sig|signature|secret|password)=)"
               r"[^&#\s'\"]+"),
]
_SECRET_ENV_NAME = re.compile(r"(?i)key|token|secret|passw(?:or)?d|credential|auth")
_MIN_SECRET_LEN = 8

_registered: set[str] = set()


def add_secret(value: str) -> None:
    """Scrub this exact value (and its encoded forms) from every wrapped exporter from now on."""
    if value and len(value) >= _MIN_SECRET_LEN:
        _registered.add(value)


class Scrubber:
    def __init__(self, secrets: Iterable[str] = (), env: bool = True, patterns: bool = True):
        self.secrets = {s for s in secrets if s and len(s) >= _MIN_SECRET_LEN}
        self.env = env
        self.patterns = patterns
        self._cache_key: frozenset[str] | None = None
        self._needles: list[str] = []

    def _known(self) -> list[str]:
        values = set(self.secrets) | _registered
        if self.env:
            values |= {v for k, v in os.environ.items()
                       if _SECRET_ENV_NAME.search(k) and len(v) >= _MIN_SECRET_LEN}
        key = frozenset(values)
        if key != self._cache_key:  # rebuild only when the set of secrets changed
            forms = set(values)
            for v in values:
                forms |= set(encoded_forms(v).values())
            self._needles = sorted(forms, key=len, reverse=True)  # longest first
            self._cache_key = key
        return self._needles

    def text(self, s: str) -> str:
        for needle in self._known():
            if needle in s:
                s = s.replace(needle, REDACTED)
        if self.patterns:
            for p in _PATTERNS:
                s = p.sub(REDACTED, s)
            for p in _KEEP_PREFIX:
                s = p.sub(lambda m: m.group(1) + REDACTED, s)
        return s

    def value(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, Mapping):
            return {self.text(str(k)): self.value(x) for k, x in v.items()}
        if isinstance(v, Sequence) and not isinstance(v, (bytes, bytearray)):
            return tuple(self.value(x) for x in v)
        return v

    def attrs(self, a):
        return None if a is None else self.value(dict(a))


class ScrubbingSpanExporter(SpanExporter):
    def __init__(self, inner: SpanExporter, scrubber: Scrubber):
        self.inner, self.s = inner, scrubber

    def _span(self, sp: ReadableSpan) -> ReadableSpan:
        s = self.s
        status = sp.status
        if status.description:
            status = Status(status.status_code, s.text(status.description))
        return ReadableSpan(
            name=s.text(sp.name), context=sp.context, parent=sp.parent, resource=sp.resource,
            attributes=s.attrs(sp.attributes),
            events=[Event(s.text(e.name), s.attrs(e.attributes), e.timestamp) for e in sp.events],
            links=sp.links, kind=sp.kind, status=status, start_time=sp.start_time,
            end_time=sp.end_time, instrumentation_scope=sp.instrumentation_scope,
        )

    def export(self, spans) -> SpanExportResult:
        return self.inner.export([self._span(sp) for sp in spans])

    def shutdown(self) -> None:
        self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.inner.force_flush(timeout_millis)


def _log_exporter_bases() -> tuple[type, ...]:
    # Private, renamed module: newer SDKs export via LogRecordExporter, older via LogExporter.
    import opentelemetry.sdk._logs.export as e

    return tuple(c for c in (getattr(e, "LogRecordExporter", None), getattr(e, "LogExporter", None)) if c)


class _ScrubbingLogExporterMixin:
    def __init__(self, inner, scrubber: Scrubber):
        self.inner, self.s = inner, scrubber

    def _record(self, item):
        lr = copy.copy(item.log_record)
        lr.body = self.s.value(lr.body)
        lr.attributes = self.s.attrs(lr.attributes)
        if dataclasses.is_dataclass(item):  # newer SDKs: a frozen ReadableLogRecord
            return dataclasses.replace(item, log_record=lr)
        item = copy.copy(item)  # older SDKs: a mutable LogData
        item.log_record = lr
        return item

    def export(self, batch):
        return self.inner.export([self._record(x) for x in batch])

    def shutdown(self):
        self.inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.inner.force_flush(timeout_millis)


def scrub(exporter, *, secrets: Iterable[str] = (), env: bool = True, patterns: bool = True):
    """Wrap a span or log exporter so secrets are removed before anything is exported."""
    scrubber = Scrubber(secrets, env, patterns)
    if isinstance(exporter, SpanExporter):
        return ScrubbingSpanExporter(exporter, scrubber)
    for base in _log_exporter_bases():
        if isinstance(exporter, base):
            cls = type("ScrubbingLogExporter", (_ScrubbingLogExporterMixin, base), {})
            return cls(exporter, scrubber)
    raise TypeError(f"scrub() wraps span or log exporters, not {type(exporter).__name__}")
