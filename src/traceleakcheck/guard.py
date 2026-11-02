"""Safety filter: scrub secrets out of telemetry before it leaves the app.

Wrap the exporter you already use, in your app (not just in tests):

    from traceleakcheck.guard import scrub
    tracer_provider.add_span_processor(BatchSpanProcessor(scrub(OTLPSpanExporter())))
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(scrub(OTLPLogExporter())))

What gets removed, everywhere in a span (name, attributes, event attributes such as
exception.message / exception.stacktrace, status message, link attributes, resource attributes)
and in log records (body, attributes, resource attributes):
  1. Known secrets: values of environment variables whose name contains KEY, TOKEN, SECRET,
     PASSWORD, CREDENTIAL or AUTH, plus anything passed to add_secret() or scrub(secrets=...),
     including their base64 / URL / hex forms. Env values that are plainly not secrets (file
     paths, URLs without a password, and, for KEY / TOKEN / CREDENTIAL / AUTH names, plain
     words, slugs and numbers such as "production" or "us-east-1") are left alone, so they
     aren't scrubbed out of every trace. Register anything else with add_secret().
  2. Well-known key formats (OpenAI, Anthropic, AWS, GitHub, Google, Slack, JWT, Bearer) and
     credential query parameters such as ?key=... or ?X-Amz-Signature=... in URLs.

It cannot know about secrets that match neither, so keep running `pytest --traceleak`: the filter
is the fix, traceleakcheck is the proof. Metrics are not filtered.
"""

from __future__ import annotations

import copy
import dataclasses
import os
import re
from collections.abc import Iterable, Mapping, Sequence

from opentelemetry.attributes import BoundedAttributes
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.util import BoundedList
from opentelemetry.trace import Link, Status

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
    # Includes every key the OTel semantic conventions say SHOULD be redacted from url.query.
    re.compile(r"(?i)([?&](?:key|api[_\-]?key|apikey|token|access_token|auth|sig|signature|secret|password"
               r"|awsaccesskeyid|x-amz-signature|x-amz-credential|x-amz-security-token"
               r"|x-goog-signature|x-goog-credential)=)"
               r"[^&#\s'\"]+"),
]
_SECRET_ENV_NAME = re.compile(r"(?i)key|token|secret|passw(?:or)?d|credential|auth")
_UNAMBIGUOUS_ENV_NAME = re.compile(r"(?i)secret|passw(?:or)?d")  # e.g. not KEYBOARD, SSH_AUTH_SOCK
_MIN_SECRET_LEN = 8

# Plain words, slugs and numbers: "production", "us-east-1", "PROD_EU", "My-Service", "30000000".
_WORD = r"(?:[A-Za-z][a-z]*|[A-Z]+|[0-9]+)"
_PLAIN_VALUE = re.compile(rf"{_WORD}(?:[-_.]{_WORD})*")
# A path needs at least one folder (/run/secrets/db, ~/.ssh/key, ./certs/x, C:\keys\a, \\host\share),
# so a password that merely starts with "/", "~" or "." is still treated as a secret.
_PATH_VALUE = re.compile(r"(?:~|\.{1,2})?/[^/]+/|[A-Za-z]:[\\/][^\\/]+[\\/]|\\\\[^\\]+\\")


def _env_secret(name: str, value: str) -> bool:
    """Whether a secret-named env var's value should be scrubbed from telemetry."""
    if len(value) < _MIN_SECRET_LEN:
        return False
    if _PATH_VALUE.match(value):  # SSH_AUTH_SOCK=/run/..., PASSWORD_FILE=/run/secrets/db
        return False
    if "://" in value:  # AUTH_URL=https://... is not a secret; redis://:pw@host is
        return "@" in value
    if _UNAMBIGUOUS_ENV_NAME.search(name):  # a passphrase may contain spaces
        return True
    return not any(ch.isspace() for ch in value) and not _PLAIN_VALUE.fullmatch(value)


# The SDK reports how many attributes, events and links it dropped (the OTLP dropped_*_count
# fields) by reading .dropped on its bounded containers. Rebuilding them as a plain dict or list
# would reset those counts to 0 and hide data loss from the backend, so carry them over.
def _keep_dropped_attrs(clean, dropped: int):
    if not dropped or clean is None:
        return clean
    bounded = BoundedAttributes(attributes=clean, immutable=True)
    bounded.dropped = dropped
    return bounded


def _keep_dropped_items(clean: list, dropped: int):
    if not dropped:
        return clean
    bounded = BoundedList.from_seq(None, clean)
    bounded.dropped = dropped
    return bounded


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
        self._resources: dict[int, tuple[Resource, Resource]] = {}

    def refresh(self) -> None:
        """Re-read the environment and registered secrets.

        Exporters call this once per batch, so a secret set or registered while the app runs is
        picked up by the next export without scanning the environment for every string.
        """
        values = set(self.secrets) | _registered
        if self.env:
            values |= {v for k, v in os.environ.items() if _SECRET_ENV_NAME.search(k) and _env_secret(k, v)}
        key = frozenset(values)
        if key != self._cache_key:  # rebuild only when the set of secrets changed
            forms = set(values)
            for v in values:
                forms |= set(encoded_forms(v).values())
            self._needles = sorted(forms, key=len, reverse=True)  # longest first
            self._cache_key = key
            self._resources.clear()

    def text(self, s: str) -> str:
        if self._cache_key is None:
            self.refresh()
        for needle in self._needles:
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

    def attrs(self, a, dropped: int = 0):
        return None if a is None else _keep_dropped_attrs(self.value(dict(a)), dropped)

    def resource(self, r: Resource | None) -> Resource | None:
        """Scrubbed copy of a resource, cached because every span and log shares the same one."""
        if r is None:
            return None
        hit = self._resources.get(id(r))
        if hit is not None and hit[0] is r:
            return hit[1]
        clean = Resource(self.attrs(r.attributes), r.schema_url)
        if len(self._resources) > 64:
            self._resources.clear()
        self._resources[id(r)] = (r, clean)  # keep r alive so its id can't be reused
        return clean


class ScrubbingSpanExporter(SpanExporter):
    def __init__(self, inner: SpanExporter, scrubber: Scrubber):
        self.inner, self.s = inner, scrubber

    def _span(self, sp: ReadableSpan) -> ReadableSpan:
        s = self.s
        status = sp.status
        if status.description:
            status = Status(status.status_code, s.text(status.description))
        return ReadableSpan(
            name=s.text(sp.name), context=sp.context, parent=sp.parent, resource=s.resource(sp.resource),
            attributes=s.attrs(sp.attributes, sp.dropped_attributes),
            events=_keep_dropped_items([
                Event(s.text(e.name), s.attrs(e.attributes, e.dropped_attributes), e.timestamp)
                for e in sp.events], sp.dropped_events),
            links=_keep_dropped_items([
                Link(lk.context, s.attrs(lk.attributes, lk.dropped_attributes))
                for lk in sp.links], sp.dropped_links),
            kind=sp.kind, status=status, start_time=sp.start_time,
            end_time=sp.end_time, instrumentation_scope=sp.instrumentation_scope,
        )

    def export(self, spans) -> SpanExportResult:
        self.s.refresh()
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
        # Newer SDKs count drops on the ReadableLogRecord, older ones on the record itself.
        dropped = getattr(item, "dropped_attributes", None)
        if dropped is None:
            dropped = getattr(item.log_record, "dropped_attributes", 0)
        lr = copy.copy(item.log_record)
        lr.body = self.s.value(lr.body)
        lr.attributes = self.s.attrs(lr.attributes, dropped or 0)
        if isinstance(getattr(lr, "resource", None), Resource):  # older SDKs keep it on the record
            lr.resource = self.s.resource(lr.resource)
        if dataclasses.is_dataclass(item):  # newer SDKs: a frozen ReadableLogRecord
            changes = {"log_record": lr}
            if isinstance(getattr(item, "resource", None), Resource):
                changes["resource"] = self.s.resource(item.resource)
            return dataclasses.replace(item, **changes)
        item = copy.copy(item)  # older SDKs: a mutable LogData
        item.log_record = lr
        return item

    def export(self, batch):
        self.s.refresh()
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
