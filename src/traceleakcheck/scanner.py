"""Find canary secrets anywhere inside decoded OTLP payloads."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .canary import Canary

# Payload key holding the raw request body (latin-1 str). Scanned only as a fallback,
# for canaries hidden in fields the protobuf decoder drops.
RAW_KEY = "\x00raw"
RAW_PATH = "<raw body: field not decoded>"


@dataclass(frozen=True)
class Finding:
    canary_kind: str
    variant: str  # "raw", "base64[1]", "url", ...
    signal: str  # "traces" | "logs" | "metrics"
    span: str | None  # name of the enclosing span, if any
    path: str  # e.g. resourceSpans[0].scopeSpans[0].spans[0].attributes[gen_ai.prompt]; "#key" = in a key


def _is_kv_list(items: list) -> bool:
    return bool(items) and all(isinstance(i, dict) and "key" in i for i in items)


def _walk(node, path: str, span: str | None):
    """Yield (path, span_name, string) for every string leaf and every key."""
    if isinstance(node, dict):
        if "spanId" in node and isinstance(node.get("name"), str):
            span = node["name"]
        for k, v in node.items():
            if k == RAW_KEY:
                continue
            p = f"{path}.{k}" if path else k
            yield f"{p}#key", span, k
            yield from _walk(v, p, span)
    elif isinstance(node, list):
        # OTLP attributes are [{key, value}]; label them by key so findings are readable.
        if _is_kv_list(node):
            for item in node:
                key = str(item["key"])
                yield f"{path}[{key}]#key", span, key
                yield from _walk(item.get("value"), f"{path}[{key}]", span)
        else:
            for i, v in enumerate(node):
                yield from _walk(v, f"{path}[{i}]", span)
    elif isinstance(node, str):
        yield path, span, node


def _match(text: str, c: Canary) -> str | None:
    """Name of the first variant of `c` found in `text` (variants are ordered raw-first)."""
    lower = None
    for name, needle in c.variants.items():
        if name == "hex":  # hex leaks in any letter case
            lower = text.lower() if lower is None else lower
            if needle in lower:
                return name
        elif needle in text:
            return name
    return None


def _mask(text: str, c: Canary) -> str:
    """Hide the canary in a path; a canary leaked as an attribute key would otherwise print in reports."""
    for needle in c.variants.values():
        text = text.replace(needle, f"<{c.kind} canary>")
    return text


def scan(payloads: Iterable[tuple[str, dict]], canaries: Iterable[Canary]) -> list[Finding]:
    canaries = list(canaries)
    findings: list[Finding] = []
    for signal, data in payloads:
        found: set[str] = set()
        for path, span, text in _walk(data, "", None):
            for c in canaries:
                if (variant := _match(text, c)) is not None:
                    findings.append(Finding(c.kind, variant, signal, span and _mask(span, c), _mask(path, c)))
                    found.add(c.value)
        raw = data.get(RAW_KEY)
        if raw:
            for c in canaries:
                if c.value not in found and (variant := _match(raw, c)) is not None:
                    findings.append(Finding(c.kind, variant, signal, None, RAW_PATH))
    return findings
