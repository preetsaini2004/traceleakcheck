"""Canary secrets in realistic formats, plus the encoded forms a leak may take."""

from __future__ import annotations

import base64
import secrets
import string
import urllib.parse
from dataclasses import dataclass, field

_ALNUM = string.ascii_letters + string.digits
_UPPER_ALNUM = string.ascii_uppercase + string.digits


def _rand(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# Realistic shapes so pattern-based redactors get a fair chance to catch them.
_GENERATORS = {
    "openai": lambda: "sk-proj-" + _rand(48),
    "anthropic": lambda: "sk-ant-api03-" + _rand(86),
    "aws": lambda: "AKIA" + _rand(16, _UPPER_ALNUM),
    "github": lambda: "ghp_" + _rand(36),
    "azure": lambda: secrets.token_hex(16),  # Azure OpenAI keys: 32 hex chars, no prefix
    "jwt": lambda: ".".join(
        [
            _b64url(b'{"alg":"HS256","typ":"JWT"}'),
            _b64url(('{"sub":"tlc-' + _rand(12) + '"}').encode()),
            _b64url(secrets.token_bytes(32)),
        ]
    ),
    "password": lambda: "tlc-pw-" + _rand(24),
}

KINDS = tuple(_GENERATORS)

# Leading chars of each kind that are fixed, not random. The truncation variant must include
# enough random chars beyond these to be unique.
_STATIC_LEN = {
    "openai": len("sk-proj-"),
    "anthropic": len("sk-ant-api03-"),
    "aws": len("AKIA"),
    "github": len("ghp_"),
    "azure": 0,
    "jwt": len(_b64url(b'{"alg":"HS256","typ":"JWT"}')) + 1 + len(_b64url(b'{"sub":"tlc-')),
    "password": len("tlc-pw-"),
}

# Shortest substring worth matching inside an encoding; shorter fragments risk false positives.
_MIN_FRAGMENT = 16


def _b64_fragments(raw: bytes) -> list[str]:
    """Base64 substrings that appear no matter where `raw` sits inside a larger encoded blob.

    Base64 packs 3 bytes into 4 chars, so the encoding of an embedded secret depends on its
    byte offset mod 3. For each offset, keep only the chars whose 6 bits come entirely from
    the secret.
    """
    out = []
    n = len(raw)
    for k in range(3):
        enc = base64.b64encode(b"\x00" * k + raw).decode()
        start = -(-8 * k // 6)  # ceil(8k/6): first char fully inside the secret
        end = (8 * (k + n)) // 6  # chars before this are fully inside the secret
        frag = enc[start:end]
        if len(frag) >= _MIN_FRAGMENT:
            out.append(frag)
    return out


@dataclass(frozen=True)
class Canary:
    kind: str
    value: str
    variants: dict[str, str] = field(compare=False, repr=False)


def make_canary(kind: str = "openai") -> Canary:
    if kind not in _GENERATORS:
        raise ValueError(f"unknown canary kind {kind!r}; choose from {KINDS}")
    value = _GENERATORS[kind]()
    variants: dict[str, str] = {"raw": value}
    # Instrumentations truncate long attributes (OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT); a cut-off
    # secret is still a leak.
    prefix = value[: _STATIC_LEN[kind] + _MIN_FRAGMENT]
    if len(prefix) < len(value):
        variants["truncated"] = prefix
    variants |= encoded_forms(value)
    return Canary(kind=kind, value=value, variants=variants)


def encoded_forms(value: str) -> dict[str, str]:
    """base64 (any offset), base64url, URL and hex forms of `value`. Keys name the encoding."""
    raw = value.encode()
    variants: dict[str, str] = {}
    for i, frag in enumerate(_b64_fragments(raw)):
        variants[f"base64[{i}]"] = frag
        urlsafe = frag.replace("+", "-").replace("/", "_")
        if urlsafe != frag:
            variants[f"base64url[{i}]"] = urlsafe
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        variants["url"] = quoted
    variants["hex"] = raw.hex()  # scanner matches this case-insensitively
    return variants
