"""Secret redaction applied before any trace is persisted.

Used by the recorder (scrub args/results on the way to disk) and by the report
(never echo a captured secret into HTML). Conservative regexes: it is better to
over-redact a trace than to leak a key into ``traces/*.jsonl``.
"""

from __future__ import annotations

import re
from typing import Any

from agentperms.models import Redaction

REDACTED = "‹redacted›"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Common API-key shapes: sk-..., ghp_..., AKIA..., long hex/base64 blobs, bearer tokens.
_API_KEY = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9]{16,}"
    r"|ghp_[A-Za-z0-9]{20,}"
    r"|gho_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
    r")\b"
)
_BEARER = re.compile(r"(?i)\b(bearer|token|api[_-]?key|password|secret)\b(?:\s*[=:]\s*|\s+)\S+")
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.DOTALL)


def redact_text(text: str, cfg: Redaction | None = None) -> str:
    cfg = cfg or Redaction()
    out = _PEM_BLOCK.sub(REDACTED, text)
    if cfg.api_keys:
        out = _API_KEY.sub(REDACTED, out)
        out = _BEARER.sub(lambda m: f"{m.group(1)}={REDACTED}", out)
    if cfg.emails:
        out = _EMAIL.sub(REDACTED, out)
    return out


def redact(value: Any, cfg: Redaction | None = None) -> Any:
    """Recursively redact strings inside arbitrary JSON-able data."""
    cfg = cfg or Redaction()
    if isinstance(value, str):
        return redact_text(value, cfg)
    if isinstance(value, dict):
        return {k: redact(v, cfg) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, cfg) for v in value]
    return value


def redact_event(args: dict[str, Any], cfg: Redaction | None = None) -> dict[str, Any]:
    """Redact a tool-call argument dict."""
    return redact(args, cfg)
