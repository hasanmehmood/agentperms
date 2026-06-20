"""Turn observed traces into the minimum policy that would have allowed them.

For each server we collect the distinct tools actually used (-> allowed_tools)
and the directory prefixes of any path arguments (-> allowed_paths, minimized to
a covering set). Known-dangerous categories that were *not* observed are written
into denied_tools / denied_patterns so the policy is explicit about what stays
off; risky categories that *were* observed are routed to human approval rather
than silently allowed.
"""

from __future__ import annotations

import os

from agentperms.config import SECRET_PATH_PATTERNS
from agentperms.models import Approvals, Policy, Redaction, ServerPolicy, TraceEvent
from agentperms.mcp_proxy.policy_engine import PATH_KEYS
from agentperms.models import Severity
from agentperms.scanner.rules import (
    APPROVAL_CATEGORIES,
    DANGEROUS_CATEGORIES,
    categorize_tool,
)


def _paths_in(event: TraceEvent) -> list[str]:
    out = []
    for key, val in event.args.items():
        if isinstance(val, str) and (key.lower() in PATH_KEYS or "path" in key.lower()):
            out.append(val)
    return out


def _minimal_dirs(paths: list[str]) -> list[str]:
    """Reduce observed file paths to a minimal covering set of directories."""
    dirs = set()
    for p in paths:
        d = p if (p.endswith("/") or "." not in os.path.basename(p)) else os.path.dirname(p)
        dirs.add(d.rstrip("/") or "/")
    # Drop any dir that is contained within another kept dir.
    minimal: list[str] = []
    for d in sorted(dirs, key=len):
        if not any(d != m and d.startswith(m.rstrip("/") + "/") for m in dirs):
            minimal.append(d)
    return sorted(set(minimal))


def infer_policy(events: list[TraceEvent], redaction: Redaction | None = None) -> Policy:
    by_server: dict[str, list[TraceEvent]] = {}
    for ev in events:
        by_server.setdefault(ev.server, []).append(ev)

    servers: dict[str, ServerPolicy] = {}
    approvals: list[str] = []

    for server, evs in by_server.items():
        used_tools = sorted({e.tool for e in evs})
        observed_paths = [p for e in evs for p in _paths_in(e)]
        allowed_paths = _minimal_dirs(observed_paths)

        # Approval for risky tools that were genuinely used.
        for tool in used_tools:
            cat = categorize_tool(tool)
            if cat in APPROVAL_CATEGORIES:
                approvals.append(f"{server}.{tool}")

        # Explicitly deny HIGH-severity dangerous tools that were never used,
        # so the policy documents what intentionally stays off.
        used_lower = {t.lower() for t in used_tools}
        denied_tools = sorted(
            {
                token
                for (table, sev, _reason) in DANGEROUS_CATEGORIES.values()
                if sev == Severity.HIGH
                for token in table
                if not any(token in t for t in used_lower)
            }
        )

        servers[server] = ServerPolicy(
            allowed_tools=used_tools,
            denied_tools=denied_tools,
            allowed_paths=allowed_paths,
            denied_patterns=list(SECRET_PATH_PATTERNS) if allowed_paths else [],
        )

    return Policy(
        servers=servers,
        approvals=Approvals(require_human_approval=sorted(set(approvals))),
        redaction=redaction or Redaction(),
    )
