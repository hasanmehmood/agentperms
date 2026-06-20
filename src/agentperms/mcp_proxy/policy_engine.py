"""The single decision authority over a tool call.

Both live enforcement (``stdio_proxy`` in enforce mode) and offline ``replay``
call ``evaluate`` — there is exactly one copy of the allow/deny/approve logic.

Decision order (first match wins):
  1. approvals.require_human_approval (``server.tool``)  -> REQUIRE_APPROVAL
  2. explicit denied_tools                               -> DENY
  3. path arguments hitting denied_paths/denied_patterns -> DENY
  4. allowed_tools present and tool not in it            -> DENY  (default-deny)
  5. path arguments outside allowed_paths                -> DENY
  6. otherwise                                           -> ALLOW
"""

from __future__ import annotations

import fnmatch
import os
from typing import Any

from agentperms.models import Decision, Policy, ServerPolicy

# Argument keys that commonly carry filesystem paths.
PATH_KEYS = ("path", "file", "filename", "filepath", "dir", "directory", "repo_path")


def _expand(p: str) -> str:
    return os.path.expanduser(os.path.expandvars(p))


def _extract_paths(args: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key, val in args.items():
        if isinstance(val, str) and (key.lower() in PATH_KEYS or "path" in key.lower()):
            paths.append(val)
    return paths


def _path_matches(path: str, patterns: list[str]) -> bool:
    """True if ``path`` is under any allowed/denied entry (prefix or glob)."""
    ep = _expand(path)
    for pat in patterns:
        epat = _expand(pat)
        # glob (e.g. *.pem) or directory-prefix containment
        if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(os.path.basename(ep), pat):
            return True
        try:
            common = os.path.commonpath([os.path.abspath(ep), os.path.abspath(epat)])
            if common == os.path.abspath(epat):
                return True
        except ValueError:
            continue
    return False


class PolicyEngine:
    """Convenience wrapper holding a Policy for repeated evaluation."""

    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, server: str, tool: str, args: dict[str, Any]) -> tuple[Decision, str]:
        return evaluate(self.policy, server, tool, args)


def evaluate(policy: Policy, server: str, tool: str, args: dict[str, Any]) -> tuple[Decision, str]:
    """Return (decision, reason) for a single tool call."""
    fqn = f"{server}.{tool}"

    # 1. Human approval list.
    if fqn in policy.approvals.require_human_approval or tool in policy.approvals.require_human_approval:
        return Decision.REQUIRE_APPROVAL, f"{fqn} requires human approval"

    sp: ServerPolicy | None = policy.servers.get(server)
    if sp is None:
        # Unknown server: if any servers are constrained, default-deny; else allow.
        if policy.servers:
            return Decision.DENY, f"server {server!r} not in policy (default-deny)"
        return Decision.ALLOW, "no policy constraints"

    # 2. Explicit tool denial.
    if tool in sp.denied_tools:
        return Decision.DENY, f"tool {tool!r} is explicitly denied"

    paths = _extract_paths(args)

    # 3. Denied paths / patterns.
    for p in paths:
        if _path_matches(p, sp.denied_paths) or _path_matches(p, sp.denied_patterns):
            return Decision.DENY, f"path {p!r} matches a denied path/pattern"

    # 4. Default-deny on the tool allowlist.
    if sp.allowed_tools and tool not in sp.allowed_tools:
        return Decision.DENY, f"tool {tool!r} not in allowed_tools"

    # 5. Path allowlist.
    if sp.allowed_paths and paths:
        for p in paths:
            if not _path_matches(p, sp.allowed_paths):
                return Decision.DENY, f"path {p!r} outside allowed_paths"

    return Decision.ALLOW, "allowed by policy"
