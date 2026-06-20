"""Risk heuristics shared by the scanner and inference.

The category tables here are the single source of truth for "what counts as
dangerous". ``scanner`` uses them to raise findings on discovered configs and on
tool names; ``inference`` reuses the same tables to seed ``denied_tools`` and the
human-approval list in a generated policy.
"""

from __future__ import annotations

import fnmatch
import re

from agentperms.config import SECRET_PATH_PATTERNS, SENSITIVE_PATHS
from agentperms.models import MCPServerConfig, ScanFinding, Severity

# --------------------------------------------------------------------------- #
# Tool-name category tables (substring match, case-insensitive)
# --------------------------------------------------------------------------- #
# Tools that execute arbitrary code / shell.
SHELL_TOOLS = ["shell", "exec", "run_command", "bash", "subprocess", "eval", "system"]

# Filesystem mutation.
FS_WRITE_TOOLS = ["write", "delete", "rm", "remove", "move", "mkdir", "create_file", "edit_file"]

# Database writes.
DB_WRITE_TOOLS = ["execute_write", "insert", "update", "delete_row", "drop", "truncate", "execute_sql"]

# Outbound communication.
SEND_TOOLS = ["send_email", "send_message", "send_slack", "post_message", "gmail", "smtp"]

# Destructive VCS actions.
DESTRUCTIVE_GITHUB_TOOLS = [
    "delete_repo",
    "force_push",
    "write_secret",
    "delete_branch",
    "merge_pr",
    "delete_file",
]

# Map a category key -> (table, severity, human-readable reason).
DANGEROUS_CATEGORIES: dict[str, tuple[list[str], Severity, str]] = {
    "shell": (SHELL_TOOLS, Severity.HIGH, "arbitrary code/shell execution"),
    "fs_write": (FS_WRITE_TOOLS, Severity.MEDIUM, "filesystem mutation"),
    "db_write": (DB_WRITE_TOOLS, Severity.HIGH, "database write"),
    "send": (SEND_TOOLS, Severity.HIGH, "outbound communication (email/chat)"),
    "destructive_vcs": (DESTRUCTIVE_GITHUB_TOOLS, Severity.HIGH, "destructive VCS action"),
}

# Categories that should require human approval rather than be flatly denied.
APPROVAL_CATEGORIES = {"send", "db_write", "shell", "destructive_vcs"}


def categorize_tool(tool: str) -> str | None:
    """Return the dangerous-category key for a tool name, or None if benign."""
    low = tool.lower()
    for key, (table, _sev, _reason) in DANGEROUS_CATEGORIES.items():
        if any(token in low for token in table):
            return key
    return None


def is_dangerous_tool(tool: str) -> bool:
    return categorize_tool(tool) is not None


def is_sensitive_path(path: str) -> bool:
    """True if ``path`` touches a known-sensitive location or secret pattern."""
    norm = path.strip()
    expanded = norm.replace("~", "")
    for sp in SENSITIVE_PATHS:
        if sp.replace("~", "") in expanded:
            return True
    name = norm.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(norm, pat) for pat in SECRET_PATH_PATTERNS)


# --------------------------------------------------------------------------- #
# Config-level static checks
# --------------------------------------------------------------------------- #
_UNPINNED_NPX = re.compile(r"(?:^|\s)-y(?:\s|$)|@latest")
_VERSION_PIN = re.compile(r"@\d+\.\d+")


def scan_server_config(server: MCPServerConfig) -> list[ScanFinding]:
    """Static findings derivable from a server's launch command alone."""
    findings: list[ScanFinding] = []
    cmdline = " ".join([server.command, *server.args])
    low = cmdline.lower()

    # Unpinned npx packages (rug-pull / supply-chain risk).
    if "npx" in low and _UNPINNED_NPX.search(low) and not _VERSION_PIN.search(low):
        findings.append(
            ScanFinding(
                severity=Severity.MEDIUM,
                server=server.name,
                kind="unpinned_server",
                message=f"Server launched via unpinned npx ({cmdline!r}); pin a version to prevent rug-pulls.",
            )
        )

    # Shell/filesystem server packages.
    if any(tok in low for tok in ("server-filesystem", "filesystem")):
        for arg in server.args:
            if is_sensitive_path(arg):
                findings.append(
                    ScanFinding(
                        severity=Severity.HIGH,
                        server=server.name,
                        kind="sensitive_path_exposure",
                        message=f"Filesystem server mounts sensitive path {arg!r}.",
                    )
                )

    # Secrets passed in plaintext env.
    for env_key, env_val in server.env.items():
        if any(t in env_key.lower() for t in ("token", "key", "secret", "password")) and env_val:
            findings.append(
                ScanFinding(
                    severity=Severity.MEDIUM,
                    server=server.name,
                    kind="secret_in_config",
                    message=f"Secret-like env var {env_key!r} stored in plaintext in client config.",
                )
            )
    return findings


def scan_tool_name(server: str, tool: str, description: str = "") -> list[ScanFinding]:
    """Findings for a single discovered tool name/description."""
    findings: list[ScanFinding] = []
    key = categorize_tool(tool)
    if key:
        _table, sev, reason = DANGEROUS_CATEGORIES[key]
        findings.append(
            ScanFinding(
                severity=sev,
                server=server,
                kind=f"dangerous_tool:{key}",
                message=f"Tool {tool!r} enables {reason}.",
            )
        )
    # Description-based exposure hints.
    for sp in SENSITIVE_PATHS:
        if sp.replace("~", "") in description:
            findings.append(
                ScanFinding(
                    severity=Severity.HIGH,
                    server=server,
                    kind="sensitive_path_exposure",
                    message=f"Tool {tool!r} description references sensitive path {sp!r}.",
                )
            )
            break
    return findings
