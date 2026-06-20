"""Well-known locations and shared constants.

Client config locations are best-effort across platforms; ``generic`` scanning
covers anything not enumerated here via an explicit ``--path``.
"""

from __future__ import annotations

import sys
from pathlib import Path

HOME = Path.home()

# Output artifacts (relative to the current working directory).
POLICY_FILE = "mcp.policy.yaml"
LOCK_FILE = "mcp.lock"
REPORT_FILE = "agentperms-report.html"
TRACE_DIR = "traces"
DB_FILE = ".agentperms/traces.db"
WORKFLOW_FILE = ".github/workflows/agentperms.yml"


def _claude_desktop_config() -> Path:
    if sys.platform == "darwin":
        return HOME / "Library/Application Support/Claude/claude_desktop_config.json"
    if sys.platform.startswith("win"):
        return Path(_appdata()) / "Claude/claude_desktop_config.json"
    return HOME / ".config/Claude/claude_desktop_config.json"


def _appdata() -> str:
    import os

    return os.environ.get("APPDATA", str(HOME / "AppData/Roaming"))


# client name -> list of candidate config paths
CLIENT_CONFIG_PATHS: dict[str, list[Path]] = {
    "claude": [_claude_desktop_config()],
    "cursor": [HOME / ".cursor/mcp.json", Path.cwd() / ".cursor/mcp.json"],
    "vscode": [
        HOME / ".vscode/mcp.json",
        Path.cwd() / ".vscode/mcp.json",
        Path.cwd() / ".vscode/settings.json",
    ],
    "windsurf": [HOME / ".codeium/windsurf/mcp_config.json"],
    "gemini": [HOME / ".gemini/settings.json", Path.cwd() / ".gemini/settings.json"],
}

# Sensitive paths that should essentially never be reachable by an agent.
SENSITIVE_PATHS = [
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.env",
    ".env",
    "/etc",
    "/etc/passwd",
    "~/.gnupg",
]

# Filename patterns that almost always indicate secret material.
SECRET_PATH_PATTERNS = ["*.pem", "*.key", "*.p12", "id_rsa", "id_ed25519", "*.env"]
