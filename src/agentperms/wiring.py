"""Rewrite MCP client configs to route servers through the AgentPerms proxy.

``record``/``enforce`` rewrite each server's launch command to:

    agentperms _proxy --mode <mode> [--policy ...] --server <name> -- <orig cmd...>

A timestamped backup is written next to the config so ``--stop`` can restore the
original. We never edit a config we did not back up.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from agentperms.scanner import generic

BACKUP_SUFFIX = ".agentperms.bak"


def _proxy_command(mode: str, server_name: str, orig_cmd: str, orig_args: list[str], policy: str | None) -> dict:
    args = ["-m", "agentperms", "_proxy", "--mode", mode, "--server", server_name]
    if policy:
        args += ["--policy", policy]
    args += ["--", orig_cmd, *orig_args]
    return {"command": sys.executable, "args": args}


def rewrite_config(path: Path, mode: str, policy: str | None = None) -> int:
    """Rewrite every server in a config to go through the proxy. Returns count."""
    raw = json.loads(path.read_text())
    servers = _servers_obj(raw)
    if not servers:
        return 0

    backup = path.with_suffix(path.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(path, backup)

    count = 0
    for name, entry in servers.items():
        if not isinstance(entry, dict) or not entry.get("command"):
            continue
        if entry.get("command") == sys.executable and "_proxy" in entry.get("args", []):
            continue  # already wrapped
        proxied = _proxy_command(mode, name, entry["command"], entry.get("args", []) or [], policy)
        entry["command"], entry["args"] = proxied["command"], proxied["args"]
        count += 1

    path.write_text(json.dumps(raw, indent=2))
    return count


def restore_config(path: Path) -> bool:
    """Restore a config from its AgentPerms backup. Returns True if restored."""
    backup = path.with_suffix(path.suffix + BACKUP_SUFFIX)
    if not backup.exists():
        return False
    shutil.copy2(backup, path)
    backup.unlink()
    return True


def _servers_obj(raw: dict) -> dict | None:
    # Mirror the discovery shapes, returning the mutable dict in place.
    for key in ("mcpServers", "servers"):
        if isinstance(raw.get(key), dict):
            return raw[key]
    if isinstance(raw.get("mcp"), dict) and isinstance(raw["mcp"].get("servers"), dict):
        return raw["mcp"]["servers"]
    return None


# Re-export for symmetry with the scanner's parser.
parse_config_file = generic.parse_config_file
