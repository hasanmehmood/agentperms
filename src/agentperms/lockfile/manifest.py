"""Build and diff the tool manifest lockfile.

A lockfile pins the *identity* of every tool: a hash of its name, description,
and input schema, plus a hash of the server's launch command. If a server later
silently changes a tool's description or schema (a classic tool-poisoning /
rug-pull), ``diff_lockfiles`` surfaces it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentperms.models import DiscoveredConfig, Lockfile, ManifestEntry
from agentperms.mcp_proxy.client import query_tools


def _hash(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def entries_for_server(server: str, command: list[str], tools: list[dict[str, Any]]) -> list[ManifestEntry]:
    chash = _hash(command)
    out: list[ManifestEntry] = []
    for tool in tools:
        out.append(
            ManifestEntry(
                server=server,
                command_hash=chash,
                tool=tool.get("name", ""),
                description_hash=_hash(tool.get("description", "")),
                schema_hash=_hash(tool.get("inputSchema", {})),
            )
        )
    return out


def build_lockfile(configs: list[DiscoveredConfig]) -> Lockfile:
    """Enumerate tools from every discovered server and build a lockfile."""
    entries: list[ManifestEntry] = []
    for cfg in configs:
        for server in cfg.servers:
            if not server.command:
                continue
            command = [server.command, *server.args]
            try:
                tools = query_tools(command)
            except Exception:  # noqa: BLE001 - a flaky server should not abort the lock
                tools = []
            entries.extend(entries_for_server(server.name, command, tools))
    return Lockfile(entries=entries)


def diff_lockfiles(old: Lockfile, new: Lockfile) -> list[str]:
    """Return human-readable warnings for changes from ``old`` to ``new``."""
    warnings: list[str] = []
    old_index = {(e.server, e.tool): e for e in old.entries}
    new_index = {(e.server, e.tool): e for e in new.entries}

    for key, ne in new_index.items():
        server, tool = key
        oe = old_index.get(key)
        if oe is None:
            warnings.append(f"NEW: {server}.{tool} appeared since last trust. Review before allowing.")
            continue
        if oe.description_hash != ne.description_hash:
            warnings.append(
                f"WARNING: {server}.{tool} description changed since last trust. "
                "Possible tool poisoning / rug pull."
            )
        if oe.schema_hash != ne.schema_hash:
            warnings.append(
                f"WARNING: {server}.{tool} input schema changed since last trust. "
                "Possible tool poisoning / rug pull."
            )
        if oe.command_hash != ne.command_hash:
            warnings.append(f"WARNING: {server} launch command changed since last trust.")

    for key in old_index:
        if key not in new_index:
            warnings.append(f"REMOVED: {key[0]}.{key[1]} is gone since last trust.")
    return warnings
