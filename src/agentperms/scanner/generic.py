"""Generic MCP config parsing.

Most MCP clients store servers under a ``mcpServers`` (or ``servers``) object in
JSON. This module parses that shape from any file path so the client-specific
modules can stay thin.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentperms.models import DiscoveredConfig, MCPServerConfig


def parse_config_file(path: Path, client: str) -> DiscoveredConfig | None:
    """Parse a single JSON config file into a DiscoveredConfig, or None."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None

    servers_obj = _locate_servers(raw)
    if not servers_obj:
        return None

    servers: list[MCPServerConfig] = []
    for name, entry in servers_obj.items():
        if not isinstance(entry, dict):
            continue
        servers.append(
            MCPServerConfig(
                name=name,
                command=entry.get("command", "") or "",
                args=[str(a) for a in entry.get("args", []) or []],
                env={str(k): str(v) for k, v in (entry.get("env") or {}).items()},
                source=str(path),
            )
        )
    return DiscoveredConfig(client=client, path=str(path), servers=servers)


def _locate_servers(raw: dict) -> dict | None:
    """Find the server map under common keys (incl. VS Code's nested form)."""
    for key in ("mcpServers", "servers", "mcp"):
        val = raw.get(key)
        if isinstance(val, dict):
            # VS Code nests as {"mcp": {"servers": {...}}}
            if key == "mcp" and isinstance(val.get("servers"), dict):
                return val["servers"]
            if key != "mcp":
                return val
    return None


def discover_in_dir(directory: Path, client: str = "generic") -> list[DiscoveredConfig]:
    """Find MCP-shaped JSON configs anywhere under a directory."""
    found: list[DiscoveredConfig] = []
    if directory.is_file():
        cfg = parse_config_file(directory, client)
        return [cfg] if cfg else []
    for path in directory.rglob("*.json"):
        cfg = parse_config_file(path, client)
        if cfg and cfg.servers:
            found.append(cfg)
    return found
