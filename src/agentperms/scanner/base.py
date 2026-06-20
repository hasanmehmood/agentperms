"""Top-level discovery + scan orchestration."""

from __future__ import annotations

from pathlib import Path

from agentperms.config import CLIENT_CONFIG_PATHS
from agentperms.models import DiscoveredConfig, ScanFinding
from agentperms.scanner import generic, rules


def discover_client(client: str) -> list[DiscoveredConfig]:
    """Discover configs for a single known client by its well-known paths."""
    out: list[DiscoveredConfig] = []
    for path in CLIENT_CONFIG_PATHS.get(client, []):
        if path.exists():
            cfg = generic.parse_config_file(path, client)
            if cfg and cfg.servers:
                out.append(cfg)
    return out


def discover_all(path: str | None = None) -> list[DiscoveredConfig]:
    """Discover across all known clients, or scope to an explicit path."""
    if path:
        return generic.discover_in_dir(Path(path).expanduser(), "generic")
    out: list[DiscoveredConfig] = []
    for client in CLIENT_CONFIG_PATHS:
        out.extend(discover_client(client))
    return out


def scan_configs(configs: list[DiscoveredConfig]) -> list[ScanFinding]:
    """Run static rules over discovered server configs."""
    findings: list[ScanFinding] = []
    for cfg in configs:
        for server in cfg.servers:
            findings.extend(rules.scan_server_config(server))
    return findings
