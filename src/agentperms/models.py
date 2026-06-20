"""Pydantic data models shared across AgentPerms.

These are the contracts every subsystem speaks: the scanner emits ``ScanFinding``s,
the recorder writes ``TraceEvent``s, inference produces a ``Policy``, and the
lockfile is a list of ``ManifestEntry``s wrapped in a ``Lockfile``.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

import yaml
from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
class ServerPolicy(BaseModel):
    """Per-server permission grants."""

    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    denied_patterns: list[str] = Field(default_factory=list)


class Redaction(BaseModel):
    secrets: bool = True
    emails: bool = True
    api_keys: bool = True


class Approvals(BaseModel):
    require_human_approval: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    """The generated ``mcp.policy.yaml`` document."""

    version: int = 1
    servers: dict[str, ServerPolicy] = Field(default_factory=dict)
    approvals: Approvals = Field(default_factory=Approvals)
    redaction: Redaction = Field(default_factory=Redaction)

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            self.model_dump(mode="json"), sort_keys=False, default_flow_style=False
        )

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        return cls.model_validate(yaml.safe_load(text) or {})


# --------------------------------------------------------------------------- #
# Traces
# --------------------------------------------------------------------------- #
class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    RECORD = "record"  # record-only mode, no policy applied


class TraceEvent(BaseModel):
    """A single recorded MCP ``tools/call``."""

    ts: float = Field(default_factory=time.time)
    server: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""
    decision: Decision = Decision.RECORD


# --------------------------------------------------------------------------- #
# Lockfile
# --------------------------------------------------------------------------- #
class ManifestEntry(BaseModel):
    server: str
    command_hash: str
    tool: str
    description_hash: str
    schema_hash: str


class Lockfile(BaseModel):
    version: int = 1
    entries: list[ManifestEntry] = Field(default_factory=list)

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            self.model_dump(mode="json"), sort_keys=False, default_flow_style=False
        )

    @classmethod
    def from_yaml(cls, text: str) -> "Lockfile":
        return cls.model_validate(yaml.safe_load(text) or {})


# --------------------------------------------------------------------------- #
# Scan findings
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanFinding(BaseModel):
    severity: Severity
    server: str
    kind: str
    message: str


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
class MCPServerConfig(BaseModel):
    """A single MCP server entry discovered in a client config."""

    name: str
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    source: str = ""  # which client/file it came from


class DiscoveredConfig(BaseModel):
    client: str
    path: str
    servers: list[MCPServerConfig] = Field(default_factory=list)
