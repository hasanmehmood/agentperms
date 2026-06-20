"""Minimal MCP stdio client: enough handshake to enumerate tools.

Used by ``agentperms lock`` and ``agentperms scan`` to ask a server what tools
it exposes (``initialize`` -> ``notifications/initialized`` -> ``tools/list``).
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "agentperms", "version": "0.1.0"},
    },
}
_INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def query_tools(command: list[str], timeout: float = 10.0) -> list[dict[str, Any]]:
    """Spawn an MCP server and return its advertised tools (best-effort)."""
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdin and proc.stdout
    try:
        for msg in (_INIT, _INITIALIZED, _LIST):
            proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

        # Read until we see the tools/list response (id == 2).
        deadline_lines = 200
        for _ in range(deadline_lines):
            line = proc.stdout.readline()
            if not line:
                break
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == 2 and isinstance(obj.get("result"), dict):
                return obj["result"].get("tools", [])
        return []
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
