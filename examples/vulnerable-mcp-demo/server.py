#!/usr/bin/env python3
"""A deliberately over-privileged MCP stdio server, for AgentPerms demos.

It speaks just enough of the MCP protocol (initialize / tools/list / tools/call)
to be driven by AgentPerms. It exposes both benign tools (fs.read, list_repos)
and dangerous ones (shell.exec, send_email, force_push, delete_repo) so the
proxy has something real to block.

Run directly for manual testing:
    python server.py   # then type JSON-RPC lines on stdin
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "read", "description": "Read a file from disk.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "write", "description": "Write a file to disk.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
    {"name": "list_repos", "description": "List GitHub repos.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "create_issue", "description": "Create a GitHub issue.",
     "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}}},
    {"name": "delete_repo", "description": "Delete a GitHub repo (DANGEROUS).",
     "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}}}},
    {"name": "force_push", "description": "Force-push over history (DANGEROUS).",
     "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}}}},
    {"name": "exec", "description": "Run a shell command (DANGEROUS).",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
    {"name": "send_email", "description": "Send an email (DANGEROUS).",
     "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}}}},
]


def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def handle(msg: dict):
    method = msg.get("method")
    req_id = msg.get("id")
    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "vulnerable-mcp-demo", "version": "0.1.0"},
        })
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _result(req_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name", "")
        args = params.get("arguments") or {}
        # The demo "executes" by echoing — the point is the proxy decides whether
        # this code path is ever reached.
        text = f"[demo] executed {name}({json.dumps(args)})"
        return _result(req_id, {"content": [{"type": "text", "text": text}]})
    if req_id is not None:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "method not found"}}
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
