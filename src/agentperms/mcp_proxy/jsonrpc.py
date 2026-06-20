"""Newline-delimited JSON-RPC 2.0 helpers for the MCP stdio transport.

MCP over stdio exchanges one JSON object per line. These helpers parse/classify
messages and build the synthetic error responses the proxy returns when a call
is denied (so the client gets a clean error instead of a dropped request).
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO

# JSON-RPC error code used for policy denials (server-defined range).
ERR_POLICY_DENIED = -32001


def parse(line: bytes | str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def is_tools_call(msg: dict[str, Any]) -> bool:
    return msg.get("method") == "tools/call"


def is_tools_list_result(msg: dict[str, Any]) -> bool:
    result = msg.get("result")
    return isinstance(result, dict) and "tools" in result


def tool_call_params(msg: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract (tool_name, arguments) from a tools/call request."""
    params = msg.get("params") or {}
    return params.get("name", ""), (params.get("arguments") or {})


def error_response(request_id: Any, message: str, code: int = ERR_POLICY_DENIED) -> dict[str, Any]:
    """Build a JSON-RPC error reply for a given request id."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def write_message(stream: BinaryIO, msg: dict[str, Any]) -> None:
    stream.write((json.dumps(msg) + "\n").encode())
    stream.flush()
