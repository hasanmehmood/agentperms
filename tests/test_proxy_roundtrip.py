"""Integration test: drive the demo server through the stdio proxy in-process."""

import io
import json
from pathlib import Path

from agentperms.mcp_proxy.stdio_proxy import StdioProxy
from agentperms.models import Decision, Policy, ServerPolicy
from agentperms.recorder.trace_store import TraceStore

DEMO = str(Path(__file__).parent.parent / "examples" / "vulnerable-mcp-demo" / "server.py")


def _drive(proxy: StdioProxy, lines: list[dict]) -> list[dict]:
    client_in = io.BytesIO(("\n".join(json.dumps(m) for m in lines) + "\n").encode())
    client_out = io.BytesIO()
    proxy.run(client_in=client_in, client_out=client_out)
    out = []
    for raw in client_out.getvalue().splitlines():
        if raw.strip():
            out.append(json.loads(raw))
    return out


def test_record_roundtrip_passes_through_and_records(tmp_path):
    store = TraceStore(db_path=tmp_path / "t.db", trace_dir=tmp_path / "traces")
    proxy = StdioProxy(["python3", DEMO], "demo", mode="record", store=store, session="s")
    replies = _drive(
        proxy,
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "read", "arguments": {"path": "./src/a.py"}}},
        ],
    )
    ids = {r["id"] for r in replies}
    assert {1, 2, 3} <= ids  # all forwarded and answered by the real server

    events = store.all_events()
    store.close()
    assert len(events) == 1
    assert events[0].tool == "read" and events[0].server == "demo"
    assert (tmp_path / "traces" / "session-s.jsonl").exists()


def test_enforce_blocks_without_reaching_server(tmp_path):
    store = TraceStore(db_path=tmp_path / "t.db", trace_dir=tmp_path / "traces")
    policy = Policy(servers={"demo": ServerPolicy(allowed_tools=["read"], denied_paths=["~/.ssh"])})
    proxy = StdioProxy(["python3", DEMO], "demo", mode="enforce", policy=policy, store=store)
    replies = _drive(
        proxy,
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "read", "arguments": {"path": "~/.ssh/id_rsa"}}},
        ],
    )
    blocked = next(r for r in replies if r["id"] == 7)
    assert "error" in blocked  # synthetic denial, never hit the demo server
    assert store.all_events()[0].decision == Decision.DENY
    store.close()
