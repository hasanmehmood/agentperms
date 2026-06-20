import json

from agentperms import wiring


def test_rewrite_and_restore(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"demo": {"command": "python3", "args": ["s.py"]}}}))

    n = wiring.rewrite_config(cfg, mode="record")
    assert n == 1
    data = json.loads(cfg.read_text())
    args = data["mcpServers"]["demo"]["args"]
    assert "_proxy" in args and "--" in args and "s.py" in args

    # rewriting again is idempotent (already wrapped)
    assert wiring.rewrite_config(cfg, mode="record") == 0

    assert wiring.restore_config(cfg) is True
    assert json.loads(cfg.read_text())["mcpServers"]["demo"]["args"] == ["s.py"]
