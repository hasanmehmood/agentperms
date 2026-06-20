from agentperms.inference import infer_policy
from agentperms.models import TraceEvent
from agentperms.mcp_proxy.policy_engine import evaluate
from agentperms.models import Decision


def _events():
    return [
        TraceEvent(server="github", tool="read_file", args={"repo": "x", "path": "src/main.py"}),
        TraceEvent(server="github", tool="list_issues", args={}),
        TraceEvent(server="filesystem", tool="read", args={"path": "./src/app.py"}),
        TraceEvent(server="filesystem", tool="read", args={"path": "./src/util.py"}),
    ]


def test_infer_collects_used_tools():
    pol = infer_policy(_events())
    assert set(pol.servers["github"].allowed_tools) == {"read_file", "list_issues"}
    assert pol.servers["filesystem"].allowed_tools == ["read"]


def test_infer_minimal_paths():
    pol = infer_policy(_events())
    assert pol.servers["filesystem"].allowed_paths == ["./src"]


def test_inferred_policy_blocks_unused_dangerous_tool():
    pol = infer_policy(_events())
    # filesystem never used `write`, so it is not allowed -> default-deny
    d, _ = evaluate(pol, "filesystem", "write", {"path": "./src/x"})
    assert d == Decision.DENY


def test_inferred_policy_allows_observed():
    pol = infer_policy(_events())
    d, _ = evaluate(pol, "filesystem", "read", {"path": "./src/new.py"})
    assert d == Decision.ALLOW
