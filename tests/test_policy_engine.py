from agentperms.models import Approvals, Policy, ServerPolicy
from agentperms.mcp_proxy.policy_engine import evaluate
from agentperms.models import Decision


def _policy():
    return Policy(
        servers={
            "filesystem": ServerPolicy(
                allowed_tools=["read"],
                allowed_paths=["./src"],
                denied_paths=["~/.ssh"],
                denied_patterns=["*.pem", "*.key"],
            ),
            "github": ServerPolicy(allowed_tools=["list_repos"], denied_tools=["delete_repo"]),
        },
        approvals=Approvals(require_human_approval=["shell.exec"]),
    )


def test_allow_in_allowlist_and_path():
    d, _ = evaluate(_policy(), "filesystem", "read", {"path": "./src/app.py"})
    assert d == Decision.ALLOW


def test_deny_tool_not_in_allowlist():
    d, _ = evaluate(_policy(), "filesystem", "write", {"path": "./src/x"})
    assert d == Decision.DENY


def test_deny_sensitive_path():
    d, _ = evaluate(_policy(), "filesystem", "read", {"path": "~/.ssh/id_rsa"})
    assert d == Decision.DENY


def test_deny_pem_pattern():
    d, _ = evaluate(_policy(), "filesystem", "read", {"path": "./src/server.pem"})
    assert d == Decision.DENY


def test_deny_path_outside_allowed():
    d, _ = evaluate(_policy(), "filesystem", "read", {"path": "/tmp/x.py"})
    assert d == Decision.DENY


def test_explicit_denied_tool():
    d, _ = evaluate(_policy(), "github", "delete_repo", {"repo": "x"})
    assert d == Decision.DENY


def test_require_approval():
    d, _ = evaluate(_policy(), "shell", "exec", {"command": "ls"})
    assert d == Decision.REQUIRE_APPROVAL


def test_unknown_server_default_deny_when_constrained():
    d, _ = evaluate(_policy(), "postgres", "select", {})
    assert d == Decision.DENY


def test_no_constraints_allows():
    d, _ = evaluate(Policy(), "anything", "anytool", {})
    assert d == Decision.ALLOW
