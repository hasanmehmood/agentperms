from agentperms.models import MCPServerConfig, Severity
from agentperms.scanner import rules


def test_flags_unpinned_npx():
    s = MCPServerConfig(name="fs", command="npx", args=["-y", "@scope/server-filesystem", "./src"])
    kinds = {f.kind for f in rules.scan_server_config(s)}
    assert "unpinned_server" in kinds


def test_flags_sensitive_path_mount():
    s = MCPServerConfig(name="fs", command="npx", args=["@scope/server-filesystem@1.0.0", "~/.ssh"])
    findings = rules.scan_server_config(s)
    assert any(f.kind == "sensitive_path_exposure" and f.severity == Severity.HIGH for f in findings)


def test_categorizes_dangerous_tools():
    assert rules.categorize_tool("shell_exec") == "shell"
    assert rules.categorize_tool("send_email") == "send"
    assert rules.categorize_tool("force_push") == "destructive_vcs"
    assert rules.categorize_tool("list_repos") is None


def test_secret_in_env_flagged():
    s = MCPServerConfig(name="gh", command="x", env={"GITHUB_TOKEN": "ghp_secret"})
    assert any(f.kind == "secret_in_config" for f in rules.scan_server_config(s))
