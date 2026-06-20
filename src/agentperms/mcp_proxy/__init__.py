"""MCP proxy: stdio interception, JSON-RPC framing, and the policy engine."""

from agentperms.mcp_proxy.policy_engine import PolicyEngine, evaluate

__all__ = ["PolicyEngine", "evaluate"]
