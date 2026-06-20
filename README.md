# AgentPerms

**Least-privilege permissions for AI agents and MCP tools. Record what your agent does, auto-generate a safe policy, and block dangerous tool calls before they happen.**

> Your AI agent has sudo. AgentPerms takes it away.

MCP is becoming the standard way AI apps connect to tools and data — which means agents are getting access to your filesystem, your repos, your email, and your database faster than anyone can govern them. Scanners tell you something *looks* risky. Firewalls make you hand-write YAML. AgentPerms does the missing thing:

> **record → infer → lock → replay → enforce**

Run your agent in dev, record every tool call, infer the *minimum* permissions it actually needed, generate a policy, prove it blocks attacks, and enforce it in CI and at runtime.

## Install

```bash
pip install agentperms
```

## The flow

```bash
agentperms scan                  # find MCP configs, flag risky tools & exposures
agentperms lock                  # pin every tool's identity (detect tool poisoning)
agentperms record --client cursor  # route the client through the recording proxy
#   ... use your agent normally ...
agentperms infer                 # traces  -> mcp.policy.yaml (least privilege)
agentperms enforce               # route the client through the blocking proxy
agentperms replay                # prove the policy blocks a pack of attacks
agentperms report                # agentperms-report.html
agentperms init                  # .github/workflows/agentperms.yml
```

It produces `mcp.policy.yaml`, `mcp.lock`, `agentperms-report.html`, and a CI workflow.

## The killer command

```bash
agentperms infer
```

> *Your agent only used read-only GitHub calls and local `./src` access. I generated a least-privilege policy. The agent does not need shell, home directory, secrets, Gmail send, or database write access.*

## How enforcement works

AgentPerms is a transparent **stdio proxy**. `record`/`enforce` rewrite your MCP client's config so each server launches through `agentperms _proxy`:

```
Agent  →  AgentPerms proxy  →  MCP server
              │
              ├─ record:  log every tools/call
              └─ enforce: allow / deny / require-approval before forwarding
```

Denied calls never reach the server — the client gets a clean JSON-RPC error. Approval-gated calls prompt on your terminal.

## Try it offline

A bundled over-privileged demo server lets you see a real block with no setup:

```bash
agentperms scan --path examples/vulnerable-mcp-demo   # flags ~/.ssh mount + unpinned npx
agentperms replay --policy examples/policies/example.mcp.policy.yaml
```

## Example policy

```yaml
version: 1
servers:
  github:
    allowed_tools: [list_repos, read_file, create_issue]
    denied_tools: [delete_repo, write_secret, force_push]
  filesystem:
    allowed_paths: [./src, ./docs]
    denied_paths: [~/.ssh, ~/.env, /etc]
    denied_patterns: ["*.pem", "*.key"]
approvals:
  require_human_approval: [gmail.send_email, github.merge_pr, shell.exec]
redaction: { secrets: true, emails: true, api_keys: true }
```

## Status

v0.1 — supports Claude Desktop, Cursor, VS Code/Copilot, Windsurf, Gemini CLI configs and local stdio MCP servers. Roadmap: HTTP/SSE transport, a Node wrapper, and a live dashboard.

## License

MIT
