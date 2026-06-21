# AgentPerms

**Least-privilege permissions for AI agents and MCP tools. Record what your agent does, auto-generate a safe policy, and block dangerous tool calls before they happen.**

> Your AI agent has sudo. AgentPerms takes it away.

[![PyPI](https://img.shields.io/pypi/v/agentperms.svg)](https://pypi.org/project/agentperms/)
[![Python](https://img.shields.io/pypi/pyversions/agentperms.svg)](https://pypi.org/project/agentperms/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MCP is becoming the standard way AI apps connect to tools and data — which means agents are getting access to your filesystem, your repos, your email, and your database faster than anyone can govern them. Scanners tell you something *looks* risky. Firewalls make you hand-write YAML. AgentPerms does the missing thing:

> **record → infer → lock → replay → enforce**

Run your agent in dev, record every tool call, infer the *minimum* permissions it actually needed, generate a policy, prove it blocks attacks, and enforce it in CI and at runtime.

---

## Install

```bash
pip install agentperms
```

Requires Python 3.10+. This installs the `agentperms` CLI.

---

## Quick start (30 seconds, no setup)

AgentPerms ships with a deliberately over-privileged demo MCP server, so you can see a real policy decision without wiring up a client or touching the network:

```bash
# 1. Scan the demo config — flags a ~/.ssh mount and an unpinned npx server
agentperms scan --path examples/vulnerable-mcp-demo

# 2. Replay a pack of canned attacks against the example policy
agentperms replay --policy examples/policies/example.mcp.policy.yaml
```

The replay prints a table and a verdict:

```
8/8 attacks blocked.
```

Every attack in the pack — SSH-key exfiltration, `.env` reads, `rm -rf /`, unapproved email, force-push, repo deletion, destructive SQL — is denied or routed to human approval *before it would ever reach a server*.

---

## The full flow on your own agent

```bash
agentperms scan                      # find MCP configs, flag risky tools & exposures
agentperms lock                      # pin every tool's identity (detect tool poisoning)
agentperms record --client cursor    # route the client through the recording proxy
#   ... use your agent normally for a while ...
agentperms infer                     # traces  -> mcp.policy.yaml (least privilege)
agentperms replay                    # prove the policy blocks a pack of attacks
agentperms enforce --client cursor   # route the client through the blocking proxy
agentperms report                    # agentperms-report.html
agentperms init                      # scaffold .github/workflows/agentperms.yml
```

This produces `mcp.policy.yaml`, `mcp.lock`, `agentperms-report.html`, and a CI workflow.

When you're done recording or want to roll back enforcement, restore the original client config:

```bash
agentperms record --client cursor --stop
agentperms enforce --client cursor --stop
```

---

## Command reference

| Command | What it does | Key options |
| --- | --- | --- |
| `scan` | Discover MCP configs and flag risky tools, exposures, and unpinned servers | `--client <name>` (default `all`), `--path <dir>`, `--tools` (also launch servers to enumerate tool names) |
| `lock` | Pin every tool's name/description/schema; warn on silent changes (tool poisoning) | `--check` (fail on drift), `--out mcp.lock`, `--path <dir>` |
| `record` | Route a client's MCP servers through the **recording** proxy | `--client cursor`, `--path <cfg>`, `--stop` (restore) |
| `infer` | Infer a least-privilege policy from recorded traces | `[traces...]` (default `traces/*.jsonl`), `--out mcp.policy.yaml` |
| `replay` | Replay canned attacks against a policy and report blocks | `--policy mcp.policy.yaml` |
| `enforce` | Route a client's MCP servers through the **blocking** proxy | `--client cursor`, `--policy mcp.policy.yaml`, `--path <cfg>`, `--stop` |
| `report` | Render the HTML risk report from scan + traces + policy + replay | `--policy`, `--out agentperms-report.html`, `--path` |
| `init` | Scaffold the GitHub Actions workflow (scan + `lock --check` + replay) | `--out .github/workflows/agentperms.yml` |

### Supported clients (`--client`)

`scan` defaults to `all` and auto-discovers across every known client. `record`/`enforce` default to `cursor`.

| Name | Config discovered |
| --- | --- |
| `claude` | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| `cursor` | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| `vscode` | `~/.vscode/mcp.json`, `./.vscode/mcp.json`, `./.vscode/settings.json` |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| `gemini` | `~/.gemini/settings.json`, `./.gemini/settings.json` |

Don't see your client? Point any command at a config explicitly with `--path`.

---

## The killer command

```bash
agentperms infer
```

> *Your agent only used read-only GitHub calls and local `./src` access. I generated a least-privilege policy. The agent does not need shell, home directory, secrets, Gmail send, or database write access.*

`infer` reads your recorded traces and emits the **minimum** policy that still lets the agent do what it actually did: used tools become `allowed_tools`, the directories it touched collapse into the smallest covering set of `allowed_paths`, and known-dangerous categories (shell, repo deletion, email send, DB writes) are seeded into `denied_tools` / human-approval.

---

## How enforcement works

AgentPerms is a transparent **stdio proxy**. `record`/`enforce` rewrite your MCP client's config so each server launches through `agentperms _proxy` instead of directly:

```
Agent  →  AgentPerms proxy  →  MCP server
              │
              ├─ record:  log every tools/call, then forward
              └─ enforce: allow / deny / require-approval before forwarding
```

A rewritten server entry looks like this (the original command is preserved after `--`, and a `*.agentperms.bak` backup is written so `--stop` can restore it):

```jsonc
// before
{ "command": "python3", "args": ["server.py"] }

// after `agentperms enforce`
{
  "command": "/usr/bin/python3",
  "args": ["-m", "agentperms", "_proxy",
           "--mode", "enforce", "--server", "demo",
           "--policy", "/abs/path/mcp.policy.yaml",
           "--", "python3", "server.py"]
}
```

Denied calls never reach the server — the client gets a clean JSON-RPC error. Approval-gated calls prompt on your terminal. The exact same decision function powers both live enforcement and offline `replay`, so what you test is what you get.

---

## The policy file

`mcp.policy.yaml` is a small, readable contract. This is the bundled example (`examples/policies/example.mcp.policy.yaml`):

```yaml
version: 1

servers:
  github:
    allowed_tools: [list_repos, read_file, create_issue]
    denied_tools:  [delete_repo, write_secret, force_push]
  filesystem:
    allowed_paths:    [./src, ./docs]
    denied_paths:     [~/.ssh, ~/.env, /etc]
    denied_patterns:  ["*.pem", "*.key"]

approvals:
  require_human_approval: [gmail.send_email, github.merge_pr, postgres.execute_write, shell.exec]

redaction: { secrets: true, emails: true, api_keys: true }
```

**Per-server fields:** `allowed_tools`, `denied_tools`, `allowed_paths`, `denied_paths`, `denied_patterns`.
**Top-level:** `approvals.require_human_approval` (entries are `server.tool` or bare `tool`) and `redaction` (scrubs secrets/emails/API keys from traces and reports).

### How a decision is made

For each `tools/call`, the engine returns **allow / deny / require-approval** using first-match-wins precedence:

1. On the human-approval list → **require approval**
2. In `denied_tools` → **deny**
3. A path argument hits `denied_paths` / `denied_patterns` → **deny**
4. `allowed_tools` is set and the tool isn't in it → **deny** (default-deny)
5. `allowed_paths` is set and a path argument falls outside it → **deny**
6. Otherwise → **allow**

An empty policy (no servers) allows everything. Once *any* server is constrained, unknown servers default-deny.

---

## The attack pack

`replay` runs your policy against a built-in set of real-world attack shapes — entirely offline, no server required:

| Attack | Call | Why it's dangerous |
| --- | --- | --- |
| SSH key exfil | `filesystem.read ~/.ssh/id_rsa` | Steals a private key |
| Env secret read | `filesystem.read ./.env` | Leaks credentials |
| Private cert read | `filesystem.read ./certs/server.pem` | Reads a private key file |
| Shell exec | `shell.exec rm -rf /` | Arbitrary command execution |
| Unapproved email | `gmail.send_email …` | Sends mail with no human in the loop |
| Force push | `github.force_push …` | Rewrites history |
| Repo deletion | `github.delete_repo …` | Destroys a repository |
| Destructive SQL | `postgres.execute_write DROP TABLE users` | Drops data |

A call counts as *blocked* if the policy denies it **or** routes it to human approval.

---

## CI integration

`agentperms init` scaffolds a GitHub Actions workflow that fails the build on drift or weak policy:

```bash
agentperms init   # writes .github/workflows/agentperms.yml
```

It runs, on every push/PR:

```bash
agentperms scan --path .     # surface risky configs in the repo
agentperms lock --check      # fail if any tool's identity changed (tool poisoning)
agentperms replay            # fail if the committed policy stops blocking attacks
```

Commit `mcp.policy.yaml` and `mcp.lock`, and your agent's permissions become a reviewable, enforceable part of your codebase.

---

## Status

v0.1 — supports Claude Desktop, Cursor, VS Code/Copilot, Windsurf, and Gemini CLI configs, plus local stdio MCP servers. Roadmap: HTTP/SSE transport, a Node wrapper, and a live dashboard.

## License

MIT
