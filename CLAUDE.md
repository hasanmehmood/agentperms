# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AgentPerms is a CLI that generates and enforces least-privilege permissions for MCP (Model Context Protocol) agents. The core wedge is the chain **record → infer → lock → replay → enforce**: record an agent's real tool calls, infer the minimum policy it needed, pin tool identities, prove the policy blocks attacks, and enforce it at runtime by sitting between the MCP client and server.

## Commands

```bash
# Setup (src-layout package, editable install)
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/pip install pytest        # dev dep

# Tests
.venv/bin/python -m pytest -q                       # full suite
.venv/bin/python -m pytest tests/test_policy_engine.py -q
.venv/bin/python -m pytest tests/test_policy_engine.py::test_deny_pem_pattern -q

# End-to-end smoke against the bundled demo (no network/setup needed)
.venv/bin/agentperms scan --path examples/vulnerable-mcp-demo
.venv/bin/agentperms replay --policy examples/policies/example.mcp.policy.yaml
```

There is no separate lint/build step; `pip install -e .` (hatchling) is the build.

## Architecture

The CLI (`src/agentperms/cli.py`, Typer app, entry point `agentperms.cli:app`) is a thin orchestration layer over subsystem packages. The data contracts between every subsystem live in `models.py` (Pydantic): `Policy`/`ServerPolicy`, `TraceEvent`, `Lockfile`/`ManifestEntry`, `ScanFinding`, `DiscoveredConfig`.

Two architectural facts drive most of the design — keep them intact when changing code:

1. **One decision authority.** `mcp_proxy/policy_engine.py::evaluate(policy, server, tool, args) -> (Decision, reason)` is the *only* place allow/deny/approve logic lives. It is called by both live enforcement (`stdio_proxy`) and offline `replay`. Never fork this logic. Decision order is documented at the top of that file (approval list → denied_tools → denied paths/patterns → default-deny on allowlist → path allowlist → allow). An empty `Policy` (no servers) allows everything; once any server is constrained, unknown servers default-deny.

2. **The proxy is the recorder and the enforcer.** `mcp_proxy/stdio_proxy.py` spawns the real MCP server as a subprocess and pumps newline-delimited JSON-RPC both ways (`mcp_proxy/jsonrpc.py` does framing). It intercepts `tools/call` requests and captures `tools/list` responses. In `record` mode it logs+forwards; in `enforce` mode it evaluates first and, on DENY, returns a synthetic JSON-RPC error to the client *without forwarding* — denied calls never reach the server. This is invoked as the hidden `agentperms _proxy` command, which is what rewritten client configs launch.

### Flow and the modules each command touches

- **`scan`** → `scanner/` (`base.discover_all` + `generic.parse_config_file` parse `mcpServers`/`servers`/`mcp.servers` shapes from any client config; `rules.py` holds the risk heuristics).
- **`lock` / `lock --check`** → `lockfile/manifest.py` enumerates tools via `mcp_proxy/client.py` (a minimal initialize→tools/list client), hashes name/description/schema/command, and `diff_lockfiles` flags description/schema changes as tool poisoning.
- **`record` / `enforce`** → `wiring.py` rewrites a client's MCP config so each server launches through `python -m agentperms _proxy --mode <m> -- <orig cmd>`, backing up the original (`*.agentperms.bak`) for `--stop`. Traces go to `recorder/trace_store.py` (SQLite + append-only `traces/*.jsonl`), redacted first by `recorder/redactor.py`.
- **`infer`** → `inference/least_privilege.py` turns traces into a `Policy` (used tools → allowed_tools, path args → minimal covering dirs).
- **`replay`** → `replay/attack_pack.py` runs canned attacks through `evaluate`.
- **`report`** → `reports/report.py` + Jinja2 template renders the HTML risk report.

### Shared tables (single source of truth — reuse, don't duplicate)

- `scanner/rules.py` defines the dangerous-tool category tables (`DANGEROUS_CATEGORIES`, `APPROVAL_CATEGORIES`) and `categorize_tool()`. `inference` reuses these to seed `denied_tools` and the approval list. Add a new dangerous tool category here and both scanning and inference pick it up.
- `recorder/redactor.py` is used by both the recorder (scrub before persisting) and the report (never echo secrets).
- `mcp_proxy/policy_engine.py::PATH_KEYS` is the shared notion of "which arg keys carry filesystem paths", reused by inference.

## Conventions

- Per-client scanner files (`claude.py`, `cursor.py`) intentionally do **not** exist — all clients are handled generically via `config.CLIENT_CONFIG_PATHS` + `scanner/generic.py`. Add a new client by adding its config path(s) to `CLIENT_CONFIG_PATHS`, not a new module.
- `examples/vulnerable-mcp-demo/server.py` is a real (deliberately over-privileged) stdio MCP server used both as the offline demo target and as the integration-test fixture in `tests/test_proxy_roundtrip.py`. Keep its tool list in sync if tests reference specific tools.
- Generated artifacts (`mcp.policy.yaml`, `mcp.lock`, `agentperms-report.html`, `traces/`, `.agentperms/`) are gitignored.
