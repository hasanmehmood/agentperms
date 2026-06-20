# Contributing to AgentPerms

Thanks for your interest in improving AgentPerms! This project generates and
enforces least-privilege permissions for MCP agents. Contributions of all kinds
— bug reports, docs, tests, and features — are welcome.

## Development setup

AgentPerms is a `src`-layout Python package built with hatchling. Use an
editable install:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Requires Python 3.10+.

## Running the tests

```bash
.venv/bin/python -m pytest -q                       # full suite
.venv/bin/python -m pytest tests/test_policy_engine.py -q
```

## Try it end-to-end (no network/setup needed)

A bundled, deliberately over-privileged demo server lets you exercise the tool
offline:

```bash
.venv/bin/agentperms scan --path examples/vulnerable-mcp-demo
.venv/bin/agentperms replay --policy examples/policies/example.mcp.policy.yaml
```

## Architecture notes

The CLI (`src/agentperms/cli.py`) is a thin orchestration layer over subsystem
packages. A few invariants are worth knowing before you change code:

- **One decision authority.** `mcp_proxy/policy_engine.py::evaluate(...)` is the
  *only* place allow/deny/approve logic lives. It is used by both live
  enforcement and offline `replay`. Don't fork this logic.
- **The proxy is both recorder and enforcer.** `mcp_proxy/stdio_proxy.py` spawns
  the real MCP server and pumps JSON-RPC both ways, intercepting `tools/call`.
- **Shared tables, not duplicated logic.** Dangerous-tool categories live in
  `scanner/rules.py`; redaction in `recorder/redactor.py`; path-arg keys in
  `policy_engine.py::PATH_KEYS`. Reuse these rather than re-defining them.
- **Clients are handled generically.** Add a new client by adding its config
  path(s) to `config.CLIENT_CONFIG_PATHS`, not a new per-client module.

## Submitting changes

1. Fork the repo and create a feature branch off `main`.
2. Make your change with tests. Keep new code consistent with the surrounding
   style.
3. Ensure `pytest -q` passes locally.
4. Open a pull request describing the change and the motivation. Link any
   related issue.

## Reporting bugs and requesting features

Please use the GitHub issue templates. For security-sensitive reports, please
avoid filing a public issue with exploit details — open a minimal report and
note that details can be shared privately.

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
