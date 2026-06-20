# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-21

Initial public release.

### Added
- `scan` — discover MCP client configs and flag risky tools, exposures, and
  unpinned servers.
- `lock` / `lock --check` — pin every tool's name/description/schema and detect
  silent drift (tool poisoning).
- `record` — route an MCP client through a transparent recording proxy.
- `infer` — turn recorded traces into a least-privilege `mcp.policy.yaml`.
- `enforce` — route a client through the blocking proxy; denied calls never
  reach the server.
- `replay` — prove a policy blocks a pack of canned attacks.
- `report` — render an HTML risk report.
- `init` — scaffold a GitHub Actions workflow.
- Bundled deliberately-vulnerable demo MCP server for offline trials.
- Support for Claude Desktop, Cursor, VS Code/Copilot, Windsurf, and Gemini CLI
  configs over local stdio MCP servers.

[Unreleased]: https://github.com/hasanmehmood/agentperms/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hasanmehmood/agentperms/releases/tag/v0.1.0
