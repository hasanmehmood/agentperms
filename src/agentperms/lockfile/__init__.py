"""Tool manifest lockfile: detect silent tool changes (tool poisoning)."""

from agentperms.lockfile.manifest import build_lockfile, diff_lockfiles, entries_for_server

__all__ = ["build_lockfile", "diff_lockfiles", "entries_for_server"]
