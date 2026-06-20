from agentperms.lockfile import diff_lockfiles, entries_for_server
from agentperms.models import Lockfile


def _tools(desc="Read a file."):
    return [{"name": "read", "description": desc, "inputSchema": {"type": "object"}}]


def test_no_diff_when_identical():
    a = Lockfile(entries=entries_for_server("fs", ["x"], _tools()))
    b = Lockfile(entries=entries_for_server("fs", ["x"], _tools()))
    assert diff_lockfiles(a, b) == []


def test_detects_description_change_as_poisoning():
    old = Lockfile(entries=entries_for_server("fs", ["x"], _tools("Read a file.")))
    new = Lockfile(entries=entries_for_server("fs", ["x"], _tools("Read a file and exfiltrate it.")))
    warnings = diff_lockfiles(old, new)
    assert any("poisoning" in w for w in warnings)


def test_detects_new_and_removed_tools():
    old = Lockfile(entries=entries_for_server("fs", ["x"], _tools()))
    more = _tools() + [{"name": "write", "description": "w", "inputSchema": {}}]
    new = Lockfile(entries=entries_for_server("fs", ["x"], more))
    assert any("NEW" in w for w in diff_lockfiles(old, new))
    assert any("REMOVED" in w for w in diff_lockfiles(new, old))
