"""Transparent stdio MCP proxy.

Spawns the real MCP server as a subprocess and sits between the client and the
server, pumping JSON-RPC lines in both directions:

    client stdin  --> [intercept tools/call] --> server stdin
    server stdout --> [capture tools/list]   --> client stdout

In ``record`` mode every ``tools/call`` is logged and forwarded. In ``enforce``
mode each call is first evaluated by the policy engine; denials never reach the
server (a synthetic JSON-RPC error is returned to the client instead), and
approval-required calls prompt on the controlling tty.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from typing import Any, BinaryIO

from agentperms.mcp_proxy import jsonrpc
from agentperms.mcp_proxy.policy_engine import evaluate
from agentperms.models import Decision, Policy, Redaction, TraceEvent
from agentperms.recorder.redactor import redact_event
from agentperms.recorder.trace_store import TraceStore


class StdioProxy:
    def __init__(
        self,
        command: list[str],
        server_name: str,
        mode: str = "record",
        policy: Policy | None = None,
        store: TraceStore | None = None,
        session: str = "default",
        redaction: Redaction | None = None,
        on_tools_list=None,
    ):
        self.command = command
        self.server_name = server_name
        self.mode = mode
        self.policy = policy or Policy()
        self.store = store
        self.session = session
        self.redaction = redaction or Redaction()
        self.on_tools_list = on_tools_list
        self.proc: subprocess.Popen | None = None

    # ----------------------------------------------------------------- #
    # Decision + recording
    # ----------------------------------------------------------------- #
    def _decide(self, tool: str, args: dict[str, Any]) -> tuple[Decision, str]:
        if self.mode == "enforce":
            return evaluate(self.policy, self.server_name, tool, args)
        return Decision.RECORD, "record-only"

    def _record(self, tool: str, args: dict[str, Any], decision: Decision) -> None:
        if self.store is None:
            return
        self.store.record(
            TraceEvent(
                server=self.server_name,
                tool=tool,
                args=redact_event(args, self.redaction),
                decision=decision,
            ),
            session=self.session,
        )

    def _approve(self, tool: str, reason: str) -> bool:
        """Prompt for human approval on the controlling tty; deny if none."""
        try:
            tty = open("/dev/tty", "r+")
        except OSError:
            self._log(f"[enforce] no tty for approval of {tool!r}; DENYING")
            return False
        tty.write(f"\n[AgentPerms] {reason}. Allow {self.server_name}.{tool}? [y/N] ")
        tty.flush()
        answer = tty.readline().strip().lower()
        tty.close()
        return answer in ("y", "yes")

    def _log(self, msg: str) -> None:
        sys.stderr.write(f"{msg}\n")
        sys.stderr.flush()

    # ----------------------------------------------------------------- #
    # Pumps
    # ----------------------------------------------------------------- #
    def handle_client_message(self, raw: bytes, server_stdin: BinaryIO, client_stdout: BinaryIO) -> None:
        """Process one client->server line; forward or intercept."""
        msg = jsonrpc.parse(raw)
        if msg is None or not jsonrpc.is_tools_call(msg):
            server_stdin.write(raw)
            server_stdin.flush()
            return

        tool, args = jsonrpc.tool_call_params(msg)
        decision, reason = self._decide(tool, args)

        if decision == Decision.REQUIRE_APPROVAL:
            approved = self._approve(tool, reason)
            decision = Decision.ALLOW if approved else Decision.DENY
            reason = "approved by human" if approved else "approval denied"

        self._record(tool, args, decision)

        if decision == Decision.DENY:
            self._log(f"[BLOCKED] {self.server_name}.{tool}: {reason}")
            jsonrpc.write_message(
                client_stdout, jsonrpc.error_response(msg.get("id"), f"AgentPerms blocked this call: {reason}")
            )
            return

        server_stdin.write(raw)
        server_stdin.flush()

    def handle_server_message(self, raw: bytes, client_stdout: BinaryIO) -> None:
        """Process one server->client line; capture tools/list, then forward."""
        msg = jsonrpc.parse(raw)
        if msg and jsonrpc.is_tools_list_result(msg) and self.on_tools_list:
            self.on_tools_list(self.server_name, self.command, msg["result"]["tools"])
        client_stdout.write(raw)
        client_stdout.flush()

    def run(
        self,
        client_in: BinaryIO | None = None,
        client_out: BinaryIO | None = None,
    ) -> int:
        """Launch the server and pump until the client closes stdin."""
        client_in = client_in or sys.stdin.buffer
        client_out = client_out or sys.stdout.buffer
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )
        assert self.proc.stdin and self.proc.stdout

        def pump_server() -> None:
            for line in self.proc.stdout:  # type: ignore[union-attr]
                self.handle_server_message(line, client_out)

        t = threading.Thread(target=pump_server, daemon=True)
        t.start()

        try:
            for line in client_in:
                self.handle_client_message(line, self.proc.stdin, client_out)
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            self.proc.wait()
            t.join(timeout=1.0)
        return self.proc.returncode or 0
