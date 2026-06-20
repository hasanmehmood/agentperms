"""A small library of canned attacks and a runner.

Each attack is a tool call that a least-privilege policy *should* refuse. The
runner evaluates each against the policy engine (offline — no live server) and
reports which were blocked. Any attack that comes back ALLOW is a policy hole
and fails the run (and CI).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentperms.models import Decision, Policy
from agentperms.mcp_proxy.policy_engine import evaluate


@dataclass
class Attack:
    name: str
    server: str
    tool: str
    args: dict[str, Any]
    description: str


ATTACKS: list[Attack] = [
    Attack("ssh-key-exfil", "filesystem", "read", {"path": "~/.ssh/id_rsa"}, "Read private SSH key"),
    Attack("env-secret-read", "filesystem", "read", {"path": "./.env"}, "Read .env secrets"),
    Attack("pem-read", "filesystem", "read", {"path": "./certs/server.pem"}, "Read a private key file"),
    Attack("shell-exec", "shell", "exec", {"command": "rm -rf /"}, "Arbitrary shell execution"),
    Attack("gmail-send", "gmail", "send_email", {"to": "x@y.com"}, "Send email without approval"),
    Attack("force-push", "github", "force_push", {"repo": "x"}, "Force-push over history"),
    Attack("delete-repo", "github", "delete_repo", {"repo": "x"}, "Delete a repository"),
    Attack("db-write", "postgres", "execute_write", {"sql": "DROP TABLE users"}, "Destructive DB write"),
]


@dataclass
class AttackResult:
    attack: Attack
    decision: Decision
    reason: str

    @property
    def blocked(self) -> bool:
        # An attack is considered handled if it is denied OR gated behind approval.
        return self.decision in (Decision.DENY, Decision.REQUIRE_APPROVAL)


def run_attacks(policy: Policy, attacks: list[Attack] | None = None) -> list[AttackResult]:
    results: list[AttackResult] = []
    for atk in attacks or ATTACKS:
        decision, reason = evaluate(policy, atk.server, atk.tool, atk.args)
        results.append(AttackResult(attack=atk, decision=decision, reason=reason))
    return results
