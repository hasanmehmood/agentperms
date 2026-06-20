"""Render the AgentPerms HTML report.

Aggregates scan findings, recorded traces, the generated policy, and replay
results into a single risk picture: a 0-100 risk score, headline counts, policy
coverage, and a recommended action.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentperms.models import Policy, ScanFinding, Severity, TraceEvent
from agentperms.replay.attack_pack import AttackResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_SEVERITY_WEIGHT = {Severity.HIGH: 25, Severity.MEDIUM: 10, Severity.LOW: 3}


def _risk_score(findings: list[ScanFinding], attack_results: list[AttackResult]) -> int:
    score = sum(_SEVERITY_WEIGHT[f.severity] for f in findings)
    score += sum(20 for r in attack_results if not r.blocked)  # un-blocked attacks hurt a lot
    return min(100, score)


def _policy_coverage(policy: Policy, events: list[TraceEvent]) -> int:
    if not events:
        return 100
    covered = 0
    for ev in events:
        sp = policy.servers.get(ev.server)
        if sp and (not sp.allowed_tools or ev.tool in sp.allowed_tools):
            covered += 1
    return round(100 * covered / len(events))


def build_report_context(
    findings: list[ScanFinding],
    events: list[TraceEvent],
    policy: Policy,
    attack_results: list[AttackResult],
) -> dict[str, Any]:
    high = [f for f in findings if f.severity == Severity.HIGH]
    secrets = [f for f in findings if "secret" in f.kind or "sensitive" in f.kind]
    unpinned = [f for f in findings if f.kind == "unpinned_server"]
    return {
        "risk_score": _risk_score(findings, attack_results),
        "findings": findings,
        "high_count": len(high),
        "secrets_count": len(secrets),
        "unpinned_count": len(unpinned),
        "tools_observed": sorted({f"{e.server}.{e.tool}" for e in events}),
        "policy": policy,
        "policy_coverage": _policy_coverage(policy, events),
        "attack_results": attack_results,
        "attacks_blocked": sum(1 for r in attack_results if r.blocked),
        "attacks_total": len(attack_results),
        "recommended_action": _recommend(findings, attack_results),
    }


def _recommend(findings: list[ScanFinding], attack_results: list[AttackResult]) -> str:
    if any(not r.blocked for r in attack_results):
        return "Tighten the policy: some attacks were NOT blocked. Re-run `agentperms infer`."
    if any(f.severity == Severity.HIGH for f in findings):
        return "Enforce the generated least-privilege policy with `agentperms enforce`."
    return "Looks good. Commit mcp.policy.yaml and mcp.lock, and enable the CI workflow."


def render_report(context: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    return env.get_template("report.html.j2").render(**context)
