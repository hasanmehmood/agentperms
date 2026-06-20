"""AgentPerms command-line interface.

    agentperms scan       discover MCP configs and flag risky tools/exposure
    agentperms lock       pin tool identities (detect tool poisoning)
    agentperms record     wire a client through the proxy and record tool calls
    agentperms infer      turn recorded traces into a least-privilege policy
    agentperms enforce    wire a client through the proxy in blocking mode
    agentperms replay     prove the policy blocks a pack of canned attacks
    agentperms report     render agentperms-report.html
    agentperms init       scaffold the GitHub Actions workflow
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agentperms import config as cfg
from agentperms.inference import infer_policy
from agentperms.lockfile import build_lockfile, diff_lockfiles
from agentperms.models import Lockfile, Policy, Severity
from agentperms.recorder.trace_store import TraceStore, load_jsonl
from agentperms.replay import run_attacks
from agentperms.reports import build_report_context, render_report
from agentperms.scanner import base as scanner
from agentperms.scanner import rules

app = typer.Typer(
    help="Least-privilege permissions for AI agents and MCP tools.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_SEV_STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "green"}


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    client: str = typer.Option("all", help="Client to scan, or 'all'."),
    path: Optional[str] = typer.Option(None, help="Scan MCP configs under an explicit path."),
    enumerate_tools: bool = typer.Option(
        False, "--tools", help="Also launch each server to scan its tool names (slower)."
    ),
):
    """Discover MCP configs and flag risky tools, exposures, and unpinned servers."""
    configs = scanner.discover_all(path) if (path or client == "all") else scanner.discover_client(client)
    if not configs:
        console.print("[yellow]No MCP configs found.[/] Try --path or check your client.")
        raise typer.Exit(0)

    findings = scanner.scan_configs(configs)

    if enumerate_tools:
        from agentperms.mcp_proxy.client import query_tools

        for c in configs:
            for s in c.servers:
                if not s.command:
                    continue
                for tool in query_tools([s.command, *s.args]):
                    findings += rules.scan_tool_name(s.name, tool.get("name", ""), tool.get("description", ""))

    console.print(f"Scanned [bold]{sum(len(c.servers) for c in configs)}[/] servers "
                  f"across [bold]{len(configs)}[/] config(s).")
    if not findings:
        console.print("[green]No findings.[/]")
        raise typer.Exit(0)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity"); table.add_column("Server"); table.add_column("Kind"); table.add_column("Detail")
    for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
        table.add_row(f"[{_SEV_STYLE[f.severity]}]{f.severity.value}[/]", f.server, f.kind, f.message)
    console.print(table)
    if any(f.severity == Severity.HIGH for f in findings):
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# lock
# --------------------------------------------------------------------------- #
@app.command()
def lock(
    check: bool = typer.Option(False, "--check", help="Fail if tools changed since the last lock."),
    path: Optional[str] = typer.Option(None, help="Scan MCP configs under an explicit path."),
    out: str = typer.Option(cfg.LOCK_FILE, help="Lockfile path."),
):
    """Pin every tool's name/description/schema; warn on silent changes."""
    configs = scanner.discover_all(path)
    if not configs:
        console.print("[yellow]No MCP configs found.[/]")
        raise typer.Exit(0)

    new_lock = build_lockfile(configs)
    out_path = Path(out)

    if check:
        if not out_path.exists():
            console.print(f"[red]No existing {out} to check against.[/] Run `agentperms lock` first.")
            raise typer.Exit(1)
        old = Lockfile.from_yaml(out_path.read_text())
        warnings = diff_lockfiles(old, new_lock)
        if warnings:
            for w in warnings:
                console.print(f"[red]{w}[/]")
            raise typer.Exit(1)
        console.print("[green]Lockfile up to date. No tool drift detected.[/]")
        raise typer.Exit(0)

    out_path.write_text(new_lock.to_yaml())
    console.print(f"[green]Wrote {out}[/] ({len(new_lock.entries)} tools pinned).")


# --------------------------------------------------------------------------- #
# record / enforce (config wiring)
# --------------------------------------------------------------------------- #
def _wire(client: str, path: Optional[str], mode: str, policy: Optional[str], stop: bool) -> None:
    from agentperms import wiring

    paths: list[Path]
    if path:
        paths = [Path(path).expanduser()]
    else:
        paths = [p for p in cfg.CLIENT_CONFIG_PATHS.get(client, []) if p.exists()]
    if not paths:
        console.print(f"[yellow]No config found for client {client!r}.[/] Use --path.")
        raise typer.Exit(1)

    for p in paths:
        if stop:
            restored = wiring.restore_config(p)
            console.print(f"{'[green]Restored[/]' if restored else '[yellow]No backup for[/]'} {p}")
        else:
            n = wiring.rewrite_config(p, mode=mode, policy=policy)
            console.print(f"[green]Wired {n} server(s)[/] through the {mode} proxy in {p}")
    if not stop:
        console.print("[bold]Restart your MCP client to pick up the change.[/] "
                      f"Run `agentperms {mode if mode=='enforce' else 'record'} --stop` to undo.")


@app.command()
def record(
    client: str = typer.Option("cursor", help="MCP client to wire."),
    path: Optional[str] = typer.Option(None, help="Explicit config path."),
    stop: bool = typer.Option(False, "--stop", help="Restore the original config."),
):
    """Route a client's MCP servers through the recording proxy."""
    _wire(client, path, mode="record", policy=None, stop=stop)


@app.command()
def enforce(
    client: str = typer.Option("cursor", help="MCP client to wire."),
    path: Optional[str] = typer.Option(None, help="Explicit config path."),
    policy: str = typer.Option(cfg.POLICY_FILE, help="Policy to enforce."),
    stop: bool = typer.Option(False, "--stop", help="Restore the original config."),
):
    """Route a client's MCP servers through the enforcing (blocking) proxy."""
    if not stop and not Path(policy).exists():
        console.print(f"[red]Policy {policy} not found.[/] Run `agentperms infer` first.")
        raise typer.Exit(1)
    _wire(client, path, mode="enforce", policy=str(Path(policy).resolve()) if not stop else None, stop=stop)


# --------------------------------------------------------------------------- #
# infer
# --------------------------------------------------------------------------- #
@app.command()
def infer(
    traces: list[str] = typer.Argument(None, help="Trace JSONL files (default: traces/*.jsonl)."),
    out: str = typer.Option(cfg.POLICY_FILE, help="Output policy path."),
):
    """Infer a least-privilege policy from recorded traces."""
    paths = traces or [str(p) for p in Path(cfg.TRACE_DIR).glob("*.jsonl")]
    events = load_jsonl(paths)
    if not events:
        console.print("[yellow]No trace events found.[/] Record some traffic first.")
        raise typer.Exit(1)
    policy = infer_policy(events)
    Path(out).write_text(policy.to_yaml())
    servers = ", ".join(policy.servers)
    console.print(f"[green]Wrote {out}[/] from {len(events)} events across: {servers}")


# --------------------------------------------------------------------------- #
# replay
# --------------------------------------------------------------------------- #
@app.command()
def replay(policy: str = typer.Option(cfg.POLICY_FILE, help="Policy to test.")):
    """Replay a pack of canned attacks against the policy and report blocks."""
    if not Path(policy).exists():
        console.print(f"[red]Policy {policy} not found.[/]")
        raise typer.Exit(1)
    pol = Policy.from_yaml(Path(policy).read_text())
    results = run_attacks(pol)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Attack"); table.add_column("Tool"); table.add_column("Outcome"); table.add_column("Reason")
    for r in results:
        outcome = "[green]blocked[/]" if r.blocked else "[bold red]ALLOWED[/]"
        table.add_row(r.attack.description, f"{r.attack.server}.{r.attack.tool}", outcome, r.reason)
    console.print(table)

    blocked = sum(1 for r in results if r.blocked)
    console.print(f"\n[bold]{blocked}/{len(results)} attacks blocked.[/]")
    if blocked < len(results):
        console.print("[red]Policy has holes — tighten it.[/]")
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@app.command()
def report(
    path: Optional[str] = typer.Option(None, help="Scan MCP configs under an explicit path."),
    policy: str = typer.Option(cfg.POLICY_FILE, help="Policy to evaluate."),
    out: str = typer.Option(cfg.REPORT_FILE, help="Output HTML path."),
):
    """Render the HTML risk report from scan + traces + policy + replay."""
    configs = scanner.discover_all(path)
    findings = scanner.scan_configs(configs)
    events = []
    if Path(cfg.DB_FILE).exists():
        store = TraceStore()
        events = store.all_events()
        store.close()
    pol = Policy.from_yaml(Path(policy).read_text()) if Path(policy).exists() else Policy()
    attack_results = run_attacks(pol)
    context = build_report_context(findings, events, pol, attack_results)
    Path(out).write_text(render_report(context))
    console.print(f"[green]Wrote {out}[/] — risk score {context['risk_score']}/100.")


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
@app.command()
def init(out: str = typer.Option(cfg.WORKFLOW_FILE, help="Workflow path.")):
    """Scaffold the GitHub Actions workflow that runs scan + lock --check + replay."""
    template = Path(__file__).parent / "templates" / "github_action.yml.j2"
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(template.read_text())
    console.print(f"[green]Wrote {out}[/]")


# --------------------------------------------------------------------------- #
# _proxy (hidden) — what rewritten client configs invoke
# --------------------------------------------------------------------------- #
@app.command(
    "_proxy",
    hidden=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def _proxy(
    ctx: typer.Context,
    mode: str = typer.Option("record", help="record | enforce"),
    server: str = typer.Option("server", help="Logical server name."),
    policy: Optional[str] = typer.Option(None, help="Policy file (enforce mode)."),
    session: str = typer.Option("default", help="Trace session id."),
):
    """Run the transparent stdio proxy around the wrapped server command."""
    from agentperms.mcp_proxy.stdio_proxy import StdioProxy

    command = ctx.args
    if not command:
        console.print("[red]No wrapped command given after `--`.[/]")
        raise typer.Exit(2)

    pol = Policy.from_yaml(Path(policy).read_text()) if (policy and Path(policy).exists()) else Policy()
    store = TraceStore()
    proxy = StdioProxy(
        command=command, server_name=server, mode=mode, policy=pol, store=store, session=session
    )
    code = proxy.run()
    store.close()
    raise typer.Exit(code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
