"""pihole-audit — entry point."""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import assessment
import bypass
import recommender
import report
import traffic
from client import PiholeClient

console = Console()


async def _run() -> None:
    async with PiholeClient() as client:
        console.print("[bold cyan]pihole-audit[/] — fetching data…")
        client_names = await client.get_client_names()
        traffic_data, bypass_data, rec_data = await asyncio.gather(
            traffic.fetch(client, client_names=client_names),
            bypass.fetch(client, client_names=client_names),
            recommender.fetch(client),
        )

    # Summary
    s = traffic_data.summary
    console.print(f"\n[bold]Traffic Summary[/]")
    console.print(f"  Total queries  : {s.total:,}")
    console.print(f"  Blocked        : {s.blocked:,}  ({s.percent_blocked:.1f}%)")
    console.print(f"  Allowed        : {s.allowed:,}")
    console.print(f"  Cached         : {s.cached:,}")
    console.print(f"  Forwarded      : {s.forwarded:,}")
    console.print(f"  Unique domains : {s.unique_domains:,}")
    console.print(f"  Active clients : {s.active_clients} / {s.total_clients} total")
    console.print(f"  Gravity list   : {s.gravity_domains:,} domains blocked")

    # Top allowed domains
    _print_table(
        "Top Allowed Domains",
        ["Domain", "Queries"],
        [(d.domain, str(d.count)) for d in traffic_data.top_allowed[:15]],
    )

    # Top blocked domains
    _print_table(
        "Top Blocked Domains",
        ["Domain", "Queries"],
        [(d.domain, str(d.count)) for d in traffic_data.top_blocked[:15]],
    )

    # Top clients
    _print_table(
        "Top Clients",
        ["IP", "Name", "Queries"],
        [(c.client, c.name, str(c.count)) for c in traffic_data.top_clients[:15]],
    )

    # --- Bypass Detection ---
    console.print(f"\n[bold]DNS Bypass Detection[/]  "
                  f"[dim](scanned {bypass_data.queries_scanned:,} queries)[/]")

    if not bypass_data.findings:
        console.print("  [green]No bypass indicators detected.[/]")
    else:
        method_labels = {
            "doh_lookup":      "[red]DoH/DoT lookup[/]",
            "ptr_lookup":      "[yellow]PTR lookup[/]",
            "low_query_count": "[yellow]Low query count[/]",
        }
        _print_table(
            "Bypass Findings",
            ["Client IP", "Method", "Detail", "Count"],
            [
                (
                    f.client_ip,
                    method_labels.get(f.method, f.method),
                    f.detail,
                    str(f.count),
                )
                for f in bypass_data.findings
            ],
        )

    # Client query distribution (flag low-count clients)
    flagged_clients = [s for s in bypass_data.client_stats if s.flagged]
    if flagged_clients:
        console.print(f"\n  [yellow]⚠ {len(flagged_clients)} client(s) have suspiciously low query counts:[/]")
        for s in flagged_clients:
            label = f"{s.ip} ({s.name})" if s.name != s.ip else s.ip
            console.print(f"    {label}  →  {s.query_count} queries  ({s.pct_of_average:.0%} of avg)")

    # --- Blocklist Recommendations ---
    console.print(f"\n[bold]Blocklist Recommendations[/]  "
                  f"[dim](scanned {rec_data.queries_scanned:,} allowed queries)[/]")

    if not rec_data.recommendations:
        console.print("  [green]No known tracking/ad domains found in allowed queries.[/]")
    else:
        console.print(f"  Found [red]{len(rec_data.recommendations)}[/] domains across "
                      f"[yellow]{len(rec_data.by_category)}[/] categories you should consider blocking.\n")
        for category, recs in sorted(rec_data.by_category.items()):
            _print_table(
                category,
                ["Domain", "Queries", "Clients"],
                [
                    (r.domain, str(r.count), ", ".join(r.clients[:3]))
                    for r in recs
                ],
            )

    # --- AI Assessment ---
    console.print("\n[bold magenta]AI Assessment[/]  [dim](streaming from Claude…)[/]\n")
    console.rule(style="magenta")
    assessment_text = assessment.get_ai_assessment(traffic_data, bypass_data, rec_data)
    console.rule(style="magenta")
    console.print(
        Panel(
            "[dim]Assessment complete. See above for full analysis.[/]",
            border_style="magenta",
            title="[bold magenta]Claude AI Assessment[/]",
        )
    )

    # --- HTML Report ---
    out = report.render_html(
        traffic_data, bypass_data, rec_data,
        client_names=client_names,
        assessment_text=assessment_text,
    )
    console.print(f"\n[bold green]✓ Report saved:[/] {out}")


def _print_table(title: str, headers: list[str], rows: list[tuple[str, ...]]) -> None:
    t = Table(title=title, show_lines=False)
    for h in headers:
        t.add_column(h)
    for row in rows:
        t.add_row(*row)
    console.print()
    console.print(t)


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
