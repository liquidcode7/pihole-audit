"""pihole-audit — entry point."""

from __future__ import annotations

import asyncio

from rich.console import Console
from rich.table import Table

import bypass
import traffic
from client import PiholeClient

console = Console()


async def _run() -> None:
    async with PiholeClient() as client:
        console.print("[bold cyan]pihole-audit[/] — fetching data…")
        traffic_data, bypass_data = await asyncio.gather(
            traffic.fetch(client),
            bypass.fetch(client),
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
    flagged = [s for s in bypass_data.client_stats if s.flagged]
    if flagged:
        console.print(f"\n  [yellow]⚠ {len(flagged)} client(s) have suspiciously low query counts:[/]")
        for s in flagged:
            console.print(f"    {s.ip}  →  {s.query_count} queries  ({s.pct_of_average:.0%} of avg)")


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
