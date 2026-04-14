"""pihole-audit — entry point."""

from __future__ import annotations

import asyncio
import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import assessment
import bypass
import conversation
import correlate
import device_identifier
import fail2ban
import firewall
import metrics
import recommender
import report
import traffic
from client import PiholeClient

console = Console()

_RISK_COLORS = {
    "high":    "[red]",
    "medium":  "[yellow]",
    "low":     "[green]",
    "minimal": "[cyan]",
}
_RISK_RESET = "[/]"


def _device_label(
    ip: str,
    device_map: dict[str, device_identifier.DeviceInfo],
    client_names: dict[str, str],
) -> str:
    """Return the best human-readable label for an IP."""
    info = device_map.get(ip)
    if info and info.device_type != "Unknown device":
        return f"{info.device_type} ({ip})"
    name = client_names.get(ip)
    if name and name != ip:
        return f"{name} ({ip})"
    return ip


async def _run() -> None:
    aliases_path = os.environ.get("PIHOLE_DEVICES_JSON", "devices.json")

    async with PiholeClient() as client:
        console.print("[bold cyan]pihole-audit[/] — fetching data…")
        client_names, mac_vendors = await asyncio.gather(
            client.get_client_names(),
            client.get_mac_vendors(),
        )
        traffic_data, bypass_data, rec_data, device_map = await asyncio.gather(
            traffic.fetch(client, client_names=client_names),
            bypass.fetch(client, client_names=client_names),
            recommender.fetch(client),
            device_identifier.identify_devices(
                client,
                client_names=client_names,
                mac_vendors=mac_vendors,
                aliases_path=aliases_path,
            ),
        )

    risk_summary = device_identifier.network_risk_summary(device_map)

    # Phase 2: independent sources
    raw_metrics, raw_firewall, raw_fail2ban = await asyncio.gather(
        metrics.fetch(),
        firewall.fetch(),
        fail2ban.fetch(),
        return_exceptions=True,
    )
    metrics_data  = None if isinstance(raw_metrics,  Exception) else raw_metrics
    firewall_data = None if isinstance(raw_firewall, Exception) else raw_firewall
    fail2ban_data = None if isinstance(raw_fail2ban, Exception) else raw_fail2ban

    # Cross-source correlation
    correlation_report = correlate.correlate(
        bypass_data=bypass_data,
        firewall_data=firewall_data,
        fail2ban_data=fail2ban_data,
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
        ["IP", "Device / Name", "Queries"],
        [
            (
                c.client,
                _device_label(c.client, device_map, client_names),
                str(c.count),
            )
            for c in traffic_data.top_clients[:15]
        ],
    )

    # --- Device Inventory ---
    risk_color = _RISK_COLORS.get(risk_summary.overall_risk, "")
    console.print(
        f"\n[bold]Device Inventory[/]  "
        f"[dim]({risk_summary.identified} identified · "
        f"{risk_summary.unknown} unknown · "
        f"{risk_summary.manual} manual)[/]  "
        f"Network risk: {risk_color}{risk_summary.overall_risk.upper()}{_RISK_RESET}"
    )

    sorted_devices = sorted(
        device_map.values(),
        key=lambda d: (
            {"high": 0, "medium": 1, "low": 2, "minimal": 3}.get(d.privacy_risk, 4),
            d.ip,
        ),
    )

    device_rows = []
    for info in sorted_devices:
        rc = _RISK_COLORS.get(info.privacy_risk, "")
        risk_cell = f"{rc}{info.privacy_risk}{_RISK_RESET}"
        conf_cell = (
            f"{info.confidence:.0%}"
            if not info.manual_override
            else "[dim]manual[/]"
        )
        label = info.hostname if info.hostname != info.ip else ""
        flag = " [yellow]⚠[/]" if info.device_type == "Unknown device" else ""
        device_rows.append((
            info.ip,
            label,
            f"{info.device_type}{flag}",
            conf_cell,
            risk_cell,
        ))

    _print_table(
        "Device Inventory",
        ["IP", "Hostname", "Device Type", "Confidence", "Privacy Risk"],
        device_rows,
    )

    unknown_devices = [d for d in device_map.values() if d.device_type == "Unknown device"]
    if unknown_devices:
        console.print(
            f"\n  [yellow]⚠ {len(unknown_devices)} unidentified device(s) — "
            f"add labels to devices.json to suppress this warning.[/]"
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
            ["Client", "Method", "Detail", "Count"],
            [
                (
                    _device_label(f.client_ip, device_map, client_names),
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
            label = _device_label(s.ip, device_map, client_names)
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
                    (
                        r.domain,
                        str(r.count),
                        ", ".join(
                            _device_label(ip, device_map, client_names)
                            for ip in r.clients[:3]
                        ),
                    )
                    for r in recs
                ],
            )

    # --- AI Assessment ---
    console.print("\n[bold magenta]AI Assessment[/]  [dim](streaming from Claude…)[/]\n")
    console.rule(style="magenta")
    assessment_text = assessment.get_ai_assessment(
        traffic_data, bypass_data, rec_data, device_map=device_map,
        metrics_data=metrics_data, firewall_data=firewall_data,
        fail2ban_data=fail2ban_data, correlation_report=correlation_report,
    )
    console.rule(style="magenta")
    console.print(
        Panel(
            "[dim]Assessment complete. See above for full analysis.[/]",
            border_style="magenta",
            title="[bold magenta]Claude AI Assessment[/]",
        )
    )

    # --- Interactive Conversation ---
    chat_history = conversation.start_conversation(
        traffic_data, bypass_data, rec_data, device_map, assessment_text,
        metrics_data=metrics_data, firewall_data=firewall_data,
        fail2ban_data=fail2ban_data, correlation_report=correlation_report,
    )

    # --- HTML Report (generated after conversation so transcript can be included) ---
    out = report.render_html(
        traffic_data, bypass_data, rec_data,
        client_names=client_names,
        assessment_text=assessment_text,
        device_map=device_map,
        risk_summary=risk_summary,
        chat_history=chat_history,
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
