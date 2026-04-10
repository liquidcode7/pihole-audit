"""Module 4: AI Security & Privacy Assessment via Claude API.

Packages findings from the three audit modules into a structured prompt,
streams the response in real time, and returns the full text for the HTML report.
"""

from __future__ import annotations

import os

import anthropic
from dotenv import load_dotenv

from bypass import BypassData
from recommender import RecommenderData
from traffic import TrafficData

load_dotenv()

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 1500


def _build_findings_summary(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
) -> str:
    s = traffic_data.summary
    lines: list[str] = []

    # --- Traffic summary ---
    lines.append("=== TRAFFIC SUMMARY ===")
    lines.append(f"Total queries: {s.total:,}")
    lines.append(f"Blocked: {s.blocked:,} ({s.percent_blocked:.1f}%)")
    lines.append(f"Allowed: {s.allowed:,}")
    lines.append(f"Cached: {s.cached:,}")
    lines.append(f"Forwarded: {s.forwarded:,}")
    lines.append(f"Unique domains: {s.unique_domains:,}")
    lines.append(f"Active clients: {s.active_clients} / {s.total_clients} total")
    lines.append(f"Gravity list size: {s.gravity_domains:,} domains")

    lines.append("\n=== TOP ALLOWED DOMAINS (top 10) ===")
    for d in traffic_data.top_allowed[:10]:
        lines.append(f"  {d.domain}: {d.count:,} queries")

    lines.append("\n=== TOP BLOCKED DOMAINS (top 10) ===")
    for d in traffic_data.top_blocked[:10]:
        lines.append(f"  {d.domain}: {d.count:,} queries")

    lines.append("\n=== TOP CLIENTS (top 10) ===")
    for c in traffic_data.top_clients[:10]:
        label = f"{c.name} ({c.client})" if c.name != c.client else c.client
        lines.append(f"  {label}: {c.count:,} queries")

    # --- Bypass detection ---
    lines.append(f"\n=== DNS BYPASS DETECTION ({bypass_data.queries_scanned:,} queries scanned) ===")
    if not bypass_data.findings:
        lines.append("  No bypass indicators detected.")
    else:
        doh = [f for f in bypass_data.findings if f.method == "doh_lookup"]
        ptr = [f for f in bypass_data.findings if f.method == "ptr_lookup"]
        low = [f for f in bypass_data.findings if f.method == "low_query_count"]

        if doh:
            lines.append(f"DoH/DoT lookup attempts ({len(doh)} finding(s)):")
            for f in doh:
                lines.append(f"  {f.client_ip} → {f.detail} ({f.count} hits)")

        if ptr:
            lines.append(f"PTR lookups for public DNS IPs ({len(ptr)} finding(s)):")
            for f in ptr:
                lines.append(f"  {f.client_ip} → {f.detail} ({f.count} hits)")

        if low:
            lines.append(f"Low query count (potential bypass) ({len(low)} client(s)):")
            for f in low:
                lines.append(f"  {f.client_ip}: {f.count} queries — {f.detail}")

    # --- Blocklist recommendations ---
    lines.append(f"\n=== BLOCKLIST RECOMMENDATIONS ({rec_data.queries_scanned:,} allowed queries scanned) ===")
    if not rec_data.recommendations:
        lines.append("  No known tracking/ad domains found in allowed queries.")
    else:
        lines.append(f"Found {len(rec_data.recommendations)} domains across {len(rec_data.by_category)} categories:\n")
        for category, recs in sorted(rec_data.by_category.items()):
            lines.append(f"{category} ({len(recs)} domain(s)):")
            for r in recs[:10]:
                clients_str = ", ".join(r.clients[:3])
                lines.append(f"  {r.domain}: {r.count:,} queries  [clients: {clients_str}]")
            if len(recs) > 10:
                lines.append(f"  ... and {len(recs) - 10} more")

    return "\n".join(lines)


def get_ai_assessment(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
) -> str:
    """Stream an AI security assessment from Claude and return the full text.

    Prints each token to stdout in real time as the response streams in.
    Returns the complete assessment text for inclusion in the HTML report.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "AI assessment skipped — ANTHROPIC_API_KEY not set in .env."

    findings = _build_findings_summary(traffic_data, bypass_data, rec_data)

    system_prompt = (
        "You are a network security and privacy analyst. The user is a technically "
        "advanced home-lab operator who runs their own infrastructure: OPNsense firewall, "
        "Proxmox hypervisor, Pi-hole DNS filter, and various self-hosted services. "
        "They are privacy-focused and want specific, actionable advice — not generic tips. "
        "Reference actual IPs, domains, and counts from the data they provide. "
        "Be direct and concise. Do not pad your response."
    )

    user_prompt = (
        "Below is the output from a Pi-hole DNS audit run against my network. "
        "Please provide:\n\n"
        "1. **Overall Assessment** — What is the current privacy/security posture? "
        "What stands out most?\n\n"
        "2. **Top 3 Priority Actions** — For each, give the exact steps I should take "
        "(Pi-hole settings, blocklist URLs, firewall rules, etc.). "
        "Reference specific IPs, domains, and counts from the data.\n\n"
        "3. **Notable Patterns** — Any interesting correlations, unusual traffic, or "
        "trends in the data worth investigating further.\n\n"
        "4. **Domains to Block First** — From the flagged domains in the recommendations, "
        "which should I add to my blocklist immediately and why? Give a prioritized list.\n\n"
        "---\n\n"
        f"{findings}"
    )

    client = anthropic.Anthropic(api_key=api_key)
    full_text: list[str] = []

    with client.messages.stream(
        model=_MODEL,
        max_tokens=_MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        for chunk in stream.text_stream:
            print(chunk, end="", flush=True)
            full_text.append(chunk)

    print()  # newline after streaming completes
    return "".join(full_text)
