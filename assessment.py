"""Module 4: AI Security & Privacy Assessment via Claude API.

Packages findings from all audit modules into a structured prompt,
streams the response in real time, and returns the full text for the report.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from bypass import BypassData
from device_identifier import DeviceInfo, NetworkRiskSummary, network_risk_summary
from recommender import RecommenderData
from traffic import TrafficData

load_dotenv()

MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 4000


# ---------------------------------------------------------------------------
# Pi-hole / DNS section builders
# ---------------------------------------------------------------------------

def _build_findings_summary(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
) -> str:
    s = traffic_data.summary
    lines: list[str] = []

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


def _build_device_summary(device_map: dict[str, DeviceInfo]) -> str:
    lines: list[str] = []
    lines.append("\n=== DEVICE INVENTORY ===")
    risk_summary = network_risk_summary(device_map)
    lines.append(
        f"Total devices: {risk_summary.total_devices}  "
        f"(identified: {risk_summary.identified}, unknown: {risk_summary.unknown}, "
        f"manual: {risk_summary.manual})"
    )
    lines.append(
        f"Privacy risk breakdown — high: {risk_summary.high_risk}, "
        f"medium: {risk_summary.medium_risk}, low: {risk_summary.low_risk}, "
        f"minimal: {risk_summary.minimal_risk}"
    )
    lines.append(f"Overall network privacy risk: {risk_summary.overall_risk.upper()}")
    lines.append("")

    sorted_devices = sorted(
        device_map.values(),
        key=lambda d: ({"high": 0, "medium": 1, "low": 2, "minimal": 3}.get(d.privacy_risk, 4), d.ip),
    )
    for info in sorted_devices:
        label = info.hostname if info.hostname != info.ip else info.ip
        conf_str = "manual override" if info.manual_override else f"{info.confidence:.0%} confidence"
        alts = ""
        if info.alternatives:
            alts = "  [alt: " + ", ".join(f"{t} ({c:.0%})" for t, c in info.alternatives) + "]"
        lines.append(
            f"  {info.ip} ({label}): {info.device_type}  "
            f"[{conf_str}]  risk={info.privacy_risk}{alts}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# New data source section builders
# ---------------------------------------------------------------------------

def _build_metrics_summary(metrics_data) -> str:
    if metrics_data is None:
        return ""
    lines = ["\n=== SYSTEM METRICS (Prometheus) ==="]
    if metrics_data.errors:
        for e in metrics_data.errors:
            lines.append(f"  [error] {e}")
    for h in sorted(metrics_data.hosts, key=lambda x: x.name):
        status = "UP" if h.up else "DOWN"
        cpu  = f"{h.cpu_pct:.1f}%"  if h.cpu_pct  is not None else "n/a"
        ram  = f"{h.ram_pct:.1f}%"  if h.ram_pct  is not None else "n/a"
        disk = f"{h.disk_pct:.1f}%" if h.disk_pct is not None else "n/a"
        net_in  = _fmt_bps(h.net_in_bps)  if h.net_in_bps  is not None else "n/a"
        net_out = _fmt_bps(h.net_out_bps) if h.net_out_bps is not None else "n/a"
        lines.append(
            f"  {h.name} ({h.ip}) [{status}] "
            f"CPU={cpu} RAM={ram} Disk={disk} "
            f"NetIn={net_in} NetOut={net_out}"
        )
    return "\n".join(lines)


def _build_firewall_summary(firewall_data) -> str:
    if firewall_data is None:
        return ""
    lines = ["\n=== FIREWALL / SURICATA (OPNsense) ==="]
    if firewall_data.errors:
        for e in firewall_data.errors:
            lines.append(f"  [error] {e}")

    lines.append(f"Firewall blocks (recent sample): {firewall_data.block_count}")
    if firewall_data.top_blocked_ips:
        lines.append("Top blocked source IPs:")
        for item in firewall_data.top_blocked_ips[:10]:
            lines.append(f"  {item['ip']}: {item['count']} blocks")

    lines.append(f"Suricata alerts: {firewall_data.alert_count} total")
    if firewall_data.suricata_alerts:
        sev_map = {1: "HIGH", 2: "MED", 3: "LOW"}
        lines.append("Recent Suricata alerts:")
        for a in firewall_data.suricata_alerts[:15]:
            sev = sev_map.get(a.severity, str(a.severity))
            lines.append(
                f"  [{sev}] {a.timestamp} | {a.alert} | "
                f"{a.src_ip} → {a.dst_ip} | cat={a.category}"
            )
    return "\n".join(lines)


def _build_fail2ban_summary(fail2ban_data) -> str:
    if fail2ban_data is None:
        return ""
    lines = ["\n=== FAIL2BAN STATUS (all containers) ==="]
    if fail2ban_data.errors:
        for e in fail2ban_data.errors:
            lines.append(f"  [error] {e}")

    lines.append(
        f"Total currently banned: {fail2ban_data.total_banned}  "
        f"Total jails: {fail2ban_data.total_jails}"
    )
    for ct in sorted(fail2ban_data.containers, key=lambda x: x.label):
        if ct.error:
            lines.append(f"  {ct.label} ({ct.ct_id}): ERROR — {ct.error}")
        else:
            jails_str = ", ".join(ct.jails) if ct.jails else "none"
            lines.append(
                f"  {ct.label} ({ct.ct_id}): jails=[{jails_str}] "
                f"banned_now={ct.currently_banned} total_bans={ct.total_bans}"
            )
            if ct.banned_ips:
                lines.append(f"    Active bans: {', '.join(ct.banned_ips[:10])}")
    return "\n".join(lines)


def _fmt_bps(bps: float) -> str:
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.1f}MB/s"
    if bps >= 1_000:
        return f"{bps/1_000:.0f}KB/s"
    return f"{bps:.0f}B/s"


# ---------------------------------------------------------------------------
# Historical report compression
# ---------------------------------------------------------------------------

def _compress_historical_report(report: dict) -> str:
    """Distil a stored report down to one compact block of key metrics."""
    lines = [f"[{report.get('created_at', 'unknown')}]"]

    # DNS / traffic
    s = (report.get("traffic_data") or {}).get("summary") or {}
    if s:
        lines.append(
            f"  DNS: {s.get('total', 0):,} queries  "
            f"{s.get('percent_blocked', 0):.1f}% blocked  "
            f"{s.get('unique_domains', 0):,} unique domains  "
            f"{s.get('active_clients', 0)} active clients"
        )

    # Bypass & recommendations
    bypass_count = len((report.get("bypass_data") or {}).get("findings") or [])
    rec_count = len((report.get("rec_data") or {}).get("recommendations") or [])
    lines.append(f"  Bypass findings: {bypass_count}  Blocklist recommendations: {rec_count}")

    # Network risk
    rs = report.get("risk_summary") or {}
    if rs:
        lines.append(
            f"  Network risk: {rs.get('overall_risk', 'unknown')}  "
            f"high={rs.get('high_risk', 0)} medium={rs.get('medium_risk', 0)} "
            f"low={rs.get('low_risk', 0)} minimal={rs.get('minimal_risk', 0)}"
        )

    # System metrics (per host)
    md = report.get("metrics_data") or {}
    for h in md.get("hosts") or []:
        cpu  = h.get("cpu_pct")
        ram  = h.get("ram_pct")
        disk = h.get("disk_pct")
        status = "UP" if h.get("up") else "DOWN"
        cpu_s  = f"{cpu:.1f}%"  if cpu  is not None else "n/a"
        ram_s  = f"{ram:.1f}%"  if ram  is not None else "n/a"
        disk_s = f"{disk:.1f}%" if disk is not None else "n/a"
        lines.append(
            f"  {h.get('name', '?')} [{status}]: CPU={cpu_s} RAM={ram_s} Disk={disk_s}"
        )

    # Firewall / Suricata
    fd = report.get("firewall_data") or {}
    if fd:
        lines.append(
            f"  Firewall: {fd.get('block_count', 0)} blocks  "
            f"Suricata: {fd.get('alert_count', 0)} alerts"
        )

    # Fail2ban
    f2b = report.get("fail2ban_data") or {}
    if f2b:
        lines.append(
            f"  Fail2ban: {f2b.get('total_banned', 0)} banned  "
            f"{f2b.get('total_jails', 0)} jails"
        )

    return "\n".join(lines)


def load_historical_context(reports_dir: str | Path, n: int = 5) -> str | None:
    """Load and compress the last *n* saved reports for longitudinal context.

    Returns a compact multi-report string, or None if no prior reports exist.
    The current (in-progress) report has not been saved yet, so the most
    recent file on disk is the previous run.
    """
    rdir = Path(reports_dir)
    if not rdir.exists():
        return None

    paths = sorted(rdir.glob("*.json"), key=lambda p: p.name, reverse=True)[:n]
    if not paths:
        return None

    summaries: list[str] = []
    for path in reversed(paths):  # oldest → newest for readability
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            summaries.append(_compress_historical_report(report))
        except Exception:
            continue

    return "\n\n".join(summaries) if summaries else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_audit_context(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
    device_map: dict[str, DeviceInfo] | None = None,
    metrics_data=None,
    firewall_data=None,
    fail2ban_data=None,
) -> str:
    """Return the full audit data as a plain-text string for embedding in prompts."""
    findings = _build_findings_summary(traffic_data, bypass_data, rec_data)
    if device_map:
        findings += _build_device_summary(device_map)
    findings += _build_metrics_summary(metrics_data)
    findings += _build_firewall_summary(firewall_data)
    findings += _build_fail2ban_summary(fail2ban_data)
    return findings


def get_ai_assessment(
    traffic_data: TrafficData,
    bypass_data: BypassData,
    rec_data: RecommenderData,
    device_map: dict[str, DeviceInfo] | None = None,
    metrics_data=None,
    firewall_data=None,
    fail2ban_data=None,
    historical_context: str | None = None,
) -> str:
    """Stream a holistic AI security assessment from Claude and return the full text."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "AI assessment skipped — ANTHROPIC_API_KEY not set in .env."

    findings = build_audit_context(
        traffic_data, bypass_data, rec_data, device_map,
        metrics_data, firewall_data, fail2ban_data,
    )

    has_metrics  = metrics_data  is not None and not getattr(metrics_data,  "errors", True)
    has_firewall = firewall_data is not None
    has_fail2ban = fail2ban_data is not None
    has_history  = bool(historical_context)

    system_prompt = (
        "You are a network security and privacy analyst for a technically advanced home lab. "
        "The operator runs OPNsense, Proxmox, Pi-hole, Suricata IDS, fail2ban, and "
        "self-hosted services (Jellyfin, Immich, Nextcloud, Audiobookshelf, Traefik). "
        "They are privacy-focused and want specific, actionable advice — not generic tips. "
        "Reference actual IPs, domains, counts, and container names from the data. "
        "Be direct and concise. Do not pad your response."
    )

    # Build data-aware prompt sections
    data_sections = ["DNS/Pi-hole audit data, device inventory"]
    if has_metrics:
        data_sections.append("Prometheus system metrics for all hosts")
    if has_firewall:
        data_sections.append("OPNsense firewall logs and Suricata IDS alerts")
    if has_fail2ban:
        data_sections.append("fail2ban status across all containers")

    # --- Executive summary instruction ---
    exec_summary_instruction = (
        "Begin your response with a HOLISTIC EXECUTIVE SUMMARY — 4 to 5 plain sentences, "
        "no header, no bullet points. Cover: (1) overall lab health state in one sentence, "
        "(2) the single most important thing requiring attention right now, "
        "(3) something working well or a positive trend, "
        "(4) a general risk posture statement. "
        "This summary must stand alone — readable in 30 seconds without seeing the rest.\n\n"
    )

    # --- Trends & Foresight instruction (only when history is present) ---
    if has_history:
        trends_instruction = (
            "5. **Trends & Foresight** — Using the historical report data provided, identify: "
            "growing or shrinking patterns (disk usage, query volumes, ban counts, alert rates), "
            "issues that have persisted across multiple reports (chronic vs one-time), "
            "forward-looking predictions with rough timelines (\"at this rate, X in ~N days\"), "
            "improvements since the previous report, "
            "and whether issues in sections 1–4 are new or recurring. "
            "Be specific — cite actual numbers from the history.\n\n"
        )
        history_block = (
            "=== HISTORICAL REPORT DATA (last reports, oldest → newest) ===\n"
            f"{historical_context}\n"
        )
    else:
        trends_instruction = ""
        history_block = ""

    user_prompt = (
        f"{exec_summary_instruction}"
        f"Below is data from my LiquidLab network intelligence platform, "
        f"covering: {', '.join(data_sections)}.\n\n"
        "Please analyze holistically and provide:\n\n"
        "1. **Overall Security Posture** — What is the current state? "
        "What stands out most as a risk or concern?\n\n"
        "2. **Priority Actions** — List in order: Critical / Warning / Info. "
        "For each: exact steps, referencing specific IPs, containers, and counts.\n\n"
        "3. **Cross-Source Correlations** — Are any IPs appearing in multiple "
        "data sources (e.g. same IP in Suricata + fail2ban + DNS)? "
        "Are there container health concerns (high CPU/RAM) that need attention? "
        "Are there DNS patterns that correlate with firewall events?\n\n"
        "4. **Domains to Block First** — From flagged DNS recommendations, "
        "which should be added to Pi-hole immediately and why?\n\n"
        f"{trends_instruction}"
        "---\n\n"
        f"{findings}\n\n"
        f"{history_block}"
    )

    client = anthropic.Anthropic(api_key=api_key)
    full_text: list[str] = []

    with client.messages.stream(
        model=MODEL,
        max_tokens=_MAX_TOKENS,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        for chunk in stream.text_stream:
            print(chunk, end="", flush=True)
            full_text.append(chunk)

    print()
    return "".join(full_text)
