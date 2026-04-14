"""Cross-source IP threat correlation with reputation enrichment.

Joins findings from all data sources to identify IPs that appear in
multiple places simultaneously — these are the highest-confidence threats
rather than suspicions from a single data source.

Reputation enrichment (AbuseIPDB + CrowdSec CTI) runs as a post-pass
after the correlation report is built. Set ABUSEIPDB_API_KEY and/or
CROWDSEC_API_KEY in .env to enable each.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Literal

import httpx
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
CROWDSEC_API_KEY  = os.environ.get("CROWDSEC_API_KEY", "")

# Severity is determined by how many and which sources flag an IP.
SeverityLevel = Literal["critical", "warning", "info"]


@dataclasses.dataclass
class IPReputation:
    """Reputation data from external threat intelligence services."""
    abuse_score: int | None = None          # AbuseIPDB confidence score 0-100
    abuse_categories: list[str] = dataclasses.field(default_factory=list)
    abuse_reports: int | None = None        # total reports in AbuseIPDB
    crowdsec_score: str | None = None       # "low" / "medium" / "high" / "aggressive"
    crowdsec_behaviors: list[str] = dataclasses.field(default_factory=list)
    crowdsec_community_reports: int | None = None  # # of installations flagging this IP today


@dataclasses.dataclass
class CorrelatedThreat:
    ip: str
    sources: list[str]          # which data sources flagged this IP
    details: list[str]          # human-readable detail per source
    severity: SeverityLevel     # derived from source count + source type
    internal: bool              # True = LAN IP (possible compromised device)
    reputation: IPReputation | None = None


@dataclasses.dataclass
class CorrelationReport:
    threats: list[CorrelatedThreat]
    total_ips_analyzed: int
    source_counts: dict[str, int]
    urlhaus_hits: list = dataclasses.field(default_factory=list)  # list[URLhausHit]


def _severity(sources: list[str], internal: bool) -> SeverityLevel:
    """Derive severity from number of sources and whether the IP is internal."""
    count = len(sources)
    if count >= 3:
        return "critical"
    if count == 2:
        return "critical" if internal else "warning"
    if internal and "bypass" in sources:
        return "warning"
    return "info"


def _is_internal(ip: str) -> bool:
    """Quick RFC-1918 + loopback check."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
        )
    except Exception:
        return False


def correlate(
    bypass_data=None,
    firewall_data=None,
    fail2ban_data=None,
    suricata_data=None,   # pulled from firewall_data
    urlhaus_data=None,
) -> CorrelationReport:
    """Build a CorrelationReport by joining IPs across all available sources.

    Sources considered:
    - bypass:   IPs flagged as DNS bypass suspects
    - firewall: OPNsense top-blocked source IPs
    - suricata: Suricata alert source IPs (via firewall_data)
    - fail2ban: IPs currently banned in any container

    URLhaus domain hits are attached to the report but are domain-based,
    not IP-based, so they don't participate in IP correlation.
    """
    source_map: dict[str, dict[str, list[str]]] = {
        "bypass":   {},
        "firewall": {},
        "suricata": {},
        "fail2ban": {},
    }

    # --- Bypass suspects ---
    if bypass_data is not None:
        for f in getattr(bypass_data, "findings", []):
            ip = f.client_ip
            method_labels = {
                "doh_lookup":      "queried DoH/DoT provider hostname",
                "ptr_lookup":      "PTR lookup to public DNS resolver",
                "low_query_count": "suspiciously low query count (possible hardcoded DNS)",
            }
            detail = method_labels.get(f.method, f.method)
            if f.detail:
                detail += f": {f.detail}"
            source_map["bypass"].setdefault(ip, []).append(detail)

    # --- Firewall top blocked IPs ---
    if firewall_data is not None:
        for item in getattr(firewall_data, "top_blocked_ips", []) or []:
            ip = item.get("ip", "") if isinstance(item, dict) else getattr(item, "ip", "")
            count = item.get("count", 0) if isinstance(item, dict) else getattr(item, "count", 0)
            if ip:
                source_map["firewall"].setdefault(ip, []).append(
                    f"OPNsense blocked {count} times"
                )

        # Suricata alert source IPs come via firewall_data
        for alert in getattr(firewall_data, "suricata_alerts", []) or []:
            ip = getattr(alert, "src_ip", "")
            if ip:
                sev_labels = {1: "HIGH", 2: "MED", 3: "LOW"}
                sev = sev_labels.get(getattr(alert, "severity", 3), "?")
                msg = getattr(alert, "alert", "IDS alert")
                source_map["suricata"].setdefault(ip, []).append(f"[{sev}] {msg}")

    # --- fail2ban banned IPs ---
    if fail2ban_data is not None:
        for ct in getattr(fail2ban_data, "containers", []) or []:
            for ip in getattr(ct, "banned_ips", []) or []:
                source_map["fail2ban"].setdefault(ip, []).append(
                    f"banned in {ct.label} ({', '.join(ct.jails or ['?'])})"
                )

    # Gather all unique IPs
    all_ips: set[str] = set()
    for src_ips in source_map.values():
        all_ips.update(src_ips.keys())

    # Build correlation entries for IPs appearing in 2+ sources
    threats: list[CorrelatedThreat] = []
    for ip in sorted(all_ips):
        present_sources = [src for src, ips in source_map.items() if ip in ips]
        if len(present_sources) < 2:
            continue

        details: list[str] = []
        for src in present_sources:
            for d in source_map[src][ip]:
                details.append(f"[{src}] {d}")

        internal = _is_internal(ip)
        threats.append(CorrelatedThreat(
            ip=ip,
            sources=present_sources,
            details=details,
            severity=_severity(present_sources, internal),
            internal=internal,
        ))

    # Sort: critical first, then by number of sources desc, then by IP
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    threats.sort(key=lambda t: (severity_order[t.severity], -len(t.sources), t.ip))

    source_counts = {src: len(ips) for src, ips in source_map.items()}

    return CorrelationReport(
        threats=threats,
        total_ips_analyzed=len(all_ips),
        source_counts=source_counts,
        urlhaus_hits=getattr(urlhaus_data, "hits", []) if urlhaus_data else [],
    )


# ---------------------------------------------------------------------------
# Reputation enrichment — AbuseIPDB + CrowdSec CTI
# ---------------------------------------------------------------------------

_ABUSEIPDB_CATEGORIES = {
    1: "DNS compromise", 2: "DNS poisoning", 3: "Fraud orders",
    4: "DDoS attack", 5: "FTP brute-force", 6: "Ping of death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open proxy", 10: "Web spam",
    11: "Email spam", 12: "Blog spam", 13: "VPN IP", 14: "Port scan",
    15: "Hacking", 16: "SQL injection", 17: "Spoofing", 18: "Brute-force",
    19: "Bad web bot", 20: "Exploited host", 21: "Web app attack",
    22: "SSH brute-force", 23: "IoT targeted",
}


async def enrich_reputation(report: CorrelationReport) -> None:
    """Enrich each CorrelatedThreat in-place with AbuseIPDB and CrowdSec data.

    Only external IPs are checked (internal IPs won't be in either database).
    Runs both services concurrently per IP to minimise wall-clock time.
    """
    if not ABUSEIPDB_API_KEY and not CROWDSEC_API_KEY:
        return

    import asyncio

    external_threats = [t for t in report.threats if not t.internal]
    if not external_threats:
        return

    async def _enrich_one(threat: CorrelatedThreat) -> None:
        tasks = []
        if ABUSEIPDB_API_KEY:
            tasks.append(_check_abuseipdb(threat.ip))
        if CROWDSEC_API_KEY:
            tasks.append(_check_crowdsec(threat.ip))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        rep = IPReputation()
        for result in results:
            if isinstance(result, dict):
                if "abuse_score" in result:
                    rep.abuse_score = result["abuse_score"]
                    rep.abuse_categories = result.get("categories", [])
                    rep.abuse_reports = result.get("total_reports")
                elif "crowdsec_score" in result:
                    rep.crowdsec_score = result["crowdsec_score"]
                    rep.crowdsec_behaviors = result.get("behaviors", [])
                    rep.crowdsec_community_reports = result.get("community_reports")
        threat.reputation = rep

    await asyncio.gather(*[_enrich_one(t) for t in external_threats], return_exceptions=True)


async def _check_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB reputation dict or empty dict on failure."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            category_ids = data.get("usageType", [])
            # Categories may come as list of ints in verbose mode
            if isinstance(category_ids, list):
                cats = [_ABUSEIPDB_CATEGORIES.get(c, str(c)) for c in category_ids]
            else:
                cats = []
            return {
                "abuse_score":   data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "categories":    cats,
            }
    except Exception:
        return {}


async def _check_crowdsec(ip: str) -> dict:
    """Return CrowdSec CTI reputation dict or empty dict on failure."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
                headers={"x-api-key": CROWDSEC_API_KEY},
            )
            if resp.status_code == 404:
                return {}   # IP not in CrowdSec DB — not necessarily bad
            resp.raise_for_status()
            data = resp.json()
            behaviors = [
                b.get("name") or b.get("label", "")
                for b in (data.get("behaviors") or [])
                if b.get("name") or b.get("label")
            ]
            scores = data.get("scores") or {}
            # overall score is under scores.overall.aggressiveness or similar
            score_str = (
                data.get("reputation")
                or (scores.get("overall") or {}).get("aggressiveness")
                or ""
            )
            community = data.get("attack_details", {})
            if isinstance(community, list):
                community_reports = len(community)
            else:
                community_reports = None
            return {
                "crowdsec_score":     str(score_str) if score_str else None,
                "behaviors":          behaviors[:5],
                "community_reports":  community_reports,
            }
    except Exception:
        return {}
