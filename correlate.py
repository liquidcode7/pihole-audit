"""Cross-source IP threat correlation.

Joins findings from all data sources to identify IPs that appear in
multiple places simultaneously — these are the highest-confidence threats
rather than suspicions from a single data source.
"""

from __future__ import annotations

import dataclasses
from typing import Literal


# Severity is determined by how many and which sources flag an IP.
# appearing in 3+ sources = critical, 2 sources = warning, 1 = info
SeverityLevel = Literal["critical", "warning", "info"]


@dataclasses.dataclass
class CorrelatedThreat:
    ip: str
    sources: list[str]          # which data sources flagged this IP
    details: list[str]          # human-readable detail per source
    severity: SeverityLevel     # derived from source count + source type
    internal: bool              # True = LAN IP (possible compromised device)


@dataclasses.dataclass
class CorrelationReport:
    threats: list[CorrelatedThreat]
    total_ips_analyzed: int     # unique IPs seen across all sources
    source_counts: dict[str, int]  # how many IPs each source contributed


def _severity(sources: list[str], internal: bool) -> SeverityLevel:
    """Derive severity from number of sources and whether the IP is internal."""
    count = len(sources)
    if count >= 3:
        return "critical"
    if count == 2:
        # Two external sources = warning; any internal = critical
        return "critical" if internal else "warning"
    # Single source
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
    suricata_data=None,  # pulled from firewall_data
) -> CorrelationReport:
    """Build a CorrelationReport by joining IPs across all available sources.

    Sources considered:
    - bypass: IPs flagged as DNS bypass suspects (DoH/DoT lookups or low query count)
    - firewall: OPNsense top-blocked source IPs
    - suricata: Suricata alert source IPs
    - fail2ban: IPs currently banned in any container
    """

    # Collect IPs per source with details
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

        # Also pull Suricata alert source IPs from firewall_data
        for alert in getattr(firewall_data, "suricata_alerts", []) or []:
            ip = getattr(alert, "src_ip", "")
            if ip:
                sev_labels = {1: "HIGH", 2: "MED", 3: "LOW"}
                sev = sev_labels.get(getattr(alert, "severity", 3), "?")
                msg = getattr(alert, "alert", "IDS alert")
                source_map["suricata"].setdefault(ip, []).append(
                    f"[{sev}] {msg}"
                )

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
        severity = _severity(present_sources, internal)

        threats.append(CorrelatedThreat(
            ip=ip,
            sources=present_sources,
            details=details,
            severity=severity,
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
    )
