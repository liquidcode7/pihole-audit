"""Module 2: DNS Bypass Detection.

Two detection methods:
1. Query log scan for DoH/DoT provider domains and PTR lookups for public DNS IPs.
   Devices querying dns.google, cloudflare-dns.com etc. are setting up encrypted
   DNS tunnels that bypass Pi-hole filtering.
2. Low query count heuristic - active network clients with far fewer queries than
   the network average are likely sending DNS traffic elsewhere.
"""

from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from client import PUBLIC_DNS_IPS, PiholeClient

# ---------------------------------------------------------------------------
# DoH / DoT provider hostnames
# ---------------------------------------------------------------------------

DOH_INDICATORS: dict[str, str] = {
    "dns.google":                        "Google DoH/DoT",
    "dns64.dns.google":                  "Google DoH/DoT (IPv6)",
    "cloudflare-dns.com":                "Cloudflare DoH",
    "mozilla.cloudflare-dns.com":        "Firefox/Mozilla DoH",
    "1dot1dot1dot1.cloudflare-dns.com":  "Cloudflare DoH",
    "dns.quad9.net":                     "Quad9 DoH",
    "dns9.quad9.net":                    "Quad9 DoH",
    "doh.opendns.com":                   "OpenDNS DoH",
    "doh.familyshield.opendns.com":      "OpenDNS FamilyShield DoH",
    "dns.nextdns.io":                    "NextDNS DoH",
    "doh.cleanbrowsing.org":             "CleanBrowsing DoH",
    "doh.dns.sb":                        "DNS.SB DoH",
    "dns.adguard-dns.com":               "AdGuard DoH",
    "unfiltered.adguard-dns.com":        "AdGuard DoH (unfiltered)",
}

# PTR query suffixes for known public DNS IPs
# e.g. "8.8.8.8.in-addr.arpa" means something is reverse-resolving 8.8.8.8
_PTR_SUFFIXES: dict[str, str] = {
    "{}.in-addr.arpa".format(".".join(reversed(ip.split(".")))): f"PTR lookup for {label} ({ip})"
    for ip, label in [
        ("8.8.8.8",         "Google DNS"),
        ("8.8.4.4",         "Google DNS"),
        ("1.1.1.1",         "Cloudflare DNS"),
        ("1.0.0.1",         "Cloudflare DNS"),
        ("9.9.9.9",         "Quad9 DNS"),
        ("208.67.222.222",  "OpenDNS"),
        ("208.67.220.220",  "OpenDNS"),
    ]
}

# Fraction of network-average queries below which a client is flagged
LOW_QUERY_THRESHOLD = 0.10

# IPs never flagged for low query count (routers, gateways, localhost).
# Extend via PIHOLE_BYPASS_IGNORE_IPS=192.168.1.1,10.0.0.1 in .env
_DEFAULT_IGNORE_IPS: frozenset[str] = frozenset({"192.168.1.1", "127.0.0.1", "::1"})

def _ignore_ips() -> frozenset[str]:
    extra = {
        ip.strip()
        for ip in os.environ.get("PIHOLE_BYPASS_IGNORE_IPS", "").split(",")
        if ip.strip()
    }
    return _DEFAULT_IGNORE_IPS | extra


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BypassFinding:
    client_ip: str
    method: str    # "doh_lookup" | "ptr_lookup" | "low_query_count"
    detail: str    # human-readable explanation
    count: int     # occurrences


@dataclass
class ClientQueryStat:
    ip: str
    name: str              # hostname if known, else same as ip
    query_count: int
    pct_of_average: float  # 1.0 = exactly average
    flagged: bool


@dataclass
class BypassData:
    findings: list[BypassFinding]
    client_stats: list[ClientQueryStat]
    queries_scanned: int


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def fetch(
    client: PiholeClient,
    max_queries: int = 5_000,
    top_clients_n: int = 100,
    client_names: dict[str, str] | None = None,
) -> BypassData:
    queries, clients_raw = await asyncio.gather(
        _fetch_queries(client, max_queries),
        client.get("/api/stats/top_clients", count=top_clients_n, blocked=False),
    )

    findings = _detect_doh_and_ptr(queries)
    client_stats = _detect_low_query_clients(clients_raw, client_names or {})

    for stat in client_stats:
        if stat.flagged:
            findings.append(BypassFinding(
                client_ip=stat.ip,
                method="low_query_count",
                detail=(
                    f"Only {stat.query_count} queries "
                    f"({stat.pct_of_average:.0%} of network average) - "
                    "may be using hardcoded DNS"
                ),
                count=stat.query_count,
            ))

    findings.sort(key=lambda f: f.count, reverse=True)

    return BypassData(
        findings=findings,
        client_stats=client_stats,
        queries_scanned=len(queries),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _fetch_queries(client: PiholeClient, max_queries: int) -> list[dict[str, Any]]:
    """Paginate /api/queries newest-first until we have max_queries records."""
    collected: list[dict[str, Any]] = []
    cursor: int | None = None

    while len(collected) < max_queries:
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor

        page = await client.get("/api/queries", **params)
        batch: list[dict[str, Any]] = page.get("queries", [])
        if not batch:
            break

        collected.extend(batch)

        # To paginate older records, pass the ID just below the oldest on this page
        oldest_id: int = batch[-1]["id"]
        if oldest_id <= 1:
            break
        cursor = oldest_id - 1

    return collected[:max_queries]


def _detect_doh_and_ptr(queries: list[dict[str, Any]]) -> list[BypassFinding]:
    doh_hits: dict[tuple[str, str, str], int] = defaultdict(int)
    ptr_hits: dict[tuple[str, str, str], int] = defaultdict(int)

    for q in queries:
        domain = q.get("domain", "").lower()
        client_ip = q.get("client", {}).get("ip", "unknown")

        for indicator, label in DOH_INDICATORS.items():
            if domain == indicator or domain.endswith("." + indicator):
                doh_hits[(client_ip, "doh_lookup", label)] += 1
                break

        for suffix, label in _PTR_SUFFIXES.items():
            if domain == suffix:
                ptr_hits[(client_ip, "ptr_lookup", label)] += 1
                break

    findings: list[BypassFinding] = []
    for (ip, method, detail), count in {**doh_hits, **ptr_hits}.items():
        findings.append(BypassFinding(client_ip=ip, method=method, detail=detail, count=count))
    return findings


def _detect_low_query_clients(
    raw: dict[str, Any],
    client_names: dict[str, str],
) -> list[ClientQueryStat]:
    items: list[dict[str, Any]] = raw.get("clients", [])
    if not items:
        return []

    ignore = _ignore_ips()
    counts = [(item["ip"], item["count"]) for item in items]
    average = sum(c for _, c in counts) / len(counts)

    stats: list[ClientQueryStat] = []
    for ip, count in sorted(counts, key=lambda x: x[1], reverse=True):
        pct = count / average if average > 0 else 0.0
        name = client_names.get(ip) or ip
        stats.append(ClientQueryStat(
            ip=ip,
            name=name,
            query_count=count,
            pct_of_average=pct,
            flagged=(pct < LOW_QUERY_THRESHOLD and ip not in ignore),
        ))
    return stats
