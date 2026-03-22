"""Module 3: Blocklist Recommendations.

Scans allowed (FORWARDED + CACHE) queries against known tracking, ad, telemetry,
data-broker, and IoT phone-home domain patterns to surface what you should be blocking.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from client import PiholeClient

# ---------------------------------------------------------------------------
# Category definitions — (label, [regex patterns])
# Order matters: first match wins.
# ---------------------------------------------------------------------------

CATEGORIES: list[tuple[str, list[str]]] = [
    ("Telemetry & Diagnostics", [
        # Microsoft
        r"(^|\.)telemetry\.microsoft\.com$",
        r"(^|\.)vortex\.data\.microsoft\.com$",
        r"(^|\.)settings-win\.data\.microsoft\.com$",
        r"(^|\.)watson\.telemetry\.microsoft\.com$",
        r"(^|\.)oca\.telemetry\.microsoft\.com$",
        r"(^|\.)telecommand\.telemetry\.microsoft\.com$",
        # Apple
        r"(^|\.)metrics\.apple\.com$",
        r"(^|\.)xp\.apple\.com$",
        r"(^|\.)configuration\.apple\.com$",
        # Google / Firebase / Crashlytics
        r"(^|\.)app-measurement\.com$",
        r"(^|\.)firebaselogging-pa\.googleapis\.com$",
        r"(^|\.)crashlyticsreports-pa\.googleapis\.com$",
        r"(^|\.)firebase-settings\.crashlytics\.com$",
        # Sentry / Datadog / Dynatrace
        r"(^|\.)sentry\.io$",
        r"(^|\.)ingest\.(us|eu)\.\w+\.sentry\.io$",
        r"(^|\.)datadoghq\.com$",
        r"(^|\.)dynatrace\.com$",
        r"(^|\.)bf\.\w+\.dynatrace\.com$",
        # AppsFlyer / Mixpanel / Amplitude
        r"(^|\.)appsflyersdk\.com$",
        r"(^|\.)appsflyer\.com$",
        r"(^|\.)api\.mixpanel\.com$",
        r"(^|\.)api2\.amplitude\.com$",
        r"(^|\.)cdn\.amplitude\.com$",
    ]),
    ("Ad Networks", [
        r"(^|\.)doubleclick\.net$",
        r"(^|\.)googleadservices\.com$",
        r"(^|\.)googlesyndication\.com$",
        r"(^|\.)googletagmanager\.com$",
        r"(^|\.)googletagservices\.com$",
        r"(^|\.)adnxs\.com$",           # AppNexus / Xandr
        r"(^|\.)criteo\.com$",
        r"(^|\.)criteo\.net$",
        r"(^|\.)taboola\.com$",
        r"(^|\.)outbrain\.com$",
        r"(^|\.)moatads\.com$",
        r"(^|\.)advertising\.com$",
        r"(^|\.)adform\.net$",
        r"(^|\.)adroll\.com$",
        r"(^|\.)rubiconproject\.com$",
        r"(^|\.)pubmatic\.com$",
        r"(^|\.)openx\.net$",
        r"(^|\.)smartadserver\.com$",
        r"(^|\.)lijit\.com$",
        r"(^|\.)indexww\.com$",         # Index Exchange
        r"(^|\.)casalemedia\.com$",
        r"(^|\.)triplelift\.com$",
        r"(^|\.)sharethrough\.com$",
        r"(^|\.)media\.net$",
        r"(^|\.)yieldmo\.com$",
        r"(^|\.)contextweb\.com$",
        r"(^|\.)conversantmedia\.com$",
        r"(^|\.)undertone\.com$",
    ]),
    ("Data Brokers", [
        r"(^|\.)acxiom\.com$",
        r"(^|\.)liveramp\.com$",
        r"(^|\.)datalogix\.com$",
        r"(^|\.)lotame\.com$",
        r"(^|\.)bluekai\.com$",
        r"(^|\.)kruxdigital\.com$",
        r"(^|\.)addthis\.com$",
        r"(^|\.)scorecardresearch\.com$",
        r"(^|\.)comscore\.com$",
        r"(^|\.)quantserve\.com$",
        r"(^|\.)quantcount\.com$",
        r"(^|\.)exactag\.com$",
        r"(^|\.)experian\.com$",
        r"(^|\.)epsilon\.com$",
        r"(^|\.)neustar\.biz$",
        r"(^|\.)adsymptotic\.com$",
    ]),
    ("Fingerprinting", [
        r"(^|\.)fingerprintjs\.com$",
        r"(^|\.)fpjs\.pro$",
        r"(^|\.)threatmetrix\.com$",
        r"(^|\.)iovation\.com$",
        r"(^|\.)signifyd\.com$",
        r"(^|\.)forter\.com$",
        r"(^|\.)kaptcha\.com$",
        r"(^|\.)deviceatlas\.com$",
    ]),
    ("Tracking & Analytics", [
        r"(^|\.)segment\.io$",
        r"(^|\.)segment\.com$",
        r"(^|\.)heapanalytics\.com$",
        r"(^|\.)fullstory\.com$",
        r"(^|\.)hotjar\.com$",
        r"(^|\.)clarity\.ms$",          # Microsoft Clarity
        r"(^|\.)mouseflow\.com$",
        r"(^|\.)luckyorange\.com$",
        r"(^|\.)inspectlet\.com$",
        r"(^|\.)sessioncam\.com$",
        r"(^|\.)logrocket\.com$",
        r"(^|\.)intercom\.io$",
        r"(^|\.)intercomcdn\.com$",
        r"(^|\.)kissmetrics\.com$",
        r"(^|\.)hubspot\.com$",
        r"(^|\.)hsforms\.com$",
        r"(^|\.)pardot\.com$",
        r"(^|\.)marketo\.net$",
        r"(^|\.)mktoresp\.com$",
        r"(^|\.)branch\.io$",
        r"(^|\.)app\.link$",
        r"(^|\.)adjust\.com$",
        r"(^|\.)kochava\.com$",
        r"(^|\.)singular\.net$",
    ]),
    ("Smart TV / IoT Phone-Home", [
        # Samsung
        r"(^|\.)samsungacr\.com$",
        r"(^|\.)samsungads\.com$",
        r"(^|\.)samsungotn\.net$",
        r"(^|\.)log-config\.samsungacr\.com$",
        # LG
        r"(^|\.)lgsmartad\.com$",
        r"(^|\.)lge\.com$",
        r"(^|\.)lgtvsdp\.com$",
        # Roku
        r"(^|\.)logs\.roku\.com$",
        r"(^|\.)ads\.roku\.com$",
        r"(^|\.)cooper\.roku\.com$",
        # Amazon Fire / Echo
        r"(^|\.)service\.minerva\.devices\.a2z\.com$",
        r"(^|\.)api\.smarthome\.amazon\.com$",
        # Vizio
        r"(^|\.)viziotv\.com$",
        r"(^|\.)inscape\.tv$",
        # Hisense / TCL
        r"(^|\.)hismarttv\.com$",
        r"(^|\.)hicloud\.com$",
    ]),
]

# Statuses that count as "allowed through" (not blocked by Pi-hole)
ALLOWED_STATUSES = {"FORWARDED", "CACHE", "CACHE_STALE", "SPECIAL_DOMAIN"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Recommendation:
    domain: str
    category: str
    count: int
    clients: list[str] = field(default_factory=list)   # IPs that queried it


@dataclass
class RecommenderData:
    recommendations: list[Recommendation]   # sorted by count desc
    queries_scanned: int
    by_category: dict[str, list[Recommendation]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def fetch(client: PiholeClient, max_raw_queries: int = 15_000) -> RecommenderData:
    queries = await _fetch_allowed_queries(client, max_raw_queries)

    # Count hits per domain and collect querying clients
    domain_counts: dict[str, int] = defaultdict(int)
    domain_clients: dict[str, set[str]] = defaultdict(set)

    for q in queries:
        domain = q.get("domain", "").lower()
        client_ip = q.get("client", {}).get("ip", "unknown")
        domain_counts[domain] += 1
        domain_clients[domain].add(client_ip)

    # Match domains against category patterns
    compiled: list[tuple[str, list[re.Pattern[str]]]] = [
        (label, [re.compile(p) for p in patterns])
        for label, patterns in CATEGORIES
    ]

    recommendations: list[Recommendation] = []
    for domain, count in domain_counts.items():
        category = _classify(domain, compiled)
        if category:
            recommendations.append(Recommendation(
                domain=domain,
                category=category,
                count=count,
                clients=sorted(domain_clients[domain]),
            ))

    recommendations.sort(key=lambda r: r.count, reverse=True)

    by_category: dict[str, list[Recommendation]] = defaultdict(list)
    for rec in recommendations:
        by_category[rec.category].append(rec)

    return RecommenderData(
        recommendations=recommendations,
        queries_scanned=len(queries),
        by_category=dict(by_category),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _fetch_allowed_queries(
    client: PiholeClient, max_raw_queries: int
) -> list[dict[str, Any]]:
    """Paginate /api/queries and keep only allowed (non-blocked) entries.

    Fetches up to max_raw_queries total queries from the log and returns the
    subset that have an allowed status. Using raw query count as the limit
    ensures we page through a representative window of the log rather than
    stopping early when blocked queries dominate a page.
    """
    collected: list[dict[str, Any]] = []
    cursor: int | None = None
    raw_fetched = 0

    while raw_fetched < max_raw_queries:
        params: dict[str, Any] = {}
        if cursor is not None:
            params["cursor"] = cursor

        page = await client.get("/api/queries", **params)
        batch: list[dict[str, Any]] = page.get("queries", [])
        if not batch:
            break

        raw_fetched += len(batch)
        for q in batch:
            if q.get("status") in ALLOWED_STATUSES:
                collected.append(q)

        oldest_id: int = batch[-1]["id"]
        if oldest_id <= 1:
            break
        cursor = oldest_id - 1

    return collected


def _classify(domain: str, compiled: list[tuple[str, list[re.Pattern[str]]]]) -> str | None:
    for label, patterns in compiled:
        for pattern in patterns:
            if pattern.search(domain):
                return label
    return None
