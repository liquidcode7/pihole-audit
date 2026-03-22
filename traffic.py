"""Module 1: Traffic Review — summary stats, top domains, top clients."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from client import PiholeClient


@dataclass
class TrafficSummary:
    total: int
    blocked: int
    percent_blocked: float
    cached: int
    forwarded: int
    unique_domains: int
    active_clients: int
    total_clients: int
    gravity_domains: int
    query_types: dict[str, int] = field(default_factory=dict)
    status_breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def allowed(self) -> int:
        return self.total - self.blocked


@dataclass
class TopDomain:
    domain: str
    count: int


@dataclass
class TopClient:
    client: str   # IP address
    name: str     # hostname if Pi-hole resolved it, else same as IP
    count: int


@dataclass
class TrafficData:
    summary: TrafficSummary
    top_allowed: list[TopDomain]
    top_blocked: list[TopDomain]
    top_clients: list[TopClient]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def fetch(
    client: PiholeClient,
    top_n: int = 20,
    client_names: dict[str, str] | None = None,
) -> TrafficData:
    """Fetch all traffic data concurrently and return structured results."""
    summary_raw, top_domains_raw, top_blocked_raw, top_clients_raw = (
        await asyncio.gather(
            client.get("/api/stats/summary"),
            client.get("/api/stats/top_domains", count=top_n, blocked=False),
            client.get("/api/stats/top_domains", count=top_n, blocked=True),
            client.get("/api/stats/top_clients", count=top_n, blocked=False),
        )
    )

    return TrafficData(
        summary=_parse_summary(summary_raw),
        top_allowed=_parse_top_domains(top_domains_raw, blocked=False)[:top_n],
        top_blocked=_parse_top_domains(top_blocked_raw, blocked=True)[:top_n],
        top_clients=_parse_top_clients(top_clients_raw, client_names or {})[:top_n],
    )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_summary(raw: dict[str, Any]) -> TrafficSummary:
    q = raw["queries"]
    c = raw["clients"]
    g = raw["gravity"]
    return TrafficSummary(
        total=q["total"],
        blocked=q["blocked"],
        percent_blocked=q["percent_blocked"],
        cached=q["cached"],
        forwarded=q["forwarded"],
        unique_domains=q["unique_domains"],
        active_clients=c["active"],
        total_clients=c["total"],
        gravity_domains=g["domains_being_blocked"],
        query_types={k: v for k, v in q["types"].items() if v > 0},
        status_breakdown={k: v for k, v in q["status"].items() if v > 0},
    )


def _parse_top_domains(raw: dict[str, Any], *, blocked: bool) -> list[TopDomain]:
    # v6: {"domains": [{"domain": "...", "count": N}, ...]}
    _ = blocked  # same key regardless of blocked flag
    return [
        TopDomain(domain=item["domain"], count=item["count"])
        for item in raw.get("domains", [])
    ]


def _parse_top_clients(
    raw: dict[str, Any],
    client_names: dict[str, str],
) -> list[TopClient]:
    # v6: {"clients": [{"ip": "...", "name": "...", "count": N}, ...]}
    clients = []
    for item in raw.get("clients", []):
        ip = item["ip"]
        # Prefer enriched name from network table, then Pi-hole's own name, then IP
        name = client_names.get(ip) or item.get("name") or ip
        clients.append(TopClient(client=ip, name=name, count=item["count"]))
    return clients
