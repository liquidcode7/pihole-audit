"""Module: Grafana Loki log aggregation query interface.

Queries the Loki HTTP API to pull security-relevant log events from all
containers without per-host SSH parsers. Requires Loki + Promtail deployed
on the network.

Set LOKI_URL in .env to enable (e.g. http://192.168.1.7:3100).
If LOKI_URL is unset, this module is a graceful no-op.
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field

import httpx
from dotenv import load_dotenv

load_dotenv()

LOKI_URL = os.environ.get("LOKI_URL", "")
_LOOKBACK_HOURS = 24
_MAX_EVENTS_PER_QUERY = 200


@dataclass
class LokiEvent:
    timestamp: str
    service: str
    level: str
    message: str


@dataclass
class LokiData:
    auth_failures: list[LokiEvent] = field(default_factory=list)
    error_events: list[LokiEvent] = field(default_factory=list)
    total_events: int = 0
    error: str | None = None


# LogQL queries — broad enough to cover any container Promtail ships
_QUERIES: dict[str, str] = {
    "auth_failures": (
        '{job=~".+"} |~ "(?i)(failed password|invalid user|authentication failure'
        '|bad credentials|unauthorized|401)"'
    ),
    "errors": (
        '{job=~".+", level="error"} | level="error"'
    ),
}


async def fetch(lookback_hours: int = _LOOKBACK_HOURS) -> LokiData:
    """Query Loki for security-relevant events from the past N hours."""
    data = LokiData()

    if not LOKI_URL:
        data.error = "LOKI_URL not set — skipping Loki log analysis"
        return data

    end_ns   = int(datetime.datetime.utcnow().timestamp() * 1e9)
    start_ns = end_ns - int(lookback_hours * 3600 * 1e9)

    async with httpx.AsyncClient(timeout=15.0) as client:
        for query_name, logql in _QUERIES.items():
            try:
                resp = await client.get(
                    f"{LOKI_URL}/loki/api/v1/query_range",
                    params={
                        "query":     logql,
                        "start":     str(start_ns),
                        "end":       str(end_ns),
                        "limit":     _MAX_EVENTS_PER_QUERY,
                        "direction": "backward",
                    },
                )
                resp.raise_for_status()
                events = _parse_response(resp.json())
                if query_name == "auth_failures":
                    data.auth_failures = events
                elif query_name == "errors":
                    data.error_events = events
                data.total_events += len(events)
            except httpx.HTTPStatusError as exc:
                data.error = f"Loki '{query_name}' HTTP {exc.response.status_code}"
            except Exception as exc:
                data.error = f"Loki '{query_name}' failed: {exc}"
                break

    return data


def _parse_response(body: dict) -> list[LokiEvent]:
    events: list[LokiEvent] = []
    try:
        for stream in body.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            service = (
                labels.get("job")
                or labels.get("container_name")
                or labels.get("app")
                or "unknown"
            )
            level = labels.get("level", "")
            for ts_ns, log_line in stream.get("values", []):
                ts = datetime.datetime.utcfromtimestamp(int(ts_ns) / 1e9).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                )
                events.append(LokiEvent(
                    timestamp=ts,
                    service=service,
                    level=level,
                    message=log_line[:500],
                ))
    except Exception:
        pass
    return events
