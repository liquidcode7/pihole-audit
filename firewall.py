"""Module: OPNsense firewall log and Suricata/IDS alert ingestion.

Connects to the OPNsense REST API (Basic auth with API key:secret)
to fetch recent firewall block events and Suricata alert summaries.
Skips TLS verification since OPNsense uses a self-signed cert on LAN.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx
from dotenv import load_dotenv

load_dotenv()

OPNSENSE_BASE   = os.environ.get("OPNSENSE_URL", "http://192.168.1.1")
OPNSENSE_KEY    = os.environ.get("OPNSENSE_KEY", "")
OPNSENSE_SECRET = os.environ.get("OPNSENSE_SECRET", "")


@dataclass
class FirewallEvent:
    timestamp: str
    action: str        # "block" | "pass" | "drop"
    src_ip: str
    dst_ip: str
    dst_port: str
    protocol: str
    interface: str
    reason: str


@dataclass
class SuricataAlert:
    timestamp: str
    src_ip: str
    dst_ip: str
    alert: str
    category: str
    severity: int      # 1 = high, 2 = medium, 3 = low (Suricata convention)


@dataclass
class FirewallData:
    recent_blocks: list[FirewallEvent] = field(default_factory=list)
    top_blocked_ips: list[dict] = field(default_factory=list)
    suricata_alerts: list[SuricataAlert] = field(default_factory=list)
    block_count: int = 0
    alert_count: int = 0
    errors: list[str] = field(default_factory=list)


async def fetch(limit: int = 100) -> FirewallData:
    """Fetch firewall log entries and Suricata alerts from OPNsense."""
    data = FirewallData()

    if not OPNSENSE_KEY or not OPNSENSE_SECRET:
        data.errors.append("OPNSENSE_KEY / OPNSENSE_SECRET not set — skipping firewall data")
        return data

    auth = (OPNSENSE_KEY, OPNSENSE_SECRET)
    async with httpx.AsyncClient(auth=auth, verify=False, timeout=15.0) as client:
        await _fetch_firewall_log(client, data, limit)
        await _fetch_suricata_alerts(client, data, limit)

    return data


# ---------------------------------------------------------------------------
# Firewall log
# ---------------------------------------------------------------------------

async def _fetch_firewall_log(
    client: httpx.AsyncClient,
    data: FirewallData,
    limit: int,
) -> None:
    try:
        resp = await client.get(
            f"{OPNSENSE_BASE}/api/diagnostics/firewall/log",
            params={"limit": limit},
        )
        resp.raise_for_status()
        body = resp.json()
        # OPNsense may return a list directly or {"items": [...]}
        items: list[dict] = body if isinstance(body, list) else body.get("items", [])

        block_ip_counts: dict[str, int] = {}
        for item in items:
            action = (item.get("action") or item.get("__action__") or "").lower()
            src = item.get("src") or item.get("source") or ""
            dst = item.get("dst") or item.get("destination") or ""

            if action in ("block", "drop", "reject"):
                data.block_count += 1
                block_ip_counts[src] = block_ip_counts.get(src, 0) + 1
                data.recent_blocks.append(FirewallEvent(
                    timestamp=item.get("time") or item.get("timestamp") or "",
                    action=action,
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=str(item.get("dstport") or item.get("dst_port") or ""),
                    protocol=item.get("proto") or item.get("protocol") or "",
                    interface=item.get("interface") or item.get("interface_name") or "",
                    reason=item.get("reason") or item.get("label") or item.get("rule") or "",
                ))

        data.top_blocked_ips = sorted(
            [{"ip": ip, "count": cnt} for ip, cnt in block_ip_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:20]

    except httpx.HTTPStatusError as exc:
        data.errors.append(f"Firewall log HTTP {exc.response.status_code}: {exc.request.url}")
    except Exception as exc:
        data.errors.append(f"Firewall log fetch error: {exc}")


# ---------------------------------------------------------------------------
# Suricata / IDS alerts
# ---------------------------------------------------------------------------

async def _fetch_suricata_alerts(
    client: httpx.AsyncClient,
    data: FirewallData,
    limit: int,
) -> None:
    try:
        resp = await client.post(
            f"{OPNSENSE_BASE}/api/ids/alert/searchAlerts",
            json={"current": 1, "rowCount": limit, "searchPhrase": "", "sort": {}},
        )
        resp.raise_for_status()
        body = resp.json()
        rows: list[dict] = body.get("rows", [])
        data.alert_count = int(body.get("total", len(rows)))

        for row in rows:
            data.suricata_alerts.append(SuricataAlert(
                timestamp=row.get("timestamp") or row.get("alert_time") or "",
                src_ip=row.get("src_ip") or row.get("source_ip") or "",
                dst_ip=row.get("dst_ip") or row.get("destination_ip") or "",
                alert=row.get("alert") or row.get("message") or row.get("signature") or "",
                category=row.get("category") or "",
                severity=int(row.get("severity") or row.get("priority") or 3),
            ))

    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            data.errors.append("Suricata IDS API not found (plugin may not be installed)")
        else:
            data.errors.append(f"Suricata alerts HTTP {exc.response.status_code}")
    except Exception as exc:
        data.errors.append(f"Suricata alerts fetch error: {exc}")
