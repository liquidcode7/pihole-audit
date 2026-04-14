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
class DHCPLease:
    mac: str
    ip: str
    hostname: str
    interface: str
    expires: str


@dataclass
class FirewallData:
    recent_blocks: list[FirewallEvent] = field(default_factory=list)
    top_blocked_ips: list[dict] = field(default_factory=list)
    suricata_alerts: list[SuricataAlert] = field(default_factory=list)
    block_count: int = 0
    alert_count: int = 0
    # DHCP leases (OPNsense ground truth — catches static-IP devices Pi-hole misses)
    dhcp_leases: list[DHCPLease] = field(default_factory=list)
    # Firmware patch status
    firmware_current: str | None = None
    firmware_latest: str | None = None
    firmware_update_available: bool = False
    errors: list[str] = field(default_factory=list)


async def fetch(limit: int = 100) -> FirewallData:
    """Fetch firewall log entries, Suricata alerts, DHCP leases, and firmware status."""
    data = FirewallData()

    if not OPNSENSE_KEY or not OPNSENSE_SECRET:
        data.errors.append("OPNSENSE_KEY / OPNSENSE_SECRET not set — skipping firewall data")
        return data

    auth = (OPNSENSE_KEY, OPNSENSE_SECRET)
    async with httpx.AsyncClient(auth=auth, verify=False, timeout=15.0) as client:
        import asyncio
        await asyncio.gather(
            _fetch_firewall_log(client, data, limit),
            _fetch_suricata_alerts(client, data, limit),
            _fetch_dhcp_leases(client, data),
            _fetch_firmware_status(client, data),
        )

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


# ---------------------------------------------------------------------------
# DHCP leases — more reliable than Pi-hole for device discovery
# ---------------------------------------------------------------------------

async def _fetch_dhcp_leases(
    client: httpx.AsyncClient,
    data: FirewallData,
) -> None:
    try:
        resp = await client.post(
            f"{OPNSENSE_BASE}/api/dhcpv4/leases/searchLease",
            json={"current": 1, "rowCount": 500, "searchPhrase": "", "sort": {}},
        )
        resp.raise_for_status()
        body = resp.json()
        rows: list[dict] = body.get("rows", body if isinstance(body, list) else [])

        for row in rows:
            mac      = row.get("mac") or row.get("hwaddr") or ""
            ip       = row.get("address") or row.get("ip") or ""
            hostname = row.get("hostname") or row.get("host") or ""
            iface    = row.get("if") or row.get("interface") or ""
            expires  = row.get("ends") or row.get("expires") or ""
            if ip:
                data.dhcp_leases.append(DHCPLease(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    interface=iface,
                    expires=expires,
                ))

    except httpx.HTTPStatusError as exc:
        data.errors.append(f"DHCP leases HTTP {exc.response.status_code}: {exc.request.url}")
    except Exception as exc:
        data.errors.append(f"DHCP leases fetch error: {exc}")


# ---------------------------------------------------------------------------
# Firmware status — alert if OPNsense has pending security updates
# ---------------------------------------------------------------------------

async def _fetch_firmware_status(
    client: httpx.AsyncClient,
    data: FirewallData,
) -> None:
    try:
        resp = await client.get(f"{OPNSENSE_BASE}/api/core/firmware/status")
        resp.raise_for_status()
        body = resp.json()

        data.firmware_current = (
            body.get("product_version")
            or body.get("current_version")
            or body.get("version")
        )
        data.firmware_latest = (
            body.get("product_latest")
            or body.get("latest_version")
            or body.get("new_version")
        )

        # OPNsense returns needs_reboot, upgrade_needs_reboot, or similar flags
        update_flag = (
            body.get("needs_reboot")
            or body.get("upgrade_needs_reboot")
            or body.get("updates_available")
        )
        data.firmware_update_available = bool(update_flag) or (
            data.firmware_latest is not None
            and data.firmware_current is not None
            and data.firmware_latest != data.firmware_current
        )

    except httpx.HTTPStatusError as exc:
        data.errors.append(f"Firmware status HTTP {exc.response.status_code}")
    except Exception as exc:
        data.errors.append(f"Firmware status fetch error: {exc}")
