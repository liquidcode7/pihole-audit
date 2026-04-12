"""Module: Prometheus metrics ingestion.

Queries Prometheus at PROMETHEUS_URL for CPU, RAM, disk, and network stats
for all known LiquidLab hosts. Returns a MetricsData dataclass.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from dotenv import load_dotenv

load_dotenv()

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://192.168.1.7:9090")

# Map of hostname → IP.  Prometheus instance labels are typically "<ip>:9100".
HOSTS: dict[str, str] = {
    "proxmox":        "192.168.1.20",
    "jellyfin":       "192.168.1.21",
    "immich":         "192.168.1.22",
    "audiobookshelf": "192.168.1.23",
    "nextcloud":      "192.168.1.25",
    "traefik":        "192.168.1.27",
    "ansible":        "192.168.1.26",
    "raspberry-pi":   "192.168.1.7",
    "workstation":    "192.168.1.4",
    "opnsense":       "192.168.1.1",
    "nas":            "192.168.1.5",
}

_IP_TO_NAME: dict[str, str] = {v: k for k, v in HOSTS.items()}


@dataclass
class HostMetrics:
    name: str
    ip: str
    cpu_pct: float | None = None
    ram_pct: float | None = None
    disk_pct: float | None = None
    net_in_bps: float | None = None
    net_out_bps: float | None = None
    up: bool = True


@dataclass
class MetricsData:
    hosts: list[HostMetrics] = field(default_factory=list)
    scraped_at: str = ""
    errors: list[str] = field(default_factory=list)


async def fetch() -> MetricsData:
    """Fetch current metrics from Prometheus for all known hosts."""
    data = MetricsData(scraped_at=datetime.now().isoformat())

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            results = await asyncio.gather(
                _query(client, '100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
                _query(client, '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100'),
                _query(client, '100 - (node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} * 100)'),
                _query(client, 'irate(node_network_receive_bytes_total{device!~"lo|veth.*|docker.*|br.*|cni.*"}[5m])'),
                _query(client, 'irate(node_network_transmit_bytes_total{device!~"lo|veth.*|docker.*|br.*|cni.*"}[5m])'),
                return_exceptions=True,
            )
    except Exception as exc:
        data.errors.append(f"Prometheus connection failed: {exc}")
        data.hosts = [HostMetrics(name=n, ip=ip, up=False) for n, ip in sorted(HOSTS.items())]
        return data

    cpu_raw, ram_raw, disk_raw, net_in_raw, net_out_raw = results

    if isinstance(cpu_raw, Exception):
        data.errors.append(f"CPU query failed: {cpu_raw}")
    if isinstance(ram_raw, Exception):
        data.errors.append(f"RAM query failed: {ram_raw}")
    if isinstance(disk_raw, Exception):
        data.errors.append(f"Disk query failed: {disk_raw}")

    cpu_map    = _parse_scalar(cpu_raw)
    ram_map    = _parse_scalar(ram_raw)
    disk_map   = _parse_scalar(disk_raw)
    net_in_map = _parse_sum(net_in_raw)
    net_out_map = _parse_sum(net_out_raw)

    for name, ip in sorted(HOSTS.items()):
        up = (ip in cpu_map) or (ip in ram_map)
        data.hosts.append(HostMetrics(
            name=name,
            ip=ip,
            cpu_pct=cpu_map.get(ip),
            ram_pct=ram_map.get(ip),
            disk_pct=disk_map.get(ip),
            net_in_bps=net_in_map.get(ip),
            net_out_bps=net_out_map.get(ip),
            up=up,
        ))

    return data


async def _query(client: httpx.AsyncClient, promql: str) -> list[dict]:
    resp = await client.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": promql},
    )
    resp.raise_for_status()
    body = resp.json()
    if body.get("status") != "success":
        raise ValueError(f"Prometheus error: {body.get('error', 'unknown')}")
    return body["data"]["result"]


def _parse_scalar(result: list[dict] | Exception) -> dict[str, float]:
    """Return {ip: float} from a Prometheus instant vector result."""
    if isinstance(result, Exception):
        return {}
    out: dict[str, float] = {}
    for item in result:
        instance: str = item.get("metric", {}).get("instance", "")
        ip = instance.split(":")[0] if ":" in instance else instance
        if ip in _IP_TO_NAME:
            try:
                out[ip] = float(item["value"][1])
            except (KeyError, ValueError, IndexError):
                pass
    return out


def _parse_sum(result: list[dict] | Exception) -> dict[str, float]:
    """Sum values across multiple series (e.g. per-interface network stats) per IP."""
    if isinstance(result, Exception):
        return {}
    out: dict[str, float] = {}
    for item in result:
        instance: str = item.get("metric", {}).get("instance", "")
        ip = instance.split(":")[0] if ":" in instance else instance
        if ip in _IP_TO_NAME:
            try:
                out[ip] = out.get(ip, 0.0) + float(item["value"][1])
            except (KeyError, ValueError, IndexError):
                pass
    return out
