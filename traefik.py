"""Module: Traefik access log analysis.

SSHs into the Traefik LXC container via the Proxmox host and parses the
JSON access log to detect brute-force attempts, automated scanners, and
anomalous request patterns.

Requires accessLog enabled in traefik.yml on CT105:
  [accessLog]
    filePath = "/var/log/traefik/access.log"
    format = "json"
  or in YAML:
    accessLog:
      filePath: "/var/log/traefik/access.log"
      format: json

Set TRAEFIK_CONTAINER in .env to the LXC CT ID (e.g. "105").
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import Counter
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

PROXMOX_HOST      = os.environ.get("PROXMOX_HOST", "192.168.1.20")
PROXMOX_SSH_USER  = os.environ.get("PROXMOX_SSH_USER", "root")
TRAEFIK_CONTAINER = os.environ.get("TRAEFIK_CONTAINER", "")
TRAEFIK_LOG_PATH  = os.environ.get("TRAEFIK_LOG_PATH", "/var/log/traefik/access.log")

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=5",
]

# Paths commonly probed by automated scanners
_SCANNER_PATHS = {
    "/wp-admin", "/wp-login.php", "/.env", "/.git", "/admin",
    "/phpmyadmin", "/xmlrpc.php", "/config.php", "/setup.php",
    "/install.php", "/.aws", "/.ssh", "/cgi-bin", "/actuator",
    "/.well-known/security.txt",  # legitimate but also probed
}


@dataclass
class ScannerHit:
    client_ip: str
    path: str
    status: str
    service: str


@dataclass
class TraefikStats:
    total_requests: int = 0
    auth_failures: int = 0       # 401 responses
    server_errors: int = 0       # 5xx responses
    scanner_hits: list[ScannerHit] = field(default_factory=list)
    top_client_ips: list[tuple[str, int]] = field(default_factory=list)
    top_paths: list[tuple[str, int]] = field(default_factory=list)
    top_user_agents: list[tuple[str, int]] = field(default_factory=list)
    services_targeted: list[str] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class TraefikData:
    stats: TraefikStats | None = None
    log_lines_parsed: int = 0
    error: str | None = None


async def fetch(tail_lines: int = 5000) -> TraefikData:
    """Read and parse the last N lines of the Traefik JSON access log."""
    data = TraefikData()

    if not TRAEFIK_CONTAINER:
        data.error = "TRAEFIK_CONTAINER not set — skipping Traefik log analysis"
        return data

    stdout, stderr, rc = await _pct_exec(
        TRAEFIK_CONTAINER,
        ["tail", "-n", str(tail_lines), TRAEFIK_LOG_PATH],
    )
    if rc != 0:
        data.error = (
            f"Failed to read Traefik log from CT{TRAEFIK_CONTAINER} (rc={rc}): "
            f"{(stderr or '').strip()[:200]}"
        )
        return data

    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    data.log_lines_parsed = len(lines)
    data.stats = _parse_log(lines)
    return data


def _parse_log(lines: list[str]) -> TraefikStats:
    stats = TraefikStats()
    ip_counts: Counter = Counter()
    path_counts: Counter = Counter()
    ua_counts: Counter = Counter()
    services: set[str] = set()

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        stats.total_requests += 1

        # Status code — Traefik JSON uses DownstreamStatus
        status = str(entry.get("DownstreamStatus") or entry.get("StatusCode") or "")
        if status:
            stats.status_counts[status] = stats.status_counts.get(status, 0) + 1
            if status == "401":
                stats.auth_failures += 1
            elif status.startswith("5"):
                stats.server_errors += 1

        # Client IP — ClientAddr is "ip:port"
        client_addr = str(entry.get("ClientAddr") or entry.get("ClientHost") or "")
        client_ip = client_addr.rsplit(":", 1)[0] if ":" in client_addr else client_addr
        if client_ip:
            ip_counts[client_ip] += 1

        path = str(entry.get("RequestPath") or "")
        if path:
            path_counts[path] += 1

        # User-Agent lives under "request_User-Agent" key in Traefik JSON
        ua = str(entry.get("request_User-Agent") or "")
        if ua:
            ua_counts[ua] += 1

        svc = str(entry.get("ServiceName") or entry.get("RouterName") or "")
        if svc:
            services.add(svc)

        # Scanner detection: flag requests to known exploit probe paths
        for bad in _SCANNER_PATHS:
            if path == bad or path.startswith(bad + "/") or path.startswith(bad + "?"):
                stats.scanner_hits.append(ScannerHit(
                    client_ip=client_ip,
                    path=path,
                    status=status,
                    service=svc,
                ))
                break

    stats.top_client_ips = ip_counts.most_common(10)
    stats.top_paths = path_counts.most_common(10)
    stats.top_user_agents = ua_counts.most_common(5)
    stats.services_targeted = sorted(services)
    return stats


# ---------------------------------------------------------------------------
# SSH helpers — same pattern as fail2ban.py
# ---------------------------------------------------------------------------

async def _pct_exec(ct_id: str, cmd: list[str]) -> tuple[str, str, int]:
    return await _run([
        "ssh", *_SSH_OPTS,
        f"{PROXMOX_SSH_USER}@{PROXMOX_HOST}",
        "pct", "exec", ct_id, "--", *cmd,
    ])


async def _run(cmd: list[str], timeout: float = 20.0) -> tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return "", "timeout", -1
    return out.decode(errors="replace"), err.decode(errors="replace"), proc.returncode
