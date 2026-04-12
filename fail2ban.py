"""Module: fail2ban status collection from Proxmox LXC containers.

Since the app runs inside CT107, it SSHs to the Proxmox host (192.168.1.20)
and uses `pct exec <ctid> -- fail2ban-client ...` to query each container.
The Proxmox host itself is queried directly (no pct exec needed).

Requires: SSH key from CT107 → root@192.168.1.20 must be pre-authorized.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

PROXMOX_HOST     = os.environ.get("PROXMOX_HOST", "192.168.1.20")
PROXMOX_SSH_USER = os.environ.get("PROXMOX_SSH_USER", "root")

# CT ID → (IP, label)
CONTAINERS: dict[str, tuple[str, str]] = {
    "100": ("192.168.1.21", "jellyfin"),
    "101": ("192.168.1.24", "pihole"),
    "102": ("192.168.1.22", "immich"),
    "103": ("192.168.1.23", "audiobookshelf"),
    "104": ("192.168.1.25", "nextcloud"),
    "105": ("192.168.1.27", "traefik"),
    "106": ("192.168.1.26", "ansible"),
}


@dataclass
class ContainerBans:
    ct_id: str
    ip: str
    label: str
    jails: list[str] = field(default_factory=list)
    banned_ips: list[str] = field(default_factory=list)
    total_bans: int = 0
    currently_banned: int = 0
    error: str | None = None


@dataclass
class Fail2banData:
    containers: list[ContainerBans] = field(default_factory=list)
    total_banned: int = 0
    total_jails: int = 0
    errors: list[str] = field(default_factory=list)


async def fetch() -> Fail2banData:
    """Fetch fail2ban status from all containers and the Proxmox host."""
    data = Fail2banData()

    tasks = [_fetch_container(ct_id, ip, label) for ct_id, (ip, label) in CONTAINERS.items()]
    tasks.append(_fetch_host())

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            data.errors.append(str(result))
        elif result is not None:
            data.containers.append(result)
            data.total_banned  += result.currently_banned
            data.total_jails   += len(result.jails)

    return data


# ---------------------------------------------------------------------------
# Per-container and host fetchers
# ---------------------------------------------------------------------------

async def _fetch_container(ct_id: str, ip: str, label: str) -> ContainerBans:
    info = ContainerBans(ct_id=ct_id, ip=ip, label=label)

    stdout, stderr, rc = await _pct_exec(ct_id, ["fail2ban-client", "status"])
    if rc != 0:
        info.error = f"pct exec failed (rc={rc}): {(stderr or '').strip()[:200]}"
        return info

    info.jails = _parse_jail_list(stdout)
    if not info.jails:
        return info

    jail_results = await asyncio.gather(
        *[_pct_exec(ct_id, ["fail2ban-client", "status", j]) for j in info.jails],
        return_exceptions=True,
    )
    for jail, res in zip(info.jails, jail_results):
        if isinstance(res, Exception):
            continue
        total, current, ips = _parse_jail_status(res[0])
        info.total_bans      += total
        info.currently_banned += current
        info.banned_ips.extend(ips)

    return info


async def _fetch_host() -> ContainerBans:
    info = ContainerBans(ct_id="host", ip=PROXMOX_HOST, label="proxmox")

    stdout, stderr, rc = await _ssh_direct(["fail2ban-client", "status"])
    if rc != 0:
        info.error = f"SSH to Proxmox failed (rc={rc}): {(stderr or '').strip()[:200]}"
        return info

    info.jails = _parse_jail_list(stdout)

    jail_results = await asyncio.gather(
        *[_ssh_direct(["fail2ban-client", "status", j]) for j in info.jails],
        return_exceptions=True,
    )
    for jail, res in zip(info.jails, jail_results):
        if isinstance(res, Exception):
            continue
        total, current, ips = _parse_jail_status(res[0])
        info.total_bans      += total
        info.currently_banned += current
        info.banned_ips.extend(ips)

    return info


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=5",
]


async def _pct_exec(ct_id: str, cmd: list[str]) -> tuple[str, str, int]:
    return await _run([
        "ssh", *_SSH_OPTS,
        f"{PROXMOX_SSH_USER}@{PROXMOX_HOST}",
        "pct", "exec", ct_id, "--", *cmd,
    ])


async def _ssh_direct(cmd: list[str]) -> tuple[str, str, int]:
    return await _run([
        "ssh", *_SSH_OPTS,
        f"{PROXMOX_SSH_USER}@{PROXMOX_HOST}",
        *cmd,
    ])


async def _run(cmd: list[str], timeout: float = 15.0) -> tuple[str, str, int]:
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


# ---------------------------------------------------------------------------
# fail2ban output parsers
# ---------------------------------------------------------------------------

def _parse_jail_list(output: str) -> list[str]:
    """Parse `fail2ban-client status` output → list of jail names."""
    for line in output.splitlines():
        if "Jail list" in line or "jail list" in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                return [j.strip() for j in parts[1].split(",") if j.strip()]
    return []


def _parse_jail_status(output: str) -> tuple[int, int, list[str]]:
    """Parse `fail2ban-client status <jail>` output.

    Returns (total_bans, currently_banned, list_of_banned_ips).
    """
    total = current = 0
    ips: list[str] = []

    for line in output.splitlines():
        line = line.strip()
        if "Total banned:" in line:
            m = re.search(r"(\d+)", line)
            if m:
                total = int(m.group(1))
        elif "Currently banned:" in line:
            m = re.search(r"(\d+)", line)
            if m:
                current = int(m.group(1))
        elif "Banned IP list:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ips = [ip.strip() for ip in parts[1].split() if ip.strip()]

    return total, current, ips
