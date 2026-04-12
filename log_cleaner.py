"""Module: Container log cleaner — called explicitly by the UI, never automated.

Clears fail2ban active bans and truncates log files in selected LXC containers
or the Proxmox host itself. SSH key from CT107 → root@PROXMOX_HOST required.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

PROXMOX_HOST     = os.environ.get("PROXMOX_HOST", "192.168.1.20")
PROXMOX_SSH_USER = os.environ.get("PROXMOX_SSH_USER", "root")

FAIL2BAN_LOG = "/var/log/fail2ban.log"

_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=5",
]


@dataclass
class ClearResult:
    ct_id: str
    label: str
    success: bool
    log_bytes_freed: int = 0
    bans_cleared: int = 0
    error: str | None = None


@dataclass
class ClearReport:
    results: list[ClearResult] = field(default_factory=list)
    total_bytes_freed: int = 0
    errors: list[str] = field(default_factory=list)


async def clear_containers(
    container_ids: list[str],
    labels: dict[str, str] | None = None,
) -> ClearReport:
    """Clear fail2ban logs and active bans for the given container IDs.

    Args:
        container_ids: CT IDs like ["100", "104"] or ["host"] for the Proxmox host.
        labels: Optional map of ct_id → display label.
    """
    labels = labels or {}
    report = ClearReport()

    tasks = []
    for ct_id in container_ids:
        label = labels.get(ct_id, ct_id)
        if ct_id == "host":
            tasks.append(_clear_host(label))
        else:
            tasks.append(_clear_container(ct_id, label))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception):
            report.errors.append(str(result))
        else:
            report.results.append(result)
            report.total_bytes_freed += result.log_bytes_freed

    return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _clear_container(ct_id: str, label: str) -> ClearResult:
    result = ClearResult(ct_id=ct_id, label=label, success=False)

    # Measure log size before clearing
    out, _, _ = await _pct_exec(ct_id, ["stat", "-c", "%s", FAIL2BAN_LOG])
    try:
        result.log_bytes_freed = int(out.strip())
    except ValueError:
        pass

    # Unban all (best-effort — fail2ban may not be installed in every CT)
    await _pct_exec(ct_id, ["fail2ban-client", "unban", "--all"])

    # Truncate log file
    _, err, rc = await _pct_exec(ct_id, ["truncate", "-s", "0", FAIL2BAN_LOG])
    if rc != 0:
        result.error = f"truncate failed: {err.strip()[:200]}"
        return result

    result.success = True
    return result


async def _clear_host(label: str) -> ClearResult:
    result = ClearResult(ct_id="host", label=label, success=False)

    out, _, _ = await _ssh_direct(["stat", "-c", "%s", FAIL2BAN_LOG])
    try:
        result.log_bytes_freed = int(out.strip())
    except ValueError:
        pass

    await _ssh_direct(["fail2ban-client", "unban", "--all"])

    _, err, rc = await _ssh_direct(["truncate", "-s", "0", FAIL2BAN_LOG])
    if rc != 0:
        result.error = f"truncate failed: {err.strip()[:200]}"
        return result

    result.success = True
    return result


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
