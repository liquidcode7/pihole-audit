"""LiquidSystem runner — orchestrates the full analysis pipeline.

Pi-hole data runs first (requires auth), then Prometheus / OPNsense / fail2ban
run in parallel since they're independent. The AI assessment receives all data
and analyzes everything holistically.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
import os

import assessment
import bypass
import device_identifier
import fail2ban
import firewall
import metrics
import recommender
import traffic
from client import PiholeClient


async def run_analysis() -> dict:
    """Run the full analysis pipeline and return a JSON-serializable report dict."""
    aliases_path = os.environ.get("PIHOLE_DEVICES_JSON", "devices.json")

    # --- Phase 1: Pi-hole data (requires session auth) ---
    async with PiholeClient() as client:
        client_names = await client.get_client_names()
        traffic_data, bypass_data, rec_data, device_map = await asyncio.gather(
            traffic.fetch(client, client_names=client_names),
            bypass.fetch(client, client_names=client_names),
            recommender.fetch(client),
            device_identifier.identify_devices(
                client,
                client_names=client_names,
                aliases_path=aliases_path,
            ),
        )

    risk_summary = device_identifier.network_risk_summary(device_map)

    # --- Phase 2: Independent data sources (parallel) ---
    raw_metrics, raw_firewall, raw_fail2ban = await asyncio.gather(
        metrics.fetch(),
        firewall.fetch(),
        fail2ban.fetch(),
        return_exceptions=True,
    )

    metrics_data  = None if isinstance(raw_metrics,  Exception) else raw_metrics
    firewall_data = None if isinstance(raw_firewall, Exception) else raw_firewall
    fail2ban_data = None if isinstance(raw_fail2ban, Exception) else raw_fail2ban

    # Log any phase-2 failures to stdout (shows in uvicorn logs)
    if isinstance(raw_metrics,  Exception):
        print(f"[runner] metrics fetch failed: {raw_metrics}")
    if isinstance(raw_firewall, Exception):
        print(f"[runner] firewall fetch failed: {raw_firewall}")
    if isinstance(raw_fail2ban, Exception):
        print(f"[runner] fail2ban fetch failed: {raw_fail2ban}")

    # --- Phase 3: AI assessment (blocking stream → run in thread) ---
    assessment_text = await asyncio.to_thread(
        assessment.get_ai_assessment,
        traffic_data,
        bypass_data,
        rec_data,
        device_map=device_map,
        metrics_data=metrics_data,
        firewall_data=firewall_data,
        fail2ban_data=fail2ban_data,
    )

    now = datetime.datetime.now()
    report_id = now.strftime("%Y%m%d-%H%M%S")

    return {
        "id": report_id,
        "created_at": now.isoformat(),
        # Pi-hole data
        "traffic_data":  dataclasses.asdict(traffic_data),
        "bypass_data":   dataclasses.asdict(bypass_data),
        "rec_data":      dataclasses.asdict(rec_data),
        "device_map":    {ip: dataclasses.asdict(info) for ip, info in device_map.items()},
        "risk_summary":  dataclasses.asdict(risk_summary),
        "client_names":  client_names,
        # New data sources
        "metrics_data":  dataclasses.asdict(metrics_data)  if metrics_data  else None,
        "firewall_data": dataclasses.asdict(firewall_data) if firewall_data else None,
        "fail2ban_data": dataclasses.asdict(fail2ban_data) if fail2ban_data else None,
        # Assessment
        "assessment_text": assessment_text,
    }
