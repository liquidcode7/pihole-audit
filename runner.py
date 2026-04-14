"""LiquidSystem runner — orchestrates the full analysis pipeline.

Pi-hole data runs first (requires auth), then Prometheus / OPNsense /
fail2ban / Traefik / Loki / URLhaus run in parallel since they are
independent. The AI assessment receives all data and analyzes everything
holistically.
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
import os
from pathlib import Path

import assessment
import bypass
import correlate
import device_identifier
import fail2ban
import firewall
import loki
import metrics
import recommender
import traefik
import traffic
import urlhaus
from client import PiholeClient


async def run_analysis() -> dict:
    """Run the full analysis pipeline and return a JSON-serializable report dict."""
    aliases_path = os.environ.get("PIHOLE_DEVICES_JSON", "devices.json")

    # --- Phase 1: Pi-hole data (requires session auth) ---
    async with PiholeClient() as client:
        client_names, mac_vendors = await asyncio.gather(
            client.get_client_names(),
            client.get_mac_vendors(),
        )
        traffic_data, bypass_data, rec_data, device_map = await asyncio.gather(
            traffic.fetch(client, client_names=client_names),
            bypass.fetch(client, client_names=client_names),
            recommender.fetch(client),
            device_identifier.identify_devices(
                client,
                client_names=client_names,
                mac_vendors=mac_vendors,
                aliases_path=aliases_path,
            ),
        )

    risk_summary = device_identifier.network_risk_summary(device_map)

    # --- Phase 2: Independent data sources (all parallel) ---
    # URLhaus runs here because it needs traffic_data.top_allowed from Phase 1.
    raw_metrics, raw_firewall, raw_fail2ban, raw_traefik, raw_loki, raw_urlhaus = (
        await asyncio.gather(
            metrics.fetch(),
            firewall.fetch(),
            fail2ban.fetch(),
            traefik.fetch(),
            loki.fetch(),
            urlhaus.check(traffic_data.top_allowed),
            return_exceptions=True,
        )
    )

    metrics_data  = None if isinstance(raw_metrics,  Exception) else raw_metrics
    firewall_data = None if isinstance(raw_firewall, Exception) else raw_firewall
    fail2ban_data = None if isinstance(raw_fail2ban, Exception) else raw_fail2ban
    traefik_data  = None if isinstance(raw_traefik,  Exception) else raw_traefik
    loki_data     = None if isinstance(raw_loki,     Exception) else raw_loki
    urlhaus_data  = None if isinstance(raw_urlhaus,  Exception) else raw_urlhaus

    for label, result in [
        ("metrics",  raw_metrics),
        ("firewall", raw_firewall),
        ("fail2ban", raw_fail2ban),
        ("traefik",  raw_traefik),
        ("loki",     raw_loki),
        ("urlhaus",  raw_urlhaus),
    ]:
        if isinstance(result, Exception):
            print(f"[runner] {label} fetch failed: {result}")

    # --- Ban rate delta: compare total_bans against previous report ---
    bans_delta: dict[str, int] = {}
    if fail2ban_data is not None:
        reports_dir_path = Path(os.environ.get("REPORTS_DIR", "data/reports"))
        prev_paths = sorted(reports_dir_path.glob("*.json"), key=lambda p: p.name, reverse=True)
        if prev_paths:
            try:
                import json as _json
                prev_report = _json.loads(prev_paths[0].read_text(encoding="utf-8"))
                prev_f2b = prev_report.get("fail2ban_data") or {}
                prev_by_label = {
                    ct["label"]: ct.get("total_bans", 0)
                    for ct in prev_f2b.get("containers", [])
                }
                for ct in fail2ban_data.containers:
                    prev_val = prev_by_label.get(ct.label, 0)
                    bans_delta[ct.label] = ct.total_bans - prev_val
            except Exception:
                pass

    # --- Phase 2.5: Cross-source IP correlation ---
    correlation_report = correlate.correlate(
        bypass_data=bypass_data,
        firewall_data=firewall_data,
        fail2ban_data=fail2ban_data,
        urlhaus_data=urlhaus_data,
    )

    # --- Phase 2.6: Reputation enrichment (AbuseIPDB + CrowdSec CTI) ---
    await correlate.enrich_reputation(correlation_report)

    # --- Phase 3: AI assessment (blocking stream → run in thread) ---
    reports_dir = Path(os.environ.get("REPORTS_DIR", "data/reports"))
    historical_context = assessment.load_historical_context(reports_dir)

    assessment_text = await asyncio.to_thread(
        assessment.get_ai_assessment,
        traffic_data,
        bypass_data,
        rec_data,
        device_map=device_map,
        metrics_data=metrics_data,
        firewall_data=firewall_data,
        fail2ban_data=fail2ban_data,
        traefik_data=traefik_data,
        loki_data=loki_data,
        urlhaus_data=urlhaus_data,
        correlation_report=correlation_report,
        historical_context=historical_context,
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
        "traefik_data":  dataclasses.asdict(traefik_data)  if traefik_data  else None,
        "loki_data":     dataclasses.asdict(loki_data)     if loki_data     else None,
        "urlhaus_data":  dataclasses.asdict(urlhaus_data)  if urlhaus_data  else None,
        # Derived data
        "bans_delta":   bans_delta,
        "correlations": dataclasses.asdict(correlation_report),
        # Assessment
        "assessment_text": assessment_text,
    }
