"""Sends a push notification to the self-hosted ntfy instance after each report run.

Configuration (via .env or environment):
  NTFY_URL        — base URL of your ntfy server (default: http://192.168.1.26:8080)
  NTFY_TOPIC      — topic name (default: LiquidLab)
  NTFY_ENABLED    — set to "false" to disable without removing config (default: true)
  DASHBOARD_URL   — LAN URL of the dashboard for deep-link in notification
                    (e.g. http://192.168.1.26:8000)
"""

from __future__ import annotations

import os
import re

import httpx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_exec_summary(assessment_text: str) -> str:
    """Return the first paragraph (executive summary) of the assessment."""
    if not assessment_text:
        return "New LiquidSystem report available."
    paragraphs = re.split(r"\n{2,}", assessment_text.strip())
    first = paragraphs[0].strip() if paragraphs else assessment_text.strip()
    if len(first) > 300:
        first = first[:297] + "..."
    return first


def _ntfy_priority(overall_risk: str | None, threats: list) -> str:
    """Derive priority from structured risk data — not regex word-counts."""
    critical_threats = [t for t in threats if t.get("severity") == "critical"]
    if overall_risk == "high" or critical_threats:
        return "urgent"
    if overall_risk == "medium" or any(t.get("severity") == "warning" for t in threats):
        return "high"
    return "default"


def _ntfy_tags(overall_risk: str | None, threats: list) -> str:
    critical_threats = [t for t in threats if t.get("severity") == "critical"]
    if overall_risk == "high" or critical_threats:
        return "rotating_light,shield"
    if overall_risk == "medium":
        return "warning,shield"
    return "white_check_mark,shield"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def notify_report_complete(report: dict) -> None:
    """POST a summary notification to ntfy after a report run completes.

    Silently swallows errors so a notification failure never breaks the run.
    """
    ntfy_url      = os.environ.get("NTFY_URL",      "http://192.168.1.26:8080")
    ntfy_topic    = os.environ.get("NTFY_TOPIC",    "LiquidLab")
    enabled       = os.environ.get("NTFY_ENABLED",  "true").lower()
    dashboard_url = os.environ.get("DASHBOARD_URL", "").rstrip("/")

    if enabled not in ("true", "1", "yes"):
        return

    assessment_text = report.get("assessment_text", "")
    overall_risk    = (report.get("risk_summary") or {}).get("overall_risk")
    threats         = (report.get("correlations") or {}).get("threats") or []
    report_id       = report.get("id", "")

    exec_summary = _extract_exec_summary(assessment_text)

    # Append correlation summary if threats were found
    critical_count = sum(1 for t in threats if t.get("severity") == "critical")
    warning_count  = sum(1 for t in threats if t.get("severity") == "warning")
    if critical_count or warning_count:
        exec_summary += f"\n{critical_count} critical · {warning_count} warning cross-source threats"

    # Deep link to dashboard
    if dashboard_url and report_id:
        exec_summary += f"\n\n{dashboard_url}?report={report_id}"

    priority = _ntfy_priority(overall_risk, threats)
    tags     = _ntfy_tags(overall_risk, threats)

    headers: dict[str, str] = {
        "Title":       "LiquidSystem Report",
        "Priority":    priority,
        "Tags":        tags,
        "X-Report-Id": report_id,
    }
    if dashboard_url and report_id:
        headers["Click"] = f"{dashboard_url}?report={report_id}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                f"{ntfy_url.rstrip('/')}/{ntfy_topic}",
                content=exec_summary.encode(),
                headers=headers,
            )
    except Exception as exc:
        print(f"[notifier] ntfy POST failed: {exc}")
