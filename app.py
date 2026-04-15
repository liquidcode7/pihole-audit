"""LiquidSystem — FastAPI web application.

Exposes:
  POST /api/run              — trigger a new analysis (runs in background)
  GET  /api/run/status       — poll run progress
  GET  /api/reports          — list all saved reports (metadata only)
  GET  /api/reports/latest   — full JSON for the most recent report
  GET  /api/reports/{id}     — full JSON for a specific report
  POST /api/logs/clear       — clear fail2ban logs from selected containers
  POST /api/chat             — send a message; streams SSE tokens from Claude
  POST /api/chat/reset       — clear conversation history for a session
  GET  /                     — serves the dashboard SPA
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path

import anthropic
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import log_cleaner
import notifier
from assessment import MODEL, build_audit_context
from fail2ban import CONTAINERS
from runner import run_analysis

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATA_DIR    = Path(os.environ.get("REPORTS_DIR", "data/reports"))
MAX_REPORTS = int(os.environ.get("MAX_REPORTS", "30"))
# 11:00 UTC = 6:00 AM Indianapolis (EST = UTC-5)
SCHEDULE_HOUR = int(os.environ.get("SCHEDULE_HOUR", "11"))

_STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# In-memory run status
# ---------------------------------------------------------------------------

_run_status: dict = {
    "running": False,
    "started_at": None,
    "error": None,
    "last_completed": None,
}

# ---------------------------------------------------------------------------
# Core run logic
# ---------------------------------------------------------------------------


async def _execute_run() -> None:
    try:
        report = await run_analysis()
        _save_report(report)
        _run_status["last_completed"] = report["id"]
        await notifier.notify_report_complete(report)
    except Exception as exc:
        _run_status["error"] = str(exc)
    finally:
        _run_status["running"] = False


def _save_report(report: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / f"{report['id']}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _prune_old_reports()


def _prune_old_reports() -> None:
    reports = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name)
    while len(reports) > MAX_REPORTS:
        reports[0].unlink()
        reports = reports[1:]


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

scheduler = AsyncIOScheduler()


async def _scheduled_run() -> None:
    if _run_status["running"]:
        return
    _run_status.update({
        "running": True,
        "started_at": datetime.now().isoformat(),
        "error": None,
    })
    await _execute_run()


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _prune_old_sessions()   # clean up stale chat sessions on startup
    scheduler.add_job(_scheduled_run, "cron", hour=SCHEDULE_HOUR, minute=0)
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="LiquidSystem", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.post("/api/run")
async def api_run(background_tasks: BackgroundTasks) -> JSONResponse:
    if _run_status["running"]:
        return JSONResponse({"status": "already_running"}, status_code=409)
    _run_status.update({
        "running": True,
        "started_at": datetime.now().isoformat(),
        "error": None,
    })
    background_tasks.add_task(_execute_run)
    return JSONResponse({"status": "started"})


@app.get("/api/run/status")
async def api_run_status() -> dict:
    return _run_status


@app.get("/api/reports")
async def api_reports() -> list:
    reports = []
    for path in sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            reports.append({
                "id": data.get("id", path.stem),
                "created_at": data.get("created_at", ""),
            })
        except Exception:
            pass
    return reports


@app.get("/api/reports/latest")
async def api_reports_latest() -> JSONResponse:
    paths = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
    if not paths:
        raise HTTPException(status_code=404, detail="No reports yet")
    try:
        return JSONResponse(json.loads(paths[0].read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/reports/{report_id}")
async def api_report(report_id: str) -> JSONResponse:
    if not all(c.isalnum() or c in "-_" for c in report_id):
        raise HTTPException(status_code=400, detail="Invalid report ID")
    path = DATA_DIR / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/reports/{report_id}/export")
async def api_report_export(report_id: str) -> HTMLResponse:
    """Render the report as a self-contained HTML archive, then delete the stored JSON."""
    if not all(c.isalnum() or c in "-_" for c in report_id):
        raise HTTPException(status_code=400, detail="Invalid report ID")
    path = DATA_DIR / f"{report_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    html = _render_export_html(data)

    # Delete the stored JSON report
    path.unlink(missing_ok=True)

    filename = f"liquidsystem-{report_id}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _render_export_html(data: dict) -> str:
    """Generate a self-contained HTML archive directly from the report JSON dict."""
    import html as _html

    def esc(s: object) -> str:
        return _html.escape(str(s)) if s is not None else ""

    report_id  = esc(data.get("id", "unknown"))
    created_at = esc(data.get("created_at", "")[:19].replace("T", " "))
    assessment = data.get("assessment_text") or ""

    # Traffic summary
    s = (data.get("traffic_data") or {}).get("summary") or {}
    total    = s.get("total", 0)
    blocked  = s.get("blocked", 0)
    pct      = s.get("percent_blocked", 0)
    clients  = s.get("active_clients", 0)
    domains  = s.get("unique_domains", 0)
    gravity  = s.get("gravity_domains", 0)

    # Top domains
    td = data.get("traffic_data") or {}
    top_allowed_rows = "".join(
        f"<tr><td>{i+1}</td><td>{esc(d.get('domain',''))}</td>"
        f"<td style='text-align:right'>{d.get('count',0):,}</td></tr>"
        for i, d in enumerate((td.get("top_allowed") or [])[:15])
    )
    top_blocked_rows = "".join(
        f"<tr><td>{i+1}</td><td>{esc(d.get('domain',''))}</td>"
        f"<td style='text-align:right'>{d.get('count',0):,}</td></tr>"
        for i, d in enumerate((td.get("top_blocked") or [])[:15])
    )

    # Bypass findings
    bypass_findings = (data.get("bypass_data") or {}).get("findings") or []
    bypass_rows = "".join(
        f"<tr><td><code>{esc(f.get('client_ip',''))}</code></td>"
        f"<td>{esc(f.get('method',''))}</td><td>{esc(f.get('detail',''))}</td>"
        f"<td style='text-align:right'>{f.get('count',0)}</td></tr>"
        for f in bypass_findings
    ) or "<tr><td colspan='4' style='color:var(--muted)'>No bypass indicators detected.</td></tr>"

    # Correlations
    threats = (data.get("correlations") or {}).get("threats") or []
    threat_rows = ""
    for t in threats:
        sev = t.get("severity", "info")
        sev_color = {"critical": "var(--red)", "warning": "var(--yellow)"}.get(sev, "var(--muted)")
        sources = "+".join(t.get("sources") or [])
        details = "; ".join(t.get("details") or [])
        rep = t.get("reputation") or {}
        abuse = f" | AbuseIPDB: {rep['abuse_score']}/100" if rep.get("abuse_score") is not None else ""
        threat_rows += (
            f"<tr><td style='color:{sev_color}'>{esc(sev.upper())}</td>"
            f"<td><code>{esc(t.get('ip',''))}</code></td>"
            f"<td>{esc(sources)}</td>"
            f"<td style='font-size:0.85em;color:var(--muted)'>{esc(details)}{esc(abuse)}</td></tr>"
        )
    if not threat_rows:
        threat_rows = "<tr><td colspan='4' style='color:var(--muted)'>No cross-source threats detected.</td></tr>"

    # Assessment HTML (preserve newlines, basic markdown → html)
    import re
    def md_to_html(text: str) -> str:
        text = _html.escape(text)
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
        text = re.sub(r'^#{3}\s+(.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
        text = re.sub(r'^#{2}\s+(.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
        text = re.sub(r'^#{1}\s+(.+)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
        text = re.sub(r'^[-*]\s+(.+)$', r'<li>\1</li>', text, flags=re.MULTILINE)
        text = re.sub(r'(<li>.*</li>\n?)+', r'<ul>\g<0></ul>', text)
        text = re.sub(r'\n\n+', '</p><p>', text)
        return f"<p>{text}</p>"

    assessment_html = md_to_html(assessment) if assessment else "<p><em>No assessment available.</em></p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LiquidSystem Report — {report_id}</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --surface2: #20232e;
    --border: #2a2d3a; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #38bdf8; --green: #4ade80; --yellow: #facc15;
    --red: #f87171;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg); color: var(--text); font-size: 15px; line-height: 1.7;
    padding: 32px 24px; max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 1rem; font-weight: 600; color: var(--text); margin: 24px 0 10px; }}
  h3 {{ font-size: 0.9rem; font-weight: 600; color: var(--muted); margin: 16px 0 6px; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 32px; }}
  .stat-grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px 20px; min-width: 130px; }}
  .stat-label {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.06em; margin-bottom: 4px; }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; }}
  .section {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; color: var(--muted); font-size: 0.72rem;
    text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border);
    padding: 6px 10px; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid var(--border); }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ font-family: "SF Mono","Fira Code",monospace; font-size: 0.82em;
    background: var(--surface2); padding: 1px 4px; border-radius: 3px; }}
  .table-pair {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .assessment {{ line-height: 1.8; }}
  .assessment p {{ margin-bottom: 12px; }}
  .assessment h1, .assessment h2, .assessment h3 {{ margin-top: 20px; margin-bottom: 8px; }}
  .assessment ul {{ margin: 8px 0 8px 20px; }}
  .assessment li {{ margin-bottom: 4px; }}
  .assessment code {{ display: inline-block; }}
  @media (max-width: 700px) {{ .table-pair {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<h1>LiquidSystem Network Intelligence Report</h1>
<div class="meta">Report ID: {report_id} &nbsp;|&nbsp; Generated: {created_at}</div>

<div class="stat-grid">
  <div class="stat"><div class="stat-label">Total Queries</div><div class="stat-value">{total:,}</div></div>
  <div class="stat"><div class="stat-label">Blocked</div><div class="stat-value">{blocked:,}</div></div>
  <div class="stat"><div class="stat-label">Block Rate</div><div class="stat-value">{pct:.1f}%</div></div>
  <div class="stat"><div class="stat-label">Active Clients</div><div class="stat-value">{clients}</div></div>
  <div class="stat"><div class="stat-label">Unique Domains</div><div class="stat-value">{domains:,}</div></div>
  <div class="stat"><div class="stat-label">Gravity List</div><div class="stat-value">{gravity:,}</div></div>
</div>

<div class="section">
  <h2>AI Security Assessment</h2>
  <div class="assessment">{assessment_html}</div>
</div>

<div class="table-pair">
  <div class="section">
    <h2>Top Allowed Domains</h2>
    <table><thead><tr><th>#</th><th>Domain</th><th>Queries</th></tr></thead>
    <tbody>{top_allowed_rows}</tbody></table>
  </div>
  <div class="section">
    <h2>Top Blocked Domains</h2>
    <table><thead><tr><th>#</th><th>Domain</th><th>Queries</th></tr></thead>
    <tbody>{top_blocked_rows}</tbody></table>
  </div>
</div>

<div class="section">
  <h2>DNS Bypass Findings</h2>
  <table><thead><tr><th>Client IP</th><th>Method</th><th>Detail</th><th>Count</th></tr></thead>
  <tbody>{bypass_rows}</tbody></table>
</div>

<div class="section">
  <h2>Cross-Source Threat Correlations</h2>
  <table><thead><tr><th>Severity</th><th>IP</th><th>Sources</th><th>Details</th></tr></thead>
  <tbody>{threat_rows}</tbody></table>
</div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Log clear endpoint
# ---------------------------------------------------------------------------

class ClearRequest(BaseModel):
    container_ids: list[str]


@app.post("/api/logs/clear")
async def api_logs_clear(req: ClearRequest) -> JSONResponse:
    """Clear fail2ban logs and active bans from selected containers / Proxmox host."""
    # Build label map from known containers
    labels: dict[str, str] = {ct_id: label for ct_id, (_, label) in CONTAINERS.items()}
    labels["host"] = "proxmox"

    # Validate: only allow known container IDs and "host"
    valid_ids = set(CONTAINERS.keys()) | {"host"}
    unknown = [cid for cid in req.container_ids if cid not in valid_ids]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown container IDs: {unknown}")

    report = await log_cleaner.clear_containers(req.container_ids, labels)

    return JSONResponse({
        "results": [
            {
                "ct_id":           r.ct_id,
                "label":           r.label,
                "success":         r.success,
                "log_bytes_freed": r.log_bytes_freed,
                "error":           r.error,
            }
            for r in report.results
        ],
        "total_bytes_freed": report.total_bytes_freed,
        "errors": report.errors,
    })


# ---------------------------------------------------------------------------
# Chat sessions — SQLite-backed, survives restarts, 7-day TTL
# ---------------------------------------------------------------------------

_CHAT_DB_PATH = Path(os.environ.get("CHAT_DB", "data/chat_sessions.db"))
_chat_db_lock = threading.Lock()


def _chat_db() -> sqlite3.Connection:
    _CHAT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_CHAT_DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            messages   TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _load_session(session_id: str) -> list[dict]:
    with _chat_db_lock:
        conn = _chat_db()
        row = conn.execute(
            "SELECT messages FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            return []
    return []


def _save_session(session_id: str, messages: list[dict]) -> None:
    with _chat_db_lock:
        conn = _chat_db()
        conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, messages, updated_at) VALUES (?,?,?)",
            (session_id, json.dumps(messages), datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()


def _delete_session(session_id: str) -> None:
    with _chat_db_lock:
        conn = _chat_db()
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        conn.close()


def _prune_old_sessions() -> None:
    """Delete sessions not updated in the last 7 days."""
    cutoff = (datetime.now() - timedelta(days=7)).isoformat()
    with _chat_db_lock:
        conn = _chat_db()
        conn.execute("DELETE FROM sessions WHERE updated_at < ?", (cutoff,))
        conn.commit()
        conn.close()

_CHAT_SYSTEM_PROMPT = """\
You are a network security and privacy analyst who has just completed a full DNS \
audit of the user's home network. The complete audit data is embedded at the end \
of this prompt — reference it directly in every answer.

The user's setup:
  - OPNsense firewall/router
  - Pi-hole v6 DNS filter
  - Proxmox hypervisor
  - Various self-hosted services on a home LAN

Conversation rules:
1. Always reference actual IPs, domains, and counts from the audit data. \
Never give generic advice when real data is available.
2. When generating configs, firewall rules, blocklists, or CLI commands, \
wrap them in fenced code blocks (e.g. ```bash, ```yaml, ```xml).
3. If the user says "do it", "apply that", "make that change", or similar: \
state clearly that OPNsense/Pi-hole API integration is not yet implemented, \
then show exactly what the change would be — the full command, config snippet, \
or API call — so they can copy-paste it themselves.
4. Format responses clearly with headers and lists where helpful. \
Use markdown — the UI renders it.
5. You already gave an initial assessment. Build on it rather than repeating it.

--- AUDIT DATA ---
{audit_context}
"""


def _build_chat_system(report: dict) -> str:
    """Build the system prompt with full audit context from a report dict."""
    from bypass import BypassData
    from device_identifier import DeviceInfo
    from recommender import RecommenderData
    from traffic import TrafficData

    try:
        traffic     = TrafficData(**report["traffic_data"])    if report.get("traffic_data") else None
        bypass      = BypassData(**report["bypass_data"])      if report.get("bypass_data")  else None
        rec         = RecommenderData(**report["rec_data"])     if report.get("rec_data")     else None
        raw_devices = report.get("device_map") or {}
        devices     = {ip: DeviceInfo(**info) for ip, info in raw_devices.items()}

        # Phase 2 data — reconstruct typed objects for the context builder
        from metrics import MetricsData, HostMetrics
        from firewall import FirewallData, FirewallEvent, SuricataAlert
        from fail2ban import Fail2banData, ContainerBans

        def _load(cls, key):
            raw = report.get(key)
            if not raw:
                return None
            try:
                return cls(**raw)
            except Exception:
                return None

        metrics_data  = _load(MetricsData,  "metrics_data")
        firewall_data = _load(FirewallData, "firewall_data")
        fail2ban_data = _load(Fail2banData, "fail2ban_data")

        # Correlations (simple namespace object)
        from correlate import CorrelationReport, CorrelatedThreat
        corr_raw = report.get("correlations")
        correlation_report = None
        if corr_raw:
            try:
                correlation_report = CorrelationReport(**corr_raw)
            except Exception:
                pass

        bans_delta = report.get("bans_delta") or {}

        context = build_audit_context(
            traffic, bypass, rec, devices,
            metrics_data, firewall_data, fail2ban_data,
            correlation_report, bans_delta,
        )
    except Exception:
        context = "(Audit data could not be parsed — answer based on general home lab security best practices.)"

    # Also inject the initial assessment so Claude knows what it already said
    assessment = report.get("assessment_text", "")
    if assessment:
        context += f"\n\n--- INITIAL ASSESSMENT ---\n{assessment}"

    return _CHAT_SYSTEM_PROMPT.format(audit_context=context)


class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    report_id: str | None = None  # which report to use for context


class ChatResetRequest(BaseModel):
    session_id: str = "default"


@app.post("/api/chat")
async def api_chat(req: ChatRequest) -> StreamingResponse:
    """Stream a Claude response via Server-Sent Events."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not set")

    # Load report for context
    report: dict = {}
    if req.report_id:
        rpath = DATA_DIR / f"{req.report_id}.json"
        if rpath.exists():
            report = json.loads(rpath.read_text(encoding="utf-8"))
    else:
        # Fall back to latest
        paths = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name, reverse=True)
        if paths:
            report = json.loads(paths[0].read_text(encoding="utf-8"))

    system_prompt = _build_chat_system(report)

    history = _load_session(req.session_id)
    history.append({"role": "user", "content": req.message})

    # Snapshot messages for the thread (history is mutable)
    messages_snapshot = list(history)

    async def event_stream():
        client = anthropic.Anthropic(api_key=api_key)
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_event_loop()

        def stream_in_thread():
            try:
                with client.messages.stream(
                    model=MODEL,
                    max_tokens=4096,
                    system=system_prompt,
                    messages=messages_snapshot,
                ) as stream:
                    for chunk in stream.text_stream:
                        loop.call_soon_threadsafe(queue.put_nowait, {"token": chunk})
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, {"error": str(exc)})
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

        executor = ThreadPoolExecutor(max_workers=1)
        loop.run_in_executor(executor, stream_in_thread)

        full_text: list[str] = []
        while True:
            item = await queue.get()
            if item is None:
                break
            if "error" in item:
                yield f"data: {json.dumps({'error': item['error']})}\n\n"
                return
            token = item["token"]
            full_text.append(token)
            yield f"data: {json.dumps({'token': token})}\n\n"

        response_text = "".join(full_text)
        history.append({"role": "assistant", "content": response_text})
        _save_session(req.session_id, history)
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/chat/reset")
async def api_chat_reset(req: ChatResetRequest) -> JSONResponse:
    """Clear conversation history for a session."""
    _delete_session(req.session_id)
    return JSONResponse({"status": "cleared"})


# ---------------------------------------------------------------------------
# Pi-hole domain blocking
# ---------------------------------------------------------------------------

class BlockRequest(BaseModel):
    domain: str
    comment: str = "blocked via LiquidSystem"


@app.post("/api/pihole/block")
async def api_pihole_block(req: BlockRequest) -> JSONResponse:
    """Add a domain to Pi-hole's gravity blocklist directly from the dashboard."""
    domain = req.domain.strip().lower()
    if not domain or "/" in domain or " " in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    from client import PiholeClient
    try:
        async with PiholeClient() as client:
            result = await client.block_domain(domain, comment=req.comment)
        return JSONResponse({"status": "blocked", "domain": domain, "result": result})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pi-hole block failed: {exc}")


@app.get("/api/trends")
async def api_trends() -> JSONResponse:
    """Return time-series data across all saved reports for trend charts."""
    points = []
    for path in sorted(DATA_DIR.glob("*.json"), key=lambda p: p.name):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            s    = (data.get("traffic_data") or {}).get("summary") or {}
            fd   = data.get("firewall_data") or {}
            f2b  = data.get("fail2ban_data") or {}
            corr = data.get("correlations")  or {}
            points.append({
                "id":           data.get("id", path.stem),
                "created_at":   data.get("created_at", ""),
                "total_queries":    s.get("total", 0),
                "percent_blocked":  round(s.get("percent_blocked", 0), 1),
                "active_clients":   s.get("active_clients", 0),
                "unique_domains":   s.get("unique_domains", 0),
                "gravity_domains":  s.get("gravity_domains", 0),
                "suricata_alerts":  fd.get("alert_count", 0),
                "fw_blocks":        fd.get("block_count", 0),
                "f2b_banned":       f2b.get("total_banned", 0),
                "threat_count":     len(corr.get("threats") or []),
            })
        except Exception:
            continue
    return JSONResponse(points)

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
