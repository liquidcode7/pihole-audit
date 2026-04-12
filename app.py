"""LiquidSystem — FastAPI web application.

Exposes:
  POST /api/run              — trigger a new analysis (runs in background)
  GET  /api/run/status       — poll run progress
  GET  /api/reports          — list all saved reports (metadata only)
  GET  /api/reports/latest   — full JSON for the most recent report
  GET  /api/reports/{id}     — full JSON for a specific report
  POST /api/logs/clear       — clear fail2ban logs from selected containers
  GET  /                     — serves the dashboard SPA
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import log_cleaner
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
# Static files and root
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
