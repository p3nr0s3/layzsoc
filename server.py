"""FastAPI Server for Slothery Custom Web Interface."""

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

from core.config import BASE_DIR, CACHE_TTL_HOURS
from core.parser import parse_raw_text, parse_uploaded_file, IoCItem
from core.key_manager import (
    KeyManager,
    SERVICE_VT,
    SERVICE_ABUSE,
)
from core.clients.virustotal import VirusTotalClient
from core.clients.abuseipdb import AbuseIPDBClient
from core.engine import (
    EnrichmentEngine,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_CLEAN,
    VERDICT_UNKNOWN,
)
from core.database import (
    get_all_cached_iocs,
    clear_cache,
    delete_cache_entry,
    get_cache_stats,
    get_scan_history,
)
from core.exporter import export_to_csv, export_to_json

app = FastAPI(title="Slothery Threat Intelligence Triage", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

km = KeyManager()
engine = EnrichmentEngine(km)
vt_client = VirusTotalClient(km)
abuse_client = AbuseIPDBClient(km)

WEB_DIR = BASE_DIR / "web"
WEB_DIR.mkdir(parents=True, exist_ok=True)


# Models
class ScanRequest(BaseModel):
    raw_text: str
    use_cache: bool = True
    ttl_hours: int = CACHE_TTL_HOURS
    skip_private_ips: bool = True
    auto_throttle: bool = True


class KeyRequest(BaseModel):
    service: str
    key: str


class ExportRequest(BaseModel):
    results: List[Dict[str, Any]]
    format: str = "csv"  # 'csv' or 'json'
    defang: bool = True


@app.get("/api/status")
def get_system_status():
    """Returns key pool stats and cache stats."""
    return {
        "pools": km.get_pool_counts(),
        "cache": get_cache_stats(),
        "services": {
            SERVICE_VT: km.get_service_summary(SERVICE_VT),
            SERVICE_ABUSE: km.get_service_summary(SERVICE_ABUSE),
        },
    }


@app.post("/api/parse")
def parse_indicators(req: Dict[str, str]):
    """Parses raw text and returns classified IoCs."""
    raw = req.get("raw_text", "")
    items = parse_raw_text(raw)
    return {
        "total": len(items),
        "items": [item.to_dict() for item in items],
    }


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    """Executes full scan on provided raw text."""
    items = parse_raw_text(req.raw_text)
    if not items:
        return {"total": 0, "results": [], "summary": {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}}

    results = []
    final_summary = None

    for event in engine.scan_items(
        items=items,
        use_cache=req.use_cache,
        ttl_hours=req.ttl_hours,
        skip_private_ips=req.skip_private_ips,
        auto_throttle=req.auto_throttle,
    ):
        if event["type"] == "item_result":
            results.append(event["data"])
        elif event["type"] == "complete":
            final_summary = event["summary"]

    return {
        "total": len(results),
        "results": results,
        "summary": final_summary or {
            "total": len(results),
            "malicious": sum(1 for r in results if r["verdict"] == VERDICT_MALICIOUS),
            "suspicious": sum(1 for r in results if r["verdict"] == VERDICT_SUSPICIOUS),
            "clean": sum(1 for r in results if r["verdict"] == VERDICT_CLEAN),
            "unknown": sum(1 for r in results if r["verdict"] == VERDICT_UNKNOWN),
        },
    }


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Parses uploaded CSV or TXT file."""
    content = await file.read()
    items = parse_uploaded_file(content, file.filename)
    return {
        "filename": file.filename,
        "total": len(items),
        "items": [item.to_dict() for item in items],
    }


@app.post("/api/keys")
def add_api_key(req: KeyRequest):
    ok, msg = km.add_key(req.service, req.key)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}


@app.delete("/api/keys")
def remove_api_key(service: str, key: str):
    ok = km.remove_key(service, key)
    return {"success": ok}


@app.post("/api/keys/test")
def test_api_key(req: KeyRequest):
    if req.service == SERVICE_VT:
        ok, msg = vt_client.test_key(req.key)
    elif req.service == SERVICE_ABUSE:
        ok, msg = abuse_client.test_key(req.key)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown service: {req.service}")
    return {"valid": ok, "message": msg}


@app.get("/api/cache")
def list_cache(limit: int = 200):
    return {
        "stats": get_cache_stats(),
        "entries": get_all_cached_iocs(limit=limit),
        "history": get_scan_history(limit=15),
    }


@app.delete("/api/cache")
def clear_all_cache():
    count = clear_cache()
    return {"deleted": count}


@app.post("/api/export")
def export_results(req: ExportRequest):
    if req.format.lower() == "json":
        data = export_to_json(req.results, defang_output=req.defang)
        return StreamingResponse(
            iter([data]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=slothery_report.json"},
        )
    else:
        data = export_to_csv(req.results, defang_output=req.defang)
        return StreamingResponse(
            iter([data]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=slothery_report.csv"},
        )


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>Slothery Web UI file missing</h1>", status_code=404)
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
