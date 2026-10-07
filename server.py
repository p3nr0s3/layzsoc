"""FastAPI Server for Slothery Custom Web Interface."""

import os
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
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
from core.mail_health import MailHealthChecker
from core.recon import perform_recon
from core.email_analyzer import EmailAnalyzer
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
from core.feed import get_cyber_news
from core.cve import query_cve
from core.playbooks import get_all_playbooks, get_playbook, generate_playbook_report
from core.url_tracer import trace_url_redirects
from core.deobfuscator import deobfuscate_payload

app = FastAPI(title="LazySOC Threat Triage & Investigation Platform", version="3.0.0")

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
mail_checker = MailHealthChecker()
email_analyzer = EmailAnalyzer()

WEB_DIR = BASE_DIR / "web"
WEB_DIR.mkdir(parents=True, exist_ok=True)


# Models
class ScanRequest(BaseModel):
    raw_text: str
    providers: Optional[List[str]] = None
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


class PlaybookReportRequest(BaseModel):
    playbook_id: str
    completed_task_ids: List[str]
    analyst_name: Optional[str] = "SOC Analyst"
    incident_id: Optional[str] = "INC-SOC-001"
    notes: Optional[str] = ""
    iocs: Optional[List[str]] = None


class TraceUrlRequest(BaseModel):
    url: str
    max_hops: Optional[int] = 8


class DeobfuscateRequest(BaseModel):
    payload: str


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


@app.get("/api/mail-health")
def check_mail_health(domain: str):
    """Audits MX, SPF, DMARC, and email spoofing posture for a domain."""
    clean_domain = domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    return mail_checker.check_domain(clean_domain)


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
        providers=req.providers,
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


@app.get("/api/recon")
def network_recon_endpoint(target: str):
    """Network recon for IP or domain: WHOIS/RDAP, Reverse DNS (PTR), Geolocation & ASN."""
    tgt = target.strip()
    if not tgt:
        raise HTTPException(status_code=400, detail="Target cannot be empty.")
    return perform_recon(tgt)


@app.post("/api/analyze-eml")
async def analyze_eml_endpoint(file: Optional[UploadFile] = File(None), raw_text: Optional[str] = Form(None)):
    """Analyzes .eml file or raw email header text for phishing and spoofing indicators."""
    if file:
        content = await file.read()
        return email_analyzer.analyze(content, filename=file.filename or "email.eml")
    elif raw_text:
        return email_analyzer.analyze(raw_text.encode("utf-8", errors="ignore"), filename="pasted_headers.eml")
    else:
        raise HTTPException(status_code=400, detail="Provide either a file or raw_text.")


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


ALLOW_KEY_MANAGEMENT = os.environ.get("ALLOW_KEY_MANAGEMENT", "false").lower() in ("true", "1", "yes")


@app.post("/api/keys")
def add_api_key(req: KeyRequest):
    if not ALLOW_KEY_MANAGEMENT:
        raise HTTPException(
            status_code=403,
            detail="Key modification via Web API is locked. Manage keys securely via Environment Variables or server config."
        )
    ok, msg = km.add_key(req.service, req.key)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}


@app.delete("/api/keys")
def remove_api_key(service: str, key: str):
    if not ALLOW_KEY_MANAGEMENT:
        raise HTTPException(
            status_code=403,
            detail="Key removal via Web API is locked. API keys are protected on the server."
        )
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
            headers={"Content-Disposition": "attachment; filename=lazysoc_report.json"},
        )
    else:
        data = export_to_csv(req.results, defang_output=req.defang)
        return StreamingResponse(
            iter([data]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=lazysoc_report.csv"},
        )


@app.get("/api/feed")
def get_cyber_feed_endpoint(source: str = "all", limit: int = 40):
    """Fetches real-time cyber security news & threat advisories."""
    return get_cyber_news(source=source, limit=limit)


@app.get("/api/cve")
def get_cve_endpoint(query: Optional[str] = None, limit: int = 30, page: int = 1):
    """Searches NIST NVD and vulnerability databases for CVE details with latest-first pagination."""
    return query_cve(search=query, limit=limit, page=page)


@app.get("/api/playbooks")
def list_playbooks_endpoint():
    """Returns all standardized SOC incident response playbooks and metadata."""
    return {"playbooks": get_all_playbooks()}


@app.get("/api/playbooks/{playbook_id}")
def get_playbook_endpoint(playbook_id: str):
    """Retrieves a detailed playbook with checklist tasks and remediation commands."""
    pb = get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return pb


@app.post("/api/playbooks/report")
def generate_playbook_report_endpoint(req: PlaybookReportRequest):
    """Generates an audit report for playbook execution ready for ticket handover."""
    report = generate_playbook_report(
        playbook_id=req.playbook_id,
        completed_task_ids=req.completed_task_ids,
        analyst_name=req.analyst_name,
        incident_id=req.incident_id,
        notes=req.notes,
        iocs=req.iocs,
    )
    if "error" in report:
        raise HTTPException(status_code=400, detail=report["error"])
    return report


@app.post("/api/trace-url")
def trace_url_endpoint(req: TraceUrlRequest):
    """Traces URL redirect chain safely and passively, evaluating domain age and SSL certificates."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return trace_url_redirects(url, max_hops=req.max_hops or 8)


@app.post("/api/deobfuscate")
def deobfuscate_endpoint(req: DeobfuscateRequest):
    """De-obfuscates PowerShell commands, base64, hex, and percent-encoded payloads."""
    payload = req.payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Payload cannot be empty.")
    return deobfuscate_payload(payload)


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>LazySOC Web UI file missing</h1>", status_code=404)
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    is_dev = os.environ.get("ENV", "development") == "development"
    uvicorn.run("server:app", host=host, port=port, reload=is_dev)
