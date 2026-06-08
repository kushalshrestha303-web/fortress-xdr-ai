from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from investigation_engine import InvestigationEngine
from models import AlertListResponse, HuntRequest, HuntResponse, InvestigationResult, WazuhAlert
from wazuh_client import WazuhClient

app = FastAPI(
    title="FORTRESS XDR AI",
    description="Real Wazuh-connected SOC AI investigation dashboard.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+):(3000|517[3-9])",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = WazuhClient()
engine = InvestigationEngine()


@app.get("/health")
async def health() -> dict:
    result = await client.health()
    result["service"] = "FORTRESS XDR AI"
    return result


@app.get("/alerts/recent", response_model=AlertListResponse)
async def recent_alerts(size: int = Query(default=500, ge=1, le=1000)) -> AlertListResponse:
    return await client.recent_alerts(size=size)


@app.get("/alerts/high", response_model=AlertListResponse)
async def high_alerts(size: int = Query(default=500, ge=1, le=1000), min_level: int = Query(default=10, ge=0, le=16)) -> AlertListResponse:
    return await client.high_alerts(size=size, min_level=min_level)


@app.get("/alerts/suricata", response_model=AlertListResponse)
async def suricata_alerts(size: int = Query(default=500, ge=1, le=1000)) -> AlertListResponse:
    return await client.suricata_alerts(size=size)


@app.get("/alerts/search", response_model=AlertListResponse)
async def search_alerts(query: str = Query(default="*"), size: int = Query(default=500, ge=1, le=1000)) -> AlertListResponse:
    return await client.search_alerts(query=query, size=size)


@app.get("/alerts/{alert_id}", response_model=WazuhAlert)
async def get_alert(alert_id: str) -> WazuhAlert:
    alert = await client.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Wazuh alert not found")
    return alert


@app.post("/investigate/{alert_id}", response_model=InvestigationResult)
async def investigate(alert_id: str) -> InvestigationResult:
    alert = await client.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Wazuh alert not found")
    related = (await client.related_alerts(alert)).alerts
    return engine.investigate(alert, related)


@app.post("/hunt", response_model=HuntResponse)
async def hunt(request: HuntRequest) -> HuntResponse:
    query = request.preset or request.query or "*"
    result = await client.hunt(query=query, size=request.size)
    return HuntResponse(query=query, source=result.source, total=result.total, alerts=result.alerts)
