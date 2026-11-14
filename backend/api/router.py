"""
GOJO INFINITY SECURITY ∞ — REST API & WEBSOCKET ENGINE
Provides endpoints for the Local Web Dashboard and mobile clients.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from core.engine import engine_runtime
from core.orchestrator import six_eyes
from core.event_engine import event_bus, SecurityEventPayload
from techniques.infinity.shield import infinity_shield
from techniques.blue.recon import blue_recon
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from techniques.purple.quarantine import quarantine_vault
from techniques.hollow_purple.protocol import HollowPurpleProtocol
from network.diagnostics import NetworkDiagnostics
from network.mapper import NetworkMapper
from network.ports import PortScanner
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from vulnerability.cve import CVEIntelligence, OFFLINE_CVE_FEED
from vulnerability.validator import VulnerabilityValidator
from laboratory.web_lab import AttackLabSimulator
from laboratory.scenarios import LAB_SCENARIOS
from backend.database import SessionLocal, SecurityEvent, Vulnerability, Threat, Incident, Host, Port

api_router = APIRouter(prefix="/api")

# --- Telemetry & System Status ---
@api_router.get("/telemetry")
def get_system_telemetry():
    return engine_runtime.get_telemetry()

@api_router.get("/overview")
def get_dashboard_overview():
    correlation = six_eyes.analyze_event_correlation()
    telemetry = engine_runtime.get_telemetry()

    with SessionLocal() as db:
        recent_events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(10).all()
        events_list = [
            {
                "id": e.id,
                "type": e.event_type,
                "module": e.origin_module,
                "severity": e.severity,
                "description": e.description,
                "time": e.created_at.strftime("%H:%M:%S")
            }
            for e in recent_events
        ]

    return {
        "telemetry": telemetry,
        "correlation": correlation,
        "recent_events": events_list
    }

# --- Infinity Shield ---
@api_router.get("/infinity/rules")
def get_shield_rules():
    return infinity_shield.get_active_rules()

class BanRequest(BaseModel):
    ip_address: str
    reason: str = "Manual dashboard ban"
    duration_minutes: int = 60

@api_router.post("/infinity/ban")
def ban_ip_endpoint(req: BanRequest):
    rule = infinity_shield.ban_ip(req.ip_address, req.reason, req.duration_minutes)
    return {"status": "success", "rule_id": rule.id, "banned_ip": req.ip_address}

@api_router.post("/infinity/unban/{ip_address}")
def unban_ip_endpoint(ip_address: str):
    success = infinity_shield.unban_ip(ip_address)
    return {"status": "success" if success else "not_found", "ip": ip_address}

# --- Blue Reconnaissance ---
class ScanRequest(BaseModel):
    target: str
    project_id: Optional[int] = None
    ports: Optional[List[int]] = None

@api_router.post("/blue/scan")
async def trigger_blue_scan(req: ScanRequest):
    try:
        results = await blue_recon.scan_target_ports_and_save(req.target, req.project_id, req.ports)
        return {"status": "success", "target": req.target, "open_ports": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/blue/web-audit")
async def trigger_web_audit(url: str):
    try:
        results = await blue_recon.audit_web_target(url)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# --- Red Operations ---
class PasswordAuditRequest(BaseModel):
    password: str

@api_router.post("/red/audit-password")
def audit_password(req: PasswordAuditRequest):
    return red_operations.audit_password_strength(req.password)

# --- Purple Intelligence & Quarantine ---
@api_router.get("/purple/risk")
def get_purple_risk():
    return purple_intel.calculate_risk_index()

@api_router.post("/purple/report")
def generate_report():
    return purple_intel.generate_unified_security_report()

@api_router.get("/purple/quarantine")
def list_quarantine():
    return quarantine_vault.list_quarantined_files()

# --- Hollow Purple Protocol ---
class HollowPurpleRequest(BaseModel):
    target: str = "127.0.0.1"
    project_id: Optional[int] = None

@api_router.post("/hollow-purple/execute")
async def execute_hollow_purple(req: HollowPurpleRequest):
    try:
        res = await HollowPurpleProtocol.execute(req.target, req.project_id)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# --- Six Eyes Advisor ---
class AskAIRequest(BaseModel):
    question: str

@api_router.post("/sixeyes/ask")
def ask_six_eyes(req: AskAIRequest):
    return six_eyes.ai.ask(req.question)

# --- Network Intelligence ---
@api_router.get("/network/topology")
def get_topology():
    return NetworkMapper.generate_topology_graph()

@api_router.get("/network/diagnostics")
def get_network_diagnostics():
    return NetworkDiagnostics.get_device_ip_overview()

@api_router.get("/network/subnet")
def calc_subnet(cidr: str = Query(..., description="e.g. 192.168.1.0/24")):
    return SubnetCalculator.calculate_cidr(cidr)

@api_router.get("/network/dns")
def calc_dns(domain: str):
    return DNSAnalyzer.resolve_domain(domain)

# --- IP Intelligence & Logger ---
@api_router.get("/ip/lookup")
async def lookup_ip_endpoint(ip: str):
    return await IPLookupEngine.lookup_ip(ip)

@api_router.get("/ip/history")
def get_ip_history(limit: int = 50):
    return IPLoggerService.get_visit_history(limit=limit)

@api_router.get("/ip/export-csv")
def export_ip_csv():
    return {"csv": IPLoggerService.export_csv()}

# --- Vulnerability Center ---
@api_router.get("/vulnerabilities")
def list_vulnerabilities():
    with SessionLocal() as db:
        vulns = db.query(Vulnerability).all()
        return [
            {
                "id": v.id,
                "title": v.title,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "status": v.status,
                "target": v.target,
                "description": v.description,
                "mitigation": v.mitigation,
                "discovered_at": v.discovered_at.isoformat()
            }
            for v in vulns
        ]

@api_router.get("/cve/feed")
def get_cve_feed():
    return OFFLINE_CVE_FEED

# --- Attack Lab ---
@api_router.get("/lab/scenarios")
def get_lab_scenarios():
    return list(LAB_SCENARIOS.values())

class LabTestRequest(BaseModel):
    scenario_id: str
    input_data: str
    password_attempt: Optional[str] = None

@api_router.post("/lab/simulate")
def simulate_lab_test(req: LabTestRequest):
    if req.scenario_id == "sqli_lab":
        res = AttackLabSimulator.test_sqli_endpoint(req.input_data)
        AttackLabSimulator.record_lab_run("sqli_lab", 1, res)
        return res
    elif req.scenario_id == "xss_lab":
        res = AttackLabSimulator.test_xss_endpoint(req.input_data)
        AttackLabSimulator.record_lab_run("xss_lab", 1, res)
        return res
    elif req.scenario_id == "auth_lab":
        res = AttackLabSimulator.test_auth_endpoint(req.input_data, req.password_attempt or "")
        AttackLabSimulator.record_lab_run("auth_lab", 1, res)
        return res
    else:
        raise HTTPException(status_code=404, detail="Scenario not found")

# --- WebSocket Live Telemetry Feed ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# Hook event bus to broadcast to WebSocket clients
def on_event_broadcast(event: SecurityEventPayload):
    import asyncio
    try:
        msg = {
            "type": "SECURITY_EVENT",
            "data": {
                "id": event.id,
                "event_type": event.event_type,
                "module": event.origin_module,
                "severity": event.severity,
                "description": event.description,
                "time": event.created_at.strftime("%H:%M:%S")
            }
        }
        loop = asyncio.get_running_loop()
        loop.create_task(ws_manager.broadcast(msg))
    except Exception:
        pass

event_bus.subscribe_all(on_event_broadcast)

@api_router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
