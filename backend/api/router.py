"""
GOJO INFINITY SECURITY ∞ — REST API & WEBSOCKET ENGINE
Provides endpoints for the Local Dashboard and mobile clients.
"""

import asyncio
import hmac
from typing import List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.config import settings
from core.engine import engine_runtime
from core.logger import logger
from core.orchestrator import six_eyes
from core.event_engine import event_bus, SecurityEventPayload
from core.permissions import ScopeViolationError
from techniques.infinity.shield import infinity_shield
from techniques.blue.recon import blue_recon
from techniques.red.operations import red_operations
from techniques.purple.intelligence import purple_intel
from techniques.purple.quarantine import quarantine_vault
from techniques.hollow_purple.protocol import HollowPurpleProtocol
from network.diagnostics import NetworkDiagnostics
from network.mapper import NetworkMapper
from network.subnet import SubnetCalculator
from network.dns import DNSAnalyzer
from ip_intelligence.lookup import IPLookupEngine
from ip_intelligence.logger import IPLoggerService
from vulnerability.cve import OFFLINE_CVE_FEED
from laboratory.web_lab import AttackLabSimulator
from laboratory.scenarios import LAB_SCENARIOS
from backend.database import SessionLocal, SecurityEvent, Vulnerability

api_router = APIRouter(prefix="/api")


def _to_http_error(e: Exception) -> HTTPException:
    """Maps domain exceptions to proper HTTP status codes."""
    if isinstance(e, HTTPException):
        return e
    if isinstance(e, ScopeViolationError):
        return HTTPException(status_code=403, detail=str(e))
    if isinstance(e, (ValueError, KeyError, FileNotFoundError)):
        return HTTPException(status_code=400, detail=str(e))
    logger.exception(f"Unhandled API error: {e}")
    return HTTPException(status_code=500, detail="Internal server error")


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


@api_router.get("/infinity/stats")
def get_shield_stats():
    return infinity_shield.get_stats()


class BanRequest(BaseModel):
    ip_address: str = Field(..., min_length=2, max_length=64)
    reason: str = Field(default="Manual dashboard ban", max_length=200)
    duration_minutes: int = Field(default=60, ge=0, le=525600)


@api_router.post("/infinity/ban")
def ban_ip_endpoint(req: BanRequest):
    try:
        rule = infinity_shield.ban_ip(req.ip_address, req.reason, req.duration_minutes)
    except Exception as e:
        raise _to_http_error(e)
    return {"status": "success", "rule_id": rule["id"], "banned_ip": rule["target"]}


@api_router.post("/infinity/unban/{ip_address}")
def unban_ip_endpoint(ip_address: str):
    success = infinity_shield.unban_ip(ip_address)
    return {"status": "success" if success else "not_found", "ip": ip_address}


# --- Blue Reconnaissance ---
class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    project_id: Optional[int] = None
    ports: Optional[List[int]] = None

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: Optional[List[int]]):
        if v is None:
            return v
        if len(v) > settings.MAX_PORTS_PER_SCAN:
            raise ValueError(f"At most {settings.MAX_PORTS_PER_SCAN} ports per scan")
        if any(p < 1 or p > 65535 for p in v):
            raise ValueError("Ports must be between 1 and 65535")
        return sorted(set(v))


@api_router.post("/blue/scan")
async def trigger_blue_scan(req: ScanRequest):
    try:
        results = await blue_recon.scan_target_ports_and_save(req.target.strip(), req.project_id, req.ports)
    except Exception as e:
        raise _to_http_error(e)
    return {"status": "success", "target": req.target, "open_ports": results}


@api_router.get("/blue/web-audit")
async def trigger_web_audit(url: str = Query(..., min_length=1, max_length=2048), project_id: Optional[int] = None):
    try:
        return await blue_recon.audit_web_target(url, project_id=project_id)
    except Exception as e:
        raise _to_http_error(e)


# --- Red Operations ---
class PasswordAuditRequest(BaseModel):
    password: str = Field(..., max_length=1024)


@api_router.post("/red/audit-password")
def audit_password(req: PasswordAuditRequest):
    return red_operations.audit_password_strength(req.password)


# --- Purple Intelligence & Quarantine ---
@api_router.get("/purple/risk")
def get_purple_risk():
    return purple_intel.calculate_risk_index()


@api_router.post("/purple/report")
def generate_report():
    try:
        return purple_intel.generate_unified_security_report()
    except Exception as e:
        raise _to_http_error(e)


@api_router.get("/purple/quarantine")
def list_quarantine():
    return quarantine_vault.list_quarantined_files()


# --- Hollow Purple Protocol ---
class HollowPurpleRequest(BaseModel):
    target: str = Field(default="127.0.0.1", min_length=1, max_length=253)
    project_id: Optional[int] = None


@api_router.post("/hollow-purple/execute")
async def execute_hollow_purple(req: HollowPurpleRequest):
    try:
        return await HollowPurpleProtocol.execute(req.target.strip(), req.project_id)
    except Exception as e:
        raise _to_http_error(e)


# --- Six Eyes Advisor ---
class AskAIRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)


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
def calc_subnet(cidr: str = Query(..., max_length=64, description="e.g. 192.168.1.0/24")):
    return SubnetCalculator.calculate_cidr(cidr)


@api_router.get("/network/dns")
def calc_dns(domain: str = Query(..., min_length=1, max_length=253)):
    return DNSAnalyzer.resolve_domain(domain)


# --- IP Intelligence & Logger ---
@api_router.get("/ip/lookup")
async def lookup_ip_endpoint(ip: str = Query(..., max_length=64)):
    return await IPLookupEngine.lookup_ip(ip)


@api_router.get("/ip/history")
def get_ip_history(limit: int = Query(50, ge=1, le=1000)):
    return IPLoggerService.get_visit_history(limit=limit)


@api_router.get("/ip/export-csv")
def export_ip_csv():
    return {"csv": IPLoggerService.export_csv()}


# --- Vulnerability Center ---
@api_router.get("/vulnerabilities")
def list_vulnerabilities():
    with SessionLocal() as db:
        vulns = db.query(Vulnerability).order_by(Vulnerability.discovered_at.desc()).all()
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
    scenario_id: str = Field(..., max_length=64)
    input_data: str = Field(..., max_length=4096)
    password_attempt: Optional[str] = Field(default=None, max_length=256)


@api_router.post("/lab/simulate")
def simulate_lab_test(req: LabTestRequest):
    if req.scenario_id == "sqli_lab":
        res = AttackLabSimulator.test_sqli_endpoint(req.input_data)
    elif req.scenario_id == "xss_lab":
        res = AttackLabSimulator.test_xss_endpoint(req.input_data)
    elif req.scenario_id == "auth_lab":
        res = AttackLabSimulator.test_auth_endpoint(req.input_data, req.password_attempt or "")
    else:
        raise HTTPException(status_code=404, detail="Scenario not found")
    AttackLabSimulator.record_lab_run(req.scenario_id, 1, res)
    return res


# --- WebSocket Live Telemetry Feed ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.loop = asyncio.get_running_loop()
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
_background_tasks: set = set()


# Hook event bus to broadcast to WebSocket clients
def on_event_broadcast(event: SecurityEventPayload):
    server_loop = ws_manager.loop
    if not ws_manager.active_connections or server_loop is None or server_loop.is_closed():
        return
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
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if current_loop is server_loop:
        # Emitted from an async endpoint / middleware on the server loop
        task = server_loop.create_task(ws_manager.broadcast(msg))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
    else:
        # Emitted from a sync endpoint running in the threadpool
        asyncio.run_coroutine_threadsafe(ws_manager.broadcast(msg), server_loop)


event_bus.subscribe_all(on_event_broadcast)


@api_router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    if settings.API_TOKEN:
        supplied = websocket.query_params.get("token", "")
        if not hmac.compare_digest(supplied.encode(), settings.API_TOKEN.encode()):
            await websocket.close(code=1008)
            return
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keepalive ping/pong
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(websocket)
