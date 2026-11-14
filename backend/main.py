"""
GOJO INFINITY SECURITY ∞ — PRIMARY ASGI WEB SERVER & WAF ENGINE
FastAPI Application serving the Local Dashboard, REST API, and Infinity Shield WAF Middleware.
"""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uvicorn
import time

from core.config import settings
from core.logger import logger
from core.engine import engine_runtime
from core.notifier import TermuxNotifier
from techniques.infinity.shield import infinity_shield
from backend.api.router import api_router
from ip_intelligence.logger import IPLoggerService

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Hybrid Cybersecurity Platform for Android Termux — Blue, Red, Purple, Infinity, Six Eyes."
)

# CORS Middleware (Localhost access from Termux browsers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# INFINITY SHIELD ASGI WAF MIDDLEWARE
# -----------------------------------------------------------------------------
@app.middleware("http")
async def infinity_shield_waf_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    method = request.method
    query = str(request.url.query)

    # 1. Automatic visit logging for managed dashboard / API endpoints
    if not path.startswith("/static") and not path.endswith((".css", ".js", ".png", ".ico")):
        IPLoggerService.record_visit(
            ip_address=client_ip,
            path=path,
            user_agent=request.headers.get("user-agent"),
            consent_status="informed_dashboard_operator"
        )

    # 2. Run Infinity Shield Multi-Layer Inspection
    is_allowed, reason, block_type = infinity_shield.inspect_request(
        client_ip=client_ip,
        path=path,
        method=method,
        query_string=query
    )

    if not is_allowed:
        status_code = 429 if block_type == "RATE_LIMIT" else 403
        return JSONResponse(
            status_code=status_code,
            content={
                "error": "Access Blocked by Infinity Shield",
                "reason": reason,
                "block_type": block_type,
                "client_ip": client_ip,
                "domain_expansion": "Limitless Void — Nothing gets through Infinity."
            }
        )

    response = await call_next(request)
    # Inject Security Headers
    response.headers["X-Infinity-Shield"] = "Active"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Mount REST API
app.include_router(api_router)

# Mount Static Frontend
FRONTEND_DIR = settings.BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": f"{settings.APP_NAME} is active. Frontend index initializing."}

@app.on_event("startup")
async def on_startup():
    engine_runtime.startup()
    logger.info(f"Local Web Dashboard listening at: http://{settings.HOST}:{settings.PORT}")

@app.on_event("shutdown")
async def on_shutdown():
    engine_runtime.shutdown()

def start():
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="info",
        reload=False
    )

if __name__ == "__main__":
    start()
