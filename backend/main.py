"""
GOJO INFINITY SECURITY ∞ — PRIMARY ASGI WEB SERVER & WAF ENGINE
FastAPI Application serving the Local Dashboard, REST API, and Infinity Shield WAF Middleware.
"""

import hmac
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.logger import logger
from core.engine import engine_runtime
from core.notifier import TermuxNotifier  # importing registers Termux alert listeners
from techniques.infinity.shield import infinity_shield
from backend.api.router import api_router
from ip_intelligence.logger import IPLoggerService

FRONTEND_DIR = settings.BASE_DIR / "frontend"
STATIC_SUFFIXES = (".css", ".js", ".png", ".ico", ".svg", ".woff", ".woff2", ".map")

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from core.license import IndraLicenseGuard
    if IndraLicenseGuard.verify_license():
        engine_runtime.startup()
    else:
        logger.warning("[LICENSE] INDRA INFINITY SECURITY iniciado en modo BLOQUEADO. Esperando llave de licencia.")
    try:
        IPLoggerService.prune_retention(days=settings.IP_HISTORY_RETENTION_DAYS)
    except Exception as e:  # retention must never block startup
        logger.error(f"IP history retention pruning failed: {e}")
    logger.info(f"Local Web Dashboard listening at: http://{settings.HOST}:{settings.PORT}")
    logger.info(f"Termux push notifications: {'enabled' if TermuxNotifier.HAS_TERMUX_NOTIFY else 'unavailable (terminal fallback)'}")
    if not settings.is_loopback_bind and not settings.API_TOKEN:
        logger.warning(
            "[SECURITY] Server is bound to a non-loopback address without GOJO_API_TOKEN. "
            "Anyone on the network can use the API. Set GOJO_API_TOKEN in .env."
        )
    yield
    engine_runtime.shutdown()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Hybrid Cybersecurity Platform for Android Termux — Blue, Red, Purple, Infinity, Six Eyes.",
    lifespan=lifespan,
)


def _token_is_valid(request: Request) -> bool:
    supplied = request.headers.get("x-api-key") or request.query_params.get("token") or ""
    return hmac.compare_digest(supplied.encode(), settings.API_TOKEN.encode())


# -----------------------------------------------------------------------------
# INFINITY SHIELD ASGI WAF MIDDLEWARE
# -----------------------------------------------------------------------------
@app.middleware("http")
async def infinity_shield_waf_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    method = request.method
    query = str(request.url.query)

    # 1. Visit logging for managed dashboard / API endpoints.
    #    Stored in the IP history only (no event-bus emission) so that the dashboard's
    #    own polling does not generate a feedback loop of events.
    if not path.startswith("/static") and not path.endswith(STATIC_SUFFIXES):
        try:
            IPLoggerService.record_visit(
                ip_address=client_ip,
                path=path,
                user_agent=request.headers.get("user-agent"),
                consent_status="informed_dashboard_operator",
                emit_event=False,
            )
        except Exception as e:
            logger.error(f"Visit logging failed: {e}")

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

    # 3. Optional API token authentication
    if settings.API_TOKEN and path.startswith("/api/") and not _token_is_valid(request):
        return JSONResponse(status_code=401, content={"error": "Unauthorized", "detail": "Missing or invalid API token."})

    response = await call_next(request)
    # Inject Security Headers
    response.headers["X-Infinity-Shield"] = "Active"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if path == "/" or path.startswith("/static"):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response


# Middlewares added later run first: TrustedHost -> CORS -> WAF.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

# Mount REST API
app.include_router(api_router)

# Mount Static Frontend
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": f"{settings.APP_NAME} is active. Frontend index initializing."}


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": engine_runtime.state}


def start():
    import socket
    target_port = settings.PORT
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((settings.HOST, target_port)) == 0:
                logger.warning(f"Puerto {target_port} ocupado. Conmutando a {target_port + 1}...")
                target_port += 1
    except Exception:
        pass

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=target_port,
        log_level="debug" if settings.DEBUG else "info",
        reload=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    start()
