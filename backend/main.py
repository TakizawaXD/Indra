"""
GOJO INFINITY SECURITY ∞ — OPTIONAL REST API SERVER & WAF ENGINE
FastAPI application exposing the REST API protected by the Infinity Shield WAF middleware.
There is no web interface: the platform is operated from the interactive terminal
(python -m terminal.shell), which starts/stops this server with "server start|stop".
"""

import hmac
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.config import settings
from core.logger import logger
from core.engine import engine_runtime
from core.notifier import TermuxNotifier  # importing registers Termux alert listeners
from techniques.infinity.shield import infinity_shield
from backend.api.router import api_router
from ip_intelligence.logger import IPLoggerService

from core.engine import SystemState
from core.license import IndraLicenseGuard

# The API serves JSON only; nothing may be framed, scripted or embedded.
CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # When launched from the terminal the engine is already ONLINE: reuse it and
    # do not shut it down when the API server stops.
    started_here = False
    if engine_runtime.state != SystemState.ONLINE:
        started_here = engine_runtime.startup()
        if not started_here:
            logger.warning("[LICENSE] API iniciada en modo BLOQUEADO: todas las rutas /api responderan 403.")
    try:
        IPLoggerService.prune_retention(days=settings.IP_HISTORY_RETENTION_DAYS)
    except Exception as e:  # retention must never block startup
        logger.error(f"IP history retention pruning failed: {e}")
    logger.info(f"Termux push notifications: {'enabled' if TermuxNotifier.HAS_TERMUX_NOTIFY else 'unavailable (terminal fallback)'}")
    if not settings.is_loopback_bind and not settings.API_TOKEN:
        logger.warning(
            "[SECURITY] Server is bound to a non-loopback address without GOJO_API_TOKEN. "
            "Anyone on the network can use the API. Set GOJO_API_TOKEN in .env."
        )
    yield
    if started_here:
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

    # 1. Visit logging for API endpoints.
    #    Stored in the IP history only (no event-bus emission) so that polling clients
    #    do not generate a feedback loop of events.
    if path != "/health":
        try:
            IPLoggerService.record_visit(
                ip_address=client_ip,
                path=path,
                user_agent=request.headers.get("user-agent"),
                consent_status="informed_api_client",
                emit_event=False,
            )
        except Exception as e:
            logger.error(f"Visit logging failed: {e}")

    # 2. Run Infinity Shield Multi-Layer Inspection
    is_allowed, reason, block_type = infinity_shield.inspect_request(
        client_ip=client_ip,
        path=path,
        method=method,
        query_string=query,
        headers={"user-agent": request.headers.get("user-agent", "")},
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

    # 3. License gate: a locked platform does not serve the API
    if path.startswith("/api/") and not IndraLicenseGuard.verify_license():
        return JSONResponse(
            status_code=403,
            content={"error": "Locked", "detail": "Sistema bloqueado. Activa la licencia desde la terminal con 'insertar llave'."},
        )

    # 4. Optional API token authentication
    if settings.API_TOKEN and path.startswith("/api/") and not _token_is_valid(request):
        return JSONResponse(status_code=401, content={"error": "Unauthorized", "detail": "Missing or invalid API token."})

    response = await call_next(request)
    # Inject Security Headers
    response.headers["X-Infinity-Shield"] = "Active"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if not path.startswith(("/docs", "/redoc")):
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


@app.get("/", include_in_schema=False)
async def root():
    return {
        "system": settings.APP_NAME,
        "interface": "terminal",
        "message": "Sin interfaz web. Opera la plataforma con: python -m terminal.shell",
        "api_docs": "/docs",
    }


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": engine_runtime.state}


def start():
    """Headless API mode (no terminal). Prefer 'server start' from the terminal."""
    if not IndraLicenseGuard.verify_license():
        print("[-] Sistema bloqueado: activa la licencia con 'python -m terminal.shell' -> 'insertar llave'.", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level="debug" if settings.DEBUG else "info",
        reload=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    start()
