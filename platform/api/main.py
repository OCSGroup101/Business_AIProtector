"""
OpenClaw Platform API
FastAPI application entry point — agent-facing + console-facing API.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import pki
from .middleware.tenant import TenantMiddleware
from .middleware.rbac import RBACMiddleware
from .routes import (
    admin,
    agents,
    audit,
    enrollment,
    heartbeat,
    incidents,
    intel,
    policies,
    telemetry,
)
from .database import engine, Base
from .intel.feed_runner import start_feed_tasks
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle."""
    logger.info("OpenClaw Platform API starting up")

    # Initialize platform CA (load from env/disk, or generate dev CA)
    pki.initialize_ca()

    # Start background threat intelligence feed tasks
    feed_tasks = start_feed_tasks()

    # Run Alembic migrations on startup in dev; use explicit migration in prod
    # async with engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)

    yield

    # Cancel feed tasks on shutdown
    for task in feed_tasks:
        task.cancel()

    logger.info("OpenClaw Platform API shutting down")
    await engine.dispose()


app = FastAPI(
    title="OpenClaw Platform API",
    version="0.1.0",
    description="Agent-facing and console-facing API for the OpenClaw endpoint security platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ─── Middleware ───────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Console dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tenant context middleware — extracts tenant_id from JWT and sets DB schema
app.add_middleware(TenantMiddleware)

# ─── Routers ─────────────────────────────────────────────────────────────────

app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(enrollment.router, prefix="/api/v1/agents", tags=["enrollment"])
app.include_router(heartbeat.router, prefix="/api/v1/agents", tags=["heartbeat"])
app.include_router(telemetry.router, prefix="/api/v1/telemetry", tags=["telemetry"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["policies"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["intelligence"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """Platform health endpoint — used by load balancers and Docker healthchecks."""
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/health/ready", tags=["health"])
async def readiness_check() -> dict:
    """Readiness check — verifies database connectivity."""
    from .database import check_db_connection
    db_ok = await check_db_connection()
    if not db_ok:
        return JSONResponse(status_code=503, content={"status": "not_ready", "db": "unreachable"})
    return {"status": "ready"}


# ─── Global exception handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s %s", request.method, request.url)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
