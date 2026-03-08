"""
OpenClaw Platform API
FastAPI application entry point — agent-facing + console-facing API.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import os

from . import pki
from .middleware.tenant import TenantMiddleware
from .routes import (
    admin,
    agents,
    audit,
    cert_renewal,
    community_ioc,
    correlation,
    coverage,
    deployments,
    enrollment,
    feedback,
    heartbeat,
    hunting,
    incidents,
    intel,
    intel_feeds,
    msp,
    policies,
    reports,
    risk,
    rules,
    siem,
    telemetry,
)
from .database import engine, Base
from .intel.feed_runner import start_feed_tasks
from .kafka.producer import kafka_producer
from .kafka.consumer import kafka_consumer
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

    # Start Kafka producer and consumer
    await kafka_producer.start()
    await kafka_consumer.start()

    # In dev mode, create all tables directly (no Alembic migration needed).
    # In production, migrations are applied explicitly before startup.
    if os.getenv("OPENCLAW_DEV_MODE", "").lower() == "true":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    yield

    # Cancel feed tasks on shutdown
    for task in feed_tasks:
        task.cancel()

    await kafka_consumer.stop()
    await kafka_producer.stop()

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
app.include_router(cert_renewal.router, prefix="/api/v1/agents", tags=["enrollment"])
app.include_router(telemetry.router, prefix="/api/v1/telemetry", tags=["telemetry"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["policies"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(intel.router, prefix="/api/v1/intel", tags=["intelligence"])
app.include_router(intel_feeds.router, prefix="/api/v1/intel/custom-feeds", tags=["intelligence"])
app.include_router(community_ioc.router, prefix="/api/v1/intel/community", tags=["intelligence"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["audit"])
app.include_router(rules.router, prefix="/api/v1/rules", tags=["rules"])
app.include_router(siem.router, prefix="/api/v1/siem", tags=["siem"])
app.include_router(deployments.router, prefix="/api/v1/deployments", tags=["deployments"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(msp.router, prefix="/api/v1/msp", tags=["msp"])
app.include_router(correlation.router, prefix="/api/v1/correlation", tags=["ai"])
app.include_router(hunting.router, prefix="/api/v1/hunting", tags=["ai"])
app.include_router(risk.router, prefix="/api/v1", tags=["ai"])
app.include_router(coverage.router, prefix="/api/v1/coverage", tags=["ai"])
app.include_router(feedback.router, prefix="/api/v1/incidents", tags=["ai"])


# ─── Health check ─────────────────────────────────────────────────────────────


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """Platform health endpoint — used by load balancers and Docker healthchecks."""
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/health/ready", tags=["health"], response_model=None)
async def readiness_check() -> dict | JSONResponse:
    """Readiness check — verifies database connectivity."""
    from .database import check_db_connection

    db_ok = await check_db_connection()
    if not db_ok:
        return JSONResponse(
            status_code=503, content={"status": "not_ready", "db": "unreachable"}
        )
    return {"status": "ready"}


# ─── Global exception handler ─────────────────────────────────────────────────


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    safe_url = str(request.url).replace("\n", "\\n").replace("\r", "\\r")
    logger.exception("Unhandled exception for %s %s", request.method, safe_url)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
