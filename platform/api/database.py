"""Database engine, session factory, and tenant schema utilities."""

import os
from typing import AsyncGenerator

from fastapi import Request

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://openclaw:openclaw_dev_password@localhost:5432/openclaw",
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=40,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency: yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_tenant_db(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency: yields a session scoped to a tenant's schema.
    Sets search_path to tenant_{tenant_id} for all queries in the session.
    Row-Level Security provides defense-in-depth backup.
    """
    async with AsyncSessionLocal() as session:
        try:
            schema = f"tenant_{tenant_id.replace('-', '_')}"
            await session.execute(
                text(f"SET LOCAL search_path TO {schema}, public")
            )
            await session.execute(
                text(f"SET LOCAL app.tenant_id = '{tenant_id}'")
            )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_tenant_session(
    request: Request,
) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency: yields a tenant-scoped session.
    Extracts tenant_id from the X-Tenant-ID header (set by agent) or from
    TenantMiddleware's request.state.tenant_id (set from JWT for console routes).
    Raises HTTP 400 if no tenant_id can be determined.
    """
    from fastapi import HTTPException

    tenant_id = (
        getattr(request.state, "tenant_id", None)
        or request.headers.get("X-Tenant-ID")
    )
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant ID required")
    async for session in get_tenant_db(tenant_id):
        yield session


async def check_db_connection() -> bool:
    """Check if the database is reachable."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
