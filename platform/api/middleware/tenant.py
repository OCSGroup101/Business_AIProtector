"""
Tenant middleware — extracts tenant_id from JWT claims and injects it into
request state. The DB session layer then sets search_path per request.
"""

import logging
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Paths that do NOT require tenant context
_PUBLIC_PATHS = {
    "/health",
    "/health/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
}


class TenantMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip public paths
        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        tenant_id = _extract_tenant_id(request)

        if tenant_id:
            request.state.tenant_id = tenant_id
            logger.debug("Tenant context set: %s", tenant_id)
        else:
            # Routes that require tenant context will fail at the dependency level
            request.state.tenant_id = None

        return await call_next(request)


def _extract_tenant_id(request: Request) -> Optional[str]:
    """
    Extract tenant_id from:
    1. JWT claim `tenant_id` (preferred — validated by Kong before reaching here)
    2. X-Tenant-ID header (internal service calls only)
    """
    # Kong validates the JWT and forwards the decoded claim as X-Tenant-ID
    header_tenant = request.headers.get("X-Tenant-ID")
    if header_tenant:
        return header_tenant

    # Direct JWT parsing (dev mode without Kong)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return _decode_tenant_from_jwt(token)

    return None


def _decode_tenant_from_jwt(token: str) -> Optional[str]:
    """
    Decode tenant_id from a JWT without full verification.
    Full verification is Kong's responsibility at the gateway.
    We still validate structure to prevent injection.
    """
    import base64
    import json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        tenant_id = payload.get("tenant_id")
        if tenant_id and isinstance(tenant_id, str) and _is_valid_tenant_id(tenant_id):
            return tenant_id
    except Exception:
        pass
    return None


def _is_valid_tenant_id(tenant_id: str) -> bool:
    """Validate tenant_id format to prevent SQL injection via schema name."""
    import re
    # Must match: alphanumeric and underscores only, 1-50 chars
    return bool(re.match(r'^[a-zA-Z0-9_]{1,50}$', tenant_id))
