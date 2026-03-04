"""
RBAC middleware and permission helpers.

Roles: tenant_admin | security_admin | helpdesk | auditor
Permission enforcement via FastAPI dependencies.
"""

from enum import Enum
from functools import wraps
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status


class Role(str, Enum):
    TENANT_ADMIN = "tenant_admin"
    SECURITY_ADMIN = "security_admin"
    HELPDESK = "helpdesk"
    AUDITOR = "auditor"


class Permission(str, Enum):
    # Agent / policy management
    AGENTS_READ = "agents:read"
    AGENTS_WRITE = "agents:write"
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"
    # Containment
    CONTAINMENT_APPLY = "containment:apply"
    # Incident management
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    INCIDENTS_RESOLVE = "incidents:resolve"
    # User management
    USERS_MANAGE = "users:manage"
    # Audit logs
    AUDIT_READ = "audit:read"
    # Intelligence
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"


# Permission matrix
_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.TENANT_ADMIN: {
        Permission.AGENTS_READ, Permission.AGENTS_WRITE,
        Permission.POLICIES_READ, Permission.POLICIES_WRITE,
        Permission.CONTAINMENT_APPLY,
        Permission.INCIDENTS_READ, Permission.INCIDENTS_WRITE, Permission.INCIDENTS_RESOLVE,
        Permission.USERS_MANAGE,
        Permission.AUDIT_READ,
        Permission.INTEL_READ, Permission.INTEL_WRITE,
    },
    Role.SECURITY_ADMIN: {
        Permission.AGENTS_READ, Permission.AGENTS_WRITE,
        Permission.POLICIES_READ, Permission.POLICIES_WRITE,
        Permission.CONTAINMENT_APPLY,
        Permission.INCIDENTS_READ, Permission.INCIDENTS_WRITE, Permission.INCIDENTS_RESOLVE,
        Permission.AUDIT_READ,
        Permission.INTEL_READ, Permission.INTEL_WRITE,
    },
    Role.HELPDESK: {
        Permission.AGENTS_READ,
        Permission.POLICIES_READ,
        Permission.INCIDENTS_READ,
        Permission.AUDIT_READ,
    },
    Role.AUDITOR: {
        Permission.AGENTS_READ,
        Permission.POLICIES_READ,
        Permission.INCIDENTS_READ,
        Permission.AUDIT_READ,
        Permission.INTEL_READ,
    },
}


def get_current_user_role(request: Request) -> Role:
    """
    Extract the user's role from the JWT claim.
    In production this is validated by Kong; here we decode from request state.
    """
    role_str = getattr(request.state, "user_role", None)
    if role_str is None:
        # Try to extract from JWT
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            role_str = _extract_role_from_jwt(auth[7:])

    if role_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    try:
        return Role(role_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Unknown role: {role_str}",
        )


def require_permission(permission: Permission) -> Callable:
    """FastAPI dependency factory — raises 403 if role lacks the permission."""
    def dependency(role: Role = Depends(get_current_user_role)) -> Role:
        if permission not in _ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' does not have permission '{permission}'",
            )
        return role
    return dependency


def _extract_role_from_jwt(token: str) -> Optional[str]:
    import base64
    import json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        # Keycloak realm roles are under resource_access.openclaw-console.roles
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        for role in realm_roles:
            if role in {r.value for r in Role}:
                return role
        return None
    except Exception:
        return None


class RBACMiddleware:
    """Placeholder — RBAC is enforced per-route via Depends(require_permission(...))."""
    pass
