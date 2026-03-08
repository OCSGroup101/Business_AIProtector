# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
OpenClaw Platform API — async HTTP client.

Usage:
    async with OpenClawClient("https://openclaw.example.com", token="dev-admin-token") as c:
        incidents = await c.list_incidents(status="OPEN", limit=50)
        await c.resolve_incident(incidents[0].id, notes="Remediated by EDR")
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Literal, Optional

import httpx

from .models import Agent, AuditEntry, Incident, IocEntry, Policy, TelemetryEvent

IncidentStatus = Literal["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]


class OpenClawClient:
    """
    Async client for the OpenClaw Platform REST API.

    Supports context manager usage:
        async with OpenClawClient(base_url, token=..., tenant_id=...) as client:
            ...

    Or manual lifecycle:
        client = OpenClawClient(base_url, token=...)
        await client.__aenter__()
        ...
        await client.__aexit__(None, None, None)
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        tenant_id: str = "dev",
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": tenant_id,
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=timeout,
            verify=verify_ssl,
        )

    async def __aenter__(self) -> "OpenClawClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._client.__aexit__(*args)

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(self) -> dict[str, Any]:
        """Return platform health status."""
        r = await self._client.get("/health/ready")
        r.raise_for_status()
        return r.json()

    # ── Incidents ─────────────────────────────────────────────────────────────

    async def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[Incident]:
        """List incidents, optionally filtered by status and agent."""
        params: dict[str, Any] = {"limit": limit}
        if status:
            params["status"] = status
        if agent_id:
            params["agent_id"] = agent_id
        r = await self._client.get("/api/v1/incidents", params=params)
        r.raise_for_status()
        return [Incident.model_validate(i) for i in r.json()]

    async def get_incident(self, incident_id: str) -> Incident:
        """Get a single incident by ID."""
        r = await self._client.get(f"/api/v1/incidents/{incident_id}")
        r.raise_for_status()
        return Incident.model_validate(r.json())

    async def resolve_incident(
        self, incident_id: str, notes: Optional[str] = None
    ) -> Incident:
        """Resolve an incident with optional resolution notes."""
        r = await self._client.post(
            f"/api/v1/incidents/{incident_id}/resolve",
            json={"resolution_notes": notes},
        )
        r.raise_for_status()
        return Incident.model_validate(r.json())

    async def assign_incident(self, incident_id: str, analyst: str) -> Incident:
        """Assign an incident to an analyst by username."""
        r = await self._client.post(
            f"/api/v1/incidents/{incident_id}/assign",
            json={"assigned_to": analyst},
        )
        r.raise_for_status()
        return Incident.model_validate(r.json())

    async def update_incident_status(
        self, incident_id: str, status: IncidentStatus
    ) -> Incident:
        """Transition an incident to a new status."""
        r = await self._client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": status},
        )
        r.raise_for_status()
        return Incident.model_validate(r.json())

    # ── Agents ────────────────────────────────────────────────────────────────

    async def list_agents(self) -> list[Agent]:
        """List all enrolled agents for the tenant."""
        r = await self._client.get("/api/v1/agents")
        r.raise_for_status()
        return [Agent.model_validate(a) for a in r.json()]

    async def isolate_agent(self, agent_id: str, reason: str) -> dict[str, Any]:
        """Isolate an agent (network quarantine)."""
        r = await self._client.post(
            f"/api/v1/agents/{agent_id}/isolate",
            json={"reason": reason},
        )
        r.raise_for_status()
        return r.json()

    # ── Telemetry ─────────────────────────────────────────────────────────────

    async def upload_telemetry_batch(
        self, events: list[TelemetryEvent], agent_id: str
    ) -> dict[str, Any]:
        """Upload a batch of telemetry events (NDJSON)."""
        ndjson = "\n".join(e.to_ndjson_line() for e in events) + "\n"
        r = await self._client.post(
            "/api/v1/telemetry/batch",
            content=ndjson.encode(),
            headers={
                **self._headers,
                "Content-Type": "application/x-ndjson",
                "X-Agent-ID": agent_id,
            },
        )
        r.raise_for_status()
        return r.json()

    # ── IOC Bundle ────────────────────────────────────────────────────────────

    async def stream_ioc_bundle(
        self, since: Optional[str] = None
    ) -> AsyncIterator[IocEntry]:
        """
        Stream the IOC bundle as an async iterator of IocEntry objects.
        Yields one IocEntry per NDJSON line (upsert or delete).
        """
        params = {}
        if since:
            params["since"] = since

        async with self._client.stream(
            "GET", "/api/v1/intel/ioc-bundle", params=params
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                yield IocEntry.model_validate(obj)

    # ── Audit ─────────────────────────────────────────────────────────────────

    async def list_audit_logs(
        self,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[AuditEntry]:
        """List audit log entries."""
        params: dict[str, Any] = {"limit": limit}
        if action:
            params["action"] = action
        if actor_id:
            params["actor_id"] = actor_id
        r = await self._client.get("/api/v1/audit", params=params)
        r.raise_for_status()
        data = r.json()
        entries = data.get("entries", data) if isinstance(data, dict) else data
        return [AuditEntry.model_validate(e) for e in entries]

    # ── Policies ──────────────────────────────────────────────────────────────

    async def list_policies(self) -> list[Policy]:
        """List detection policies for the tenant."""
        r = await self._client.get("/api/v1/policies")
        r.raise_for_status()
        return [Policy.model_validate(p) for p in r.json()]

    async def create_policy(self, name: str, content_toml: str) -> Policy:
        """Create a new detection policy from TOML content."""
        r = await self._client.post(
            "/api/v1/policies",
            json={"name": name, "content_toml": content_toml},
        )
        r.raise_for_status()
        return Policy.model_validate(r.json())
