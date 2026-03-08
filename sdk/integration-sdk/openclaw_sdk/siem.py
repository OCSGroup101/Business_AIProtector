# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
SIEM/SOAR connector implementations for the OpenClaw Integration SDK.

Provides ready-made connectors for:
  - Splunk (HTTP Event Collector)
  - Elasticsearch
  - Microsoft Sentinel (Azure Monitor HTTP Data Collector)

Usage:
    from openclaw_sdk.siem import SplunkHecConnector

    async with SplunkHecConnector(url="https://splunk:8088", token="HEC_TOKEN") as s:
        await s.send_incident(incident.to_siem_dict())
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from .models import Incident


class SiemConnector(ABC):
    """Abstract base class for SIEM connectors."""

    name: str = "abstract"

    @abstractmethod
    async def send_event(self, event: dict[str, Any]) -> bool:
        """Send a raw event dictionary to the SIEM. Returns True on success."""
        ...

    @abstractmethod
    async def send_incident(self, incident: Incident) -> bool:
        """Send an OpenClaw incident to the SIEM. Returns True on success."""
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity to the SIEM endpoint. Returns True if reachable."""
        ...

    async def __aenter__(self) -> "SiemConnector":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


# ── Splunk HEC ────────────────────────────────────────────────────────────────

class SplunkHecConnector(SiemConnector):
    """
    Splunk HTTP Event Collector (HEC) connector.

    Sends OpenClaw events to a Splunk indexer via the HEC REST API.

    Args:
        url: Splunk HEC base URL, e.g. https://splunk.example.com:8088
        token: HEC token (created in Splunk Settings > Data Inputs > HTTP Event Collector)
        index: Target Splunk index (default: main)
        source_type: Splunk source type for OpenClaw events (default: openclaw:event)
        verify_ssl: Verify TLS certificate (set False for self-signed certs)
    """

    name = "splunk_hec"

    def __init__(
        self,
        url: str,
        token: str,
        index: str = "main",
        source_type: str = "openclaw:event",
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._index = index
        self._source_type = source_type
        self._verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SplunkHecConnector":
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Splunk {self._token}"},
            verify=self._verify_ssl,
            timeout=15.0,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _wrap_event(self, event: dict[str, Any], source_type: Optional[str] = None) -> dict:
        return {
            "time": time.time(),
            "host": event.get("hostname", "openclaw"),
            "source": "openclaw",
            "sourcetype": source_type or self._source_type,
            "index": self._index,
            "event": event,
        }

    async def send_event(self, event: dict[str, Any]) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        payload = json.dumps(self._wrap_event(event))
        try:
            r = await self._client.post(
                f"{self._url}/services/collector/event",
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            return r.status_code in (200, 201)
        except httpx.RequestError:
            return False

    async def send_incident(self, incident: Incident) -> bool:
        return await self.send_event(incident.to_siem_dict())

    async def test_connection(self) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        try:
            r = await self._client.get(f"{self._url}/services/collector/health")
            return r.status_code == 200
        except httpx.RequestError:
            return False


# ── Elasticsearch ─────────────────────────────────────────────────────────────

class ElasticsearchConnector(SiemConnector):
    """
    Elasticsearch connector using the Index API.

    Sends OpenClaw events to Elasticsearch indices.

    Args:
        url: Elasticsearch base URL, e.g. https://es.example.com:9200
        api_key: Elasticsearch API key (base64-encoded id:key pair)
        index_prefix: Index prefix, e.g. "openclaw" → documents go to openclaw-events-YYYY.MM.DD
        verify_ssl: Verify TLS certificate
    """

    name = "elasticsearch"

    def __init__(
        self,
        url: str,
        api_key: str,
        index_prefix: str = "openclaw",
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._prefix = index_prefix
        self._verify_ssl = verify_ssl
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ElasticsearchConnector":
        self._client = httpx.AsyncClient(
            headers={
                "Authorization": f"ApiKey {self._api_key}",
                "Content-Type": "application/json",
            },
            verify=self._verify_ssl,
            timeout=15.0,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _daily_index(self, base: str) -> str:
        today = datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
        return f"{self._prefix}-{base}-{today}"

    async def send_event(self, event: dict[str, Any]) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        index = self._daily_index("events")
        try:
            r = await self._client.post(
                f"{self._url}/{index}/_doc",
                content=json.dumps(event),
            )
            return r.status_code in (200, 201)
        except httpx.RequestError:
            return False

    async def send_incident(self, incident: Incident) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        index = self._daily_index("incidents")
        try:
            r = await self._client.post(
                f"{self._url}/{index}/_doc/{incident.id}",
                content=json.dumps(incident.to_siem_dict()),
            )
            return r.status_code in (200, 201)
        except httpx.RequestError:
            return False

    async def test_connection(self) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        try:
            r = await self._client.get(f"{self._url}/_cluster/health")
            return r.status_code == 200
        except httpx.RequestError:
            return False


# ── Microsoft Sentinel ────────────────────────────────────────────────────────

class SentinelConnector(SiemConnector):
    """
    Microsoft Sentinel connector via the Azure Monitor HTTP Data Collector API.

    Sends OpenClaw events to a Log Analytics workspace.

    Args:
        workspace_id: Azure Log Analytics workspace ID
        shared_key: Primary or secondary shared key for the workspace
        log_type: Custom log type name (default: OpenClawEvent)
        verify_ssl: Verify TLS certificate
    """

    name = "microsoft_sentinel"
    _API_VERSION = "2016-04-01"

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        log_type: str = "OpenClawEvent",
        verify_ssl: bool = True,
    ) -> None:
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type
        self._verify_ssl = verify_ssl
        self._endpoint = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version={self._API_VERSION}"
        )
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SentinelConnector":
        self._client = httpx.AsyncClient(verify=self._verify_ssl, timeout=15.0)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _build_signature(self, content_length: int, date: str) -> str:
        """Build the HMAC-SHA256 authorization header."""
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self._shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self._workspace_id}:{encoded_hash}"

    async def _post_data(self, body: str, log_type: str) -> bool:
        if not self._client:
            raise RuntimeError("Use as async context manager")
        date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body.encode("utf-8"))
        signature = self._build_signature(content_length, date)
        try:
            r = await self._client.post(
                self._endpoint,
                content=body.encode("utf-8"),
                headers={
                    "Authorization": signature,
                    "Log-Type": log_type,
                    "x-ms-date": date,
                    "time-generated-field": "timestamp",
                    "Content-Type": "application/json",
                },
            )
            return r.status_code == 200
        except httpx.RequestError:
            return False

    async def send_event(self, event: dict[str, Any]) -> bool:
        return await self._post_data(json.dumps([event]), self._log_type)

    async def send_incident(self, incident: Incident) -> bool:
        return await self._post_data(
            json.dumps([incident.to_siem_dict()]),
            f"{self._log_type}Incident",
        )

    async def test_connection(self) -> bool:
        # Send an empty test event to validate credentials
        return await self._post_data(
            json.dumps([{"test": True, "source": "openclaw-sdk-connection-test"}]),
            f"{self._log_type}Test",
        )
