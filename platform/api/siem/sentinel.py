# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Microsoft Sentinel (Azure Monitor HTTP Data Collector API) connector."""

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from email.utils import formatdate
from typing import Any

import httpx

from .base import SiemConnector

logger = logging.getLogger(__name__)

_LOG_ANALYTICS_URL = (
    "https://{workspace_id}.ods.opinsights.azure.com"
    "/api/logs?api-version=2016-04-01"
)


class SentinelConnector(SiemConnector):
    name = "sentinel"

    def __init__(
        self,
        workspace_id: str,
        shared_key: str,
        log_type: str = "OpenClawEvent",
    ) -> None:
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type
        self._endpoint = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

    def _build_signature(
        self,
        content_length: int,
        date: str,
        content_type: str,
        resource: str,
    ) -> str:
        """Compute HMAC-SHA256 Authorization header value for Log Analytics."""
        string_to_hash = (
            f"POST\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self._shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode("utf-8")
        return f"SharedKey {self._workspace_id}:{encoded_hash}"

    async def _post(self, body: list[dict[str, Any]], log_type: str) -> bool:
        """Internal POST to the Azure Monitor Data Collector API."""
        body_json = json.dumps(body)
        body_bytes = body_json.encode("utf-8")
        content_length = len(body_bytes)
        rfc1123_date = formatdate(usegmt=True)
        content_type = "application/json"
        resource = "/api/logs"

        signature = self._build_signature(
            content_length, rfc1123_date, content_type, resource
        )
        headers = {
            "Content-Type": content_type,
            "Authorization": signature,
            "Log-Type": log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    self._endpoint, content=body_bytes, headers=headers
                )
                # 200 = accepted
                return resp.status_code in (200, 204)
        except Exception as exc:
            logger.warning("Sentinel _post failed: %s", exc)
            return False

    async def send_event(self, event: dict[str, Any]) -> bool:
        """Send a telemetry event to Microsoft Sentinel."""
        record = dict(event)
        record.setdefault(
            "TimeGenerated",
            datetime.now(tz=timezone.utc).isoformat(),
        )
        return await self._post([record], self._log_type)

    async def send_incident(self, incident: dict[str, Any]) -> bool:
        """Send an incident record to Microsoft Sentinel as OpenClawIncident log type."""
        record = dict(incident)
        record.setdefault(
            "TimeGenerated",
            datetime.now(tz=timezone.utc).isoformat(),
        )
        return await self._post([record], "OpenClawIncident")

    async def test_connection(self) -> bool:
        """Send a minimal test record to validate workspace credentials."""
        test_record = {
            "TimeGenerated": datetime.now(tz=timezone.utc).isoformat(),
            "Message": "OpenClaw connectivity test",
        }
        return await self._post([test_record], self._log_type)
