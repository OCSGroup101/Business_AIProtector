# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Splunk HTTP Event Collector (HEC) connector."""

import logging
import time
from typing import Any

import httpx

from .base import SiemConnector

logger = logging.getLogger(__name__)


class SplunkHecConnector(SiemConnector):
    name = "splunk"

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
        self._headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        }

    async def send_event(self, event: dict[str, Any]) -> bool:
        """POST event to Splunk HEC /services/collector/event."""
        payload = {
            "time": time.time(),
            "sourcetype": self._source_type,
            "index": self._index,
            "source": "openclaw",
            "event": event,
        }
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/services/collector/event",
                    json=payload,
                    headers=self._headers,
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Splunk send_event failed: %s", exc)
            return False

    async def send_incident(self, incident: dict[str, Any]) -> bool:
        """Forward an incident to Splunk with sourcetype openclaw:incident."""
        payload = {
            "time": time.time(),
            "sourcetype": "openclaw:incident",
            "index": self._index,
            "source": "openclaw",
            "event": incident,
        }
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/services/collector/event",
                    json=payload,
                    headers=self._headers,
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Splunk send_incident failed: %s", exc)
            return False

    async def test_connection(self) -> bool:
        """GET /services/collector/health to verify HEC is reachable."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.get(
                    f"{self._url}/services/collector/health",
                    headers=self._headers,
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("Splunk test_connection failed: %s", exc)
            return False
