# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Elasticsearch SIEM connector."""

import logging
from typing import Any

import httpx

from .base import SiemConnector

logger = logging.getLogger(__name__)


class ElasticsearchConnector(SiemConnector):
    name = "elasticsearch"

    def __init__(
        self,
        url: str,
        index_prefix: str = "openclaw",
        api_key: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/")
        self._index_prefix = index_prefix
        self._verify_ssl = verify_ssl
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"ApiKey {api_key}"

    async def send_event(self, event: dict[str, Any]) -> bool:
        """POST event document to {index_prefix}-events/_doc."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/{self._index_prefix}-events/_doc",
                    json=event,
                    headers=self._headers,
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Elasticsearch send_event failed: %s", exc)
            return False

    async def send_incident(self, incident: dict[str, Any]) -> bool:
        """POST incident document to {index_prefix}-incidents/_doc."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.post(
                    f"{self._url}/{self._index_prefix}-incidents/_doc",
                    json=incident,
                    headers=self._headers,
                )
                resp.raise_for_status()
                return True
        except Exception as exc:
            logger.warning("Elasticsearch send_incident failed: %s", exc)
            return False

    async def test_connection(self) -> bool:
        """GET /_cluster/health to verify cluster is reachable."""
        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=10) as client:
                resp = await client.get(
                    f"{self._url}/_cluster/health",
                    headers=self._headers,
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("Elasticsearch test_connection failed: %s", exc)
            return False
