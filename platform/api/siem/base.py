# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Base SIEM connector abstract class."""

from abc import ABC, abstractmethod
from typing import Any


class SiemConnector(ABC):
    name: str

    @abstractmethod
    async def send_event(self, event: dict[str, Any]) -> bool:
        """Send a single telemetry event to the SIEM."""
        ...

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity to the SIEM endpoint. Returns True on success."""
        ...

    @abstractmethod
    async def send_incident(self, incident: dict[str, Any]) -> bool:
        """Forward an incident record to the SIEM. Returns True on success."""
        ...
