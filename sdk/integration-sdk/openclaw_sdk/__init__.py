# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
OpenClaw Integration SDK

Provides:
  - OpenClawClient: typed async client for the platform REST API
  - SiemConnector base classes for Splunk, Elasticsearch, Sentinel
  - Event/Incident models for type-safe integration

Example:
    from openclaw_sdk import OpenClawClient

    async with OpenClawClient("https://openclaw.example.com", token="...") as client:
        incidents = await client.list_incidents(status="OPEN")
        for inc in incidents:
            print(inc.rule_name, inc.severity)
"""

from .client import OpenClawClient
from .models import Incident, Agent, Policy, AuditEntry, TelemetryEvent
from .siem import SiemConnector, SplunkHecConnector, ElasticsearchConnector, SentinelConnector

__version__ = "0.1.0"
__all__ = [
    "OpenClawClient",
    "Incident",
    "Agent",
    "Policy",
    "AuditEntry",
    "TelemetryEvent",
    "SiemConnector",
    "SplunkHecConnector",
    "ElasticsearchConnector",
    "SentinelConnector",
]
