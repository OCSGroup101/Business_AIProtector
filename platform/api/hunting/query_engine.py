# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""Natural language → structured hunting query translation via Claude Opus 4.6."""

import json
import logging
import os
from typing import Any, Optional

import anthropic
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_SYSTEM = """\
You translate natural-language threat hunting queries into structured JSON queries
for the OpenClaw telemetry event store.

Available event_types (from the TelemetryEvent model):
  ProcessCreate, ProcessTerminate, FileCreate, FileModify, FileDelete,
  NetworkConnect, NetworkDns, AuthLogon, AuthLogonFailure, AuthPrivilegeEscalation,
  PersistenceCreate, PersistenceModify, IntegrityViolation, RegistryCreate,
  RegistryModify, CommandExecution

Available filter keys (map directly to telemetry event fields):
  hostname, agent_id, rule_id, severity, process_name, file_path,
  destination_ip, destination_port, username, registry_key

Output ONLY a JSON object with these fields:
{
  "event_type": "<EventType or null for all>",
  "filters": {"<key>": "<value>", ...},
  "time_range_hours": <int 1-720>,
  "limit": <int 10-1000>,
  "explanation": "<one sentence: what this query looks for>",
  "natural_language": "<the original query, verbatim>"
}

If the query is ambiguous, choose conservative defaults (24h, limit 100).
Do not add fields not listed above.  Output ONLY JSON.
"""


class HuntingQuery(BaseModel):
    event_type: Optional[str]
    filters: dict[str, Any]
    time_range_hours: int
    limit: int
    explanation: str
    natural_language: str


async def translate_hunting_query(nl_query: str) -> HuntingQuery:
    """
    Translate a natural-language threat hunting query to a structured HuntingQuery.
    Falls back to a permissive default if ANTHROPIC_API_KEY is not set.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — returning default hunting query")
        return HuntingQuery(
            event_type=None,
            filters={},
            time_range_hours=24,
            limit=100,
            explanation="Default query (API key not configured).",
            natural_language=nl_query,
        )

    client = anthropic.AsyncAnthropic(api_key=api_key)

    response = await client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        thinking={"type": "adaptive"},
        system=_SYSTEM,
        messages=[{"role": "user", "content": nl_query}],
    )

    # Extract text block
    text = ""
    for block in response.content:
        if hasattr(block, "type") and block.type == "text":
            text = block.text.strip()
            break

    # Strip markdown fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse hunting query translation: %s", exc)
        return HuntingQuery(
            event_type=None,
            filters={},
            time_range_hours=24,
            limit=100,
            explanation="Query translation failed.",
            natural_language=nl_query,
        )

    return HuntingQuery(
        event_type=data.get("event_type"),
        filters=data.get("filters", {}),
        time_range_hours=max(1, min(int(data.get("time_range_hours", 24)), 720)),
        limit=max(10, min(int(data.get("limit", 100)), 1000)),
        explanation=data.get("explanation", ""),
        natural_language=data.get("natural_language", nl_query),
    )
