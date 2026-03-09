# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Correlation agent — Claude Opus 4.6 agentic loop for multi-incident
pattern detection.  Uses the manual tool-use loop (not tool_runner) to
preserve tenant-scoped DB access and enforce a max-iteration guard.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import anthropic
from sqlalchemy.ext.asyncio import AsyncSession

from .models import CorrelationInsight, CorrelationResult
from .tools import TOOL_DEFINITIONS, execute_tool

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an expert threat intelligence analyst performing automated incident correlation
for a security operations center.

Your goal: analyze the tenant's recent security incidents, identify patterns that
suggest coordinated or multi-stage attacks, and produce a structured JSON report.

Workflow:
1. Call query_recent_incidents to fetch recent incidents (start with 7 days, all severities).
2. For any cluster of incidents on the same host, call get_agent_timeline.
3. Call get_shared_iocs on incident clusters to find common techniques/rules.
4. Call get_mitre_chain on shared techniques to assess kill-chain progression.
5. For any suspicious hashes or IPs mentioned in rule names, call lookup_ioc.
6. After analysis, output a JSON object — nothing else — matching this schema:

{
  "incidents_analyzed": <int>,
  "overall_threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "summary": "<2-3 sentence executive summary>",
  "insights": [
    {
      "pattern_type": "<lateral_movement|persistence_chain|data_exfil|credential_theft|ransomware_staging|recon_sweep|other>",
      "affected_agents": ["<hostname>", ...],
      "incident_ids": ["<id>", ...],
      "mitre_techniques": ["T1059.001", ...],
      "confidence": <0.0-1.0>,
      "narrative": "<paragraph explaining the pattern>",
      "recommended_actions": ["<action>", ...],
      "kill_chain_stage": "<stage or null>"
    }
  ]
}

Rules:
- Only report insights with confidence >= 0.3.
- If no meaningful patterns exist, return insights: [] with overall_threat_level "LOW".
- Do not fabricate incident IDs — only use IDs returned by tools.
- The final output MUST be valid JSON and nothing else.
"""


async def run_correlation_agent(
    tenant_id: str,
    db: AsyncSession,
    max_iterations: int = 20,
) -> CorrelationResult:
    """
    Run the Claude Opus 4.6 correlation agent for a tenant.

    Returns a CorrelationResult containing discovered attack patterns
    and recommended actions.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY not set — returning empty correlation result")
        return CorrelationResult(
            tenant_id=tenant_id,
            analyzed_at=datetime.now(tz=timezone.utc),
            incidents_analyzed=0,
            insights=[],
            overall_threat_level="LOW",
            summary="Correlation agent not configured (ANTHROPIC_API_KEY missing).",
        )

    client = anthropic.AsyncAnthropic(api_key=api_key)

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"Analyze security incidents for tenant '{tenant_id}'. "
                "Use the available tools to investigate patterns and then output "
                "your structured JSON report."
            ),
        }
    ]

    iteration = 0
    last_text = ""

    while iteration < max_iterations:
        iteration += 1
        logger.info(
            "Correlation agent iteration %d/%d for tenant %s",
            iteration,
            max_iterations,
            tenant_id,
        )

        async with client.messages.stream(
            model="claude-opus-4-6",
            max_tokens=8192,
            thinking={"type": "adaptive"},
            system=_SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,  # type: ignore[arg-type]
            messages=messages,  # type: ignore[arg-type]
        ) as stream:
            response = await stream.get_final_message()

        # Append assistant turn
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Extract the final text block
            for block in response.content:
                if hasattr(block, "type") and block.type == "text":
                    last_text = block.text
                    break
            break

        if response.stop_reason != "tool_use":
            logger.warning(
                "Unexpected stop_reason '%s' from correlation agent",
                response.stop_reason,
            )
            break

        # Execute all tool calls and collect results
        tool_results: list[dict[str, Any]] = []
        for block in response.content:
            if not (hasattr(block, "type") and block.type == "tool_use"):
                continue

            logger.debug("Correlation agent calling tool: %s", block.name)
            result = await execute_tool(
                tool_name=block.name,
                tool_input=block.input,
                db=db,
                tenant_id=tenant_id,
            )
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result),
                }
            )

        messages.append({"role": "user", "content": tool_results})

    else:
        logger.warning(
            "Correlation agent hit max_iterations=%d for tenant %s",
            max_iterations,
            tenant_id,
        )

    # Parse the JSON report from the final text block
    return _parse_result(last_text, tenant_id)


def _parse_result(text: str, tenant_id: str) -> CorrelationResult:
    """Parse the agent's JSON output into a CorrelationResult."""
    now = datetime.now(tz=timezone.utc)

    # Strip markdown fences if present
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.error(
            "Failed to parse correlation agent output: %s\n%s", exc, text[:500]
        )
        return CorrelationResult(
            tenant_id=tenant_id,
            analyzed_at=now,
            incidents_analyzed=0,
            insights=[],
            overall_threat_level="LOW",
            summary="Correlation analysis failed — agent output could not be parsed.",
        )

    insights = [
        CorrelationInsight(
            pattern_type=ins.get("pattern_type", "other"),
            affected_agents=ins.get("affected_agents", []),
            incident_ids=ins.get("incident_ids", []),
            mitre_techniques=ins.get("mitre_techniques", []),
            confidence=float(ins.get("confidence", 0.5)),
            narrative=ins.get("narrative", ""),
            recommended_actions=ins.get("recommended_actions", []),
            kill_chain_stage=ins.get("kill_chain_stage"),
        )
        for ins in data.get("insights", [])
        if float(ins.get("confidence", 0)) >= 0.3
    ]

    return CorrelationResult(
        tenant_id=tenant_id,
        analyzed_at=now,
        incidents_analyzed=int(data.get("incidents_analyzed", 0)),
        insights=insights,
        overall_threat_level=data.get("overall_threat_level", "LOW"),
        summary=data.get("summary", ""),
    )
