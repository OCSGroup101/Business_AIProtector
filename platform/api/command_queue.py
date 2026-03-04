# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Agent command queue — backed by Redis lists.

Key pattern:  agent:cmd:{agent_id}   (LPUSH to add, RPOP on heartbeat)
Each entry is a JSON-serialised command dict:
  {"type": "isolate"}
  {"type": "lift_isolation"}
  {"type": "update_agent",       "version": "...", "manifest_url": "..."}
  {"type": "pull_intel_bundle",  "bundle_id": "..."}

Commands are consumed exactly once by the next heartbeat from that agent.
The queue has no persistence guarantee (Redis default) — suitable for
best-effort delivery of operational commands.
"""

import json
import logging
import os

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_CMD_QUEUE_PREFIX = "agent:cmd:"
_QUEUE_MAX_LEN = 20   # cap per-agent queue to avoid runaway growth


def _key(agent_id: str) -> str:
    return f"{_CMD_QUEUE_PREFIX}{agent_id}"


async def _get_redis() -> aioredis.Redis:
    return await aioredis.from_url(_REDIS_URL, decode_responses=True)


async def push_command(agent_id: str, command: dict) -> None:
    """Enqueue a command for delivery on the agent's next heartbeat."""
    r = await _get_redis()
    try:
        payload = json.dumps(command)
        pipe = r.pipeline()
        pipe.lpush(_key(agent_id), payload)
        pipe.ltrim(_key(agent_id), 0, _QUEUE_MAX_LEN - 1)
        await pipe.execute()
        logger.info("Command queued for agent %s: %s", agent_id, command.get("type"))
    finally:
        await r.aclose()


async def pop_commands(agent_id: str, max_commands: int = 5) -> list[dict]:
    """
    Drain up to `max_commands` pending commands for an agent.
    Called from the heartbeat endpoint; returns commands to include in the response.
    """
    r = await _get_redis()
    try:
        commands: list[dict] = []
        for _ in range(max_commands):
            raw = await r.rpop(_key(agent_id))
            if raw is None:
                break
            try:
                commands.append(json.loads(raw))
            except json.JSONDecodeError:
                logger.warning("Malformed command in queue for agent %s — discarding", agent_id)
        return commands
    except Exception as exc:
        # Redis failure must not break the heartbeat
        logger.error("Redis command pop failed for agent %s: %s", agent_id, exc)
        return []
    finally:
        await r.aclose()
