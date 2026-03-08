# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Kafka consumer for platform-side event processing.

Consumes from: openclaw.telemetry.{tenant_id}
Consumer group: openclaw-platform-api

Used for:
  - Real-time detection correlation across agents (future Phase 3)
  - Audit log fan-out (future)
"""

import asyncio
import json
import logging
import os
from typing import Callable, Optional

from aiokafka import AIOKafkaConsumer

logger = logging.getLogger(__name__)

KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "kafka:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "openclaw-platform-api")
TOPIC_PATTERN = os.environ.get("KAFKA_TOPIC_PATTERN", "^openclaw\\.telemetry\\..+")


class KafkaConsumerService:
    """Wraps AIOKafkaConsumer with a pluggable message handler."""

    def __init__(self) -> None:
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._task: Optional[asyncio.Task] = None
        self._handler: Optional[Callable] = None

    def set_handler(self, handler: Callable) -> None:
        """Register an async message handler: handler(tenant_id: str, payload: dict) -> None."""
        self._handler = handler

    async def start(self) -> None:
        """Start consuming — called from FastAPI lifespan."""
        try:
            self._consumer = AIOKafkaConsumer(
                bootstrap_servers=KAFKA_BROKERS,
                group_id=CONSUMER_GROUP,
                value_deserializer=lambda v: json.loads(v.decode("utf-8", errors="replace")),
                auto_offset_reset="latest",
            )
            # Subscribe to all tenant telemetry topics via regex
            self._consumer.subscribe(pattern=TOPIC_PATTERN)
            await self._consumer.start()
            self._task = asyncio.create_task(self._consume_loop(), name="kafka-consumer")
            logger.info("Kafka consumer started (group=%s)", CONSUMER_GROUP)
        except Exception as exc:
            logger.warning("Kafka consumer failed to start: %s", exc)

    async def stop(self) -> None:
        """Stop the consumer and cancel the background task."""
        if self._task:
            self._task.cancel()
        if self._consumer:
            await self._consumer.stop()

    async def _consume_loop(self) -> None:
        if self._consumer is None:
            return
        try:
            async for msg in self._consumer:
                if self._handler is None:
                    continue
                # Extract tenant_id from topic: openclaw.telemetry.{tenant_id}
                parts = msg.topic.split(".")
                tenant_id = parts[-1] if len(parts) >= 3 else "unknown"
                try:
                    await self._handler(tenant_id, msg.value)
                except Exception as exc:
                    logger.warning("Kafka message handler error: %s", exc)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Kafka consumer loop error: %s", exc)


kafka_consumer = KafkaConsumerService()
