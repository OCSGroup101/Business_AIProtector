# Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
"""
Kafka producer for platform-side event streaming.

Produces telemetry events to topic: openclaw.telemetry.{tenant_id}

Used by:
  - routes/telemetry.py: forward received events to Kafka after persisting
  - intel: forward IOC updates to subscribed agents (future)
"""

import logging
import os
from typing import Optional

from aiokafka import AIOKafkaProducer

logger = logging.getLogger(__name__)

KAFKA_BROKERS = os.environ.get("KAFKA_BROKERS", "kafka:9092")
TOPIC_PREFIX = os.environ.get("KAFKA_TOPIC_PREFIX", "openclaw.telemetry")


class KafkaProducerService:
    """Wraps AIOKafkaProducer with connect/disconnect lifecycle."""

    def __init__(self) -> None:
        self._producer: Optional[AIOKafkaProducer] = None

    async def start(self) -> None:
        """Start the Kafka producer — called from FastAPI lifespan."""
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BROKERS,
                value_serializer=lambda v: v if isinstance(v, bytes) else v.encode(),
                compression_type="lz4",
                acks="all",
            )
            await self._producer.start()
            logger.info("Kafka producer started (brokers=%s)", KAFKA_BROKERS)
        except Exception as exc:
            logger.warning(
                "Kafka producer failed to start: %s — events will not stream", exc
            )
            self._producer = None

    async def stop(self) -> None:
        """Stop the Kafka producer — called from FastAPI lifespan shutdown."""
        if self._producer:
            await self._producer.stop()
            self._producer = None

    async def produce(self, tenant_id: str, payload: bytes) -> None:
        """
        Produce a message to openclaw.telemetry.{tenant_id}.
        Non-blocking; failures are logged but not propagated.
        """
        if self._producer is None:
            return
        topic = f"{TOPIC_PREFIX}.{tenant_id}"
        try:
            await self._producer.send(topic, payload)
        except Exception as exc:
            logger.warning("Kafka produce to %s failed: %s", topic, exc)


# Module-level singleton
kafka_producer = KafkaProducerService()
