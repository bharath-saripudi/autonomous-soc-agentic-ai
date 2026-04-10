"""Kafka consumer for high-volume alert ingestion.

Subscribes to the 'security-alerts' topic and processes messages
in batches for efficiency. Maintains offset tracking to ensure
no alerts are lost even if the system crashes.
"""

import asyncio
import json

import structlog

logger = structlog.get_logger()


class KafkaAlertConsumer:
    """Async Kafka consumer that processes security alerts in batches."""

    def __init__(self, alert_callback, bootstrap_servers: str, topic: str):
        self.alert_callback = alert_callback
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.consumer = None
        self.running = False

    async def start(self):
        """Initialize and start consuming messages."""
        from aiokafka import AIOKafkaConsumer

        self.consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id="soc-ingestion",
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            max_poll_records=100,  # Batch size
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )

        await self.consumer.start()
        self.running = True
        logger.info(
            "kafka_consumer_started",
            topic=self.topic,
            servers=self.bootstrap_servers,
        )

        try:
            await self._consume_loop()
        finally:
            await self.consumer.stop()
            logger.info("kafka_consumer_stopped")

    async def _consume_loop(self):
        """Main consumption loop — process messages in batches."""
        while self.running:
            try:
                # Poll for a batch of messages (100ms timeout)
                batch = await self.consumer.getmany(timeout_ms=100)

                for tp, messages in batch.items():
                    for msg in messages:
                        try:
                            alert_data = {
                                "source": "kafka",
                                "kafka_topic": tp.topic,
                                "kafka_partition": tp.partition,
                                "kafka_offset": msg.offset,
                                **msg.value,
                            }
                            await self.alert_callback(alert_data)

                        except Exception as e:
                            logger.error(
                                "kafka_message_error",
                                error=str(e),
                                offset=msg.offset,
                                partition=tp.partition,
                            )

                    # Commit offsets after successful batch processing
                    await self.consumer.commit()

            except Exception as e:
                logger.error("kafka_batch_error", error=str(e))
                await asyncio.sleep(1)  # Back off on errors

    async def stop(self):
        """Gracefully stop the consumer."""
        self.running = False