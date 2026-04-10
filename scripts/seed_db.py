"""Seed PostgreSQL with sample alerts from fixtures.

Usage:
    python -m scripts.seed_db
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from src.database import get_db, init_db
from src.ingestion.normalizer import AlertNormalizer
from src.models import Alert, AlertStatus


FIXTURES_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "sample_alerts.json"
normalizer = AlertNormalizer()


async def seed():
    """Load sample alerts into the database."""
    print("🔧 Initializing database tables...")
    await init_db()

    print(f"📂 Loading fixtures from {FIXTURES_PATH}")
    with open(FIXTURES_PATH) as f:
        samples = json.load(f)

    print(f"📥 Seeding {len(samples)} sample alerts...")
    async with get_db() as db:
        for i, sample in enumerate(samples):
            alert_id = str(uuid.uuid4())
            source = sample["source"]
            raw_data = sample["data"]
            normalized = normalizer.normalize(source, raw_data)

            alert = Alert(
                id=alert_id,
                source=source,
                raw_data=raw_data,
                normalized=normalized,
                status=AlertStatus.NEW,
                created_at=datetime.utcnow(),
            )
            db.add(alert)
            print(f"  [{i+1:02d}] {sample['name']} → {alert_id[:8]}...")

    print(f"\n✅ Successfully seeded {len(samples)} alerts!")
    print("   View them at: http://localhost:8000/alerts")


if __name__ == "__main__":
    asyncio.run(seed())