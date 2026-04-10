"""Seed Qdrant with historical incidents for similarity search.

Usage:
    1. Start Qdrant: docker compose up -d qdrant
    2. Run: python scripts/seed_qdrant.py

Loads sample alerts into the vector database so the Hunting Agent
can find similar past incidents when processing new alerts.
"""
import asyncio, json, sys, os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.services.vector_store import store_incident_embedding, generate_embedding, get_qdrant
from src.ingestion.normalizer import AlertNormalizer

FIXTURES = Path(__file__).parent.parent / "tests" / "fixtures" / "sample_alerts.json"
normalizer = AlertNormalizer()


async def seed_qdrant():
    print("=" * 55)
    print("  Seed Qdrant — Historical Incident Vectors")
    print("=" * 55)

    client = get_qdrant()
    if client is None:
        print("\n  ❌ Qdrant not available!")
        print("     Start it: docker compose up -d qdrant")
        print("     Then retry: python scripts/seed_qdrant.py")
        return

    with open(FIXTURES) as f:
        alerts = json.load(f)

    print(f"\n  📂 Loading {len(alerts)} incidents into Qdrant...\n")
    success = 0

    for i, alert in enumerate(alerts):
        name = alert["name"]
        source = alert["source"]
        data = alert["data"]
        normalized = normalizer.normalize(source, data)

        text_parts = []
        for field in ["event_type", "description", "hostname", "username", "source_ip", "dest_ip"]:
            val = normalized.get(field) or data.get(field)
            if val:
                text_parts.append(f"{field}: {val}")
        text = "\n".join(text_parts) if text_parts else str(data)[:500]

        metadata = {
            "event_type": normalized.get("event_type", data.get("event_type", "unknown")),
            "source": source,
            "name": name,
            "severity": 0.5,  # Default; will be updated by triage
            "outcome": "historical",
        }

        alert_id = f"seed-{i:03d}"
        ok = await store_incident_embedding(alert_id, text, metadata)
        status = "✅" if ok else "❌"
        print(f"  [{i+1:02d}] {status} {name}")
        if ok:
            success += 1

    print(f"\n  Done: {success}/{len(alerts)} incidents stored in Qdrant")
    print("  The Hunting Agent will now find similar past incidents.\n")


if __name__ == "__main__":
    asyncio.run(seed_qdrant())
