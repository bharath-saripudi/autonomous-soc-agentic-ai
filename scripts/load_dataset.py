"""Load & Process Dataset — Run all 22 sample alerts through the AI pipeline.

Usage:
    1. Start the server:  uvicorn src.api.main:app --port 8000
    2. In another terminal: python scripts/load_dataset.py

This sends each alert to the API, which triggers the full pipeline:
  Normalize → Triage (Claude) → Enrich → Hunt → Respond → Learn

Watch the server logs to see Claude analyzing each alert in real-time.
"""

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

API_BASE = "http://localhost:8000"
FIXTURES_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "sample_alerts.json"


async def load_dataset():
    print("")
    print("=" * 60)
    print("  Autonomous SOC — Dataset Loader")
    print("  Sending 22 alerts through the full AI pipeline")
    print("=" * 60)
    print("")

    # Check server is running
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{API_BASE}/health")
            if resp.status_code == 200:
                health = resp.json()
                print(f"  ✅ Server is running (status: {health.get('status')})")
            else:
                print(f"  ❌ Server returned {resp.status_code}")
                return
        except httpx.ConnectError:
            print("  ❌ Server not running!")
            print("     Start it first: uvicorn src.api.main:app --port 8000")
            return

    # Load alerts
    with open(FIXTURES_PATH) as f:
        alerts = json.load(f)

    print(f"  📂 Loaded {len(alerts)} sample alerts")
    print(f"  🤖 Each alert will be triaged by Claude AI")
    print("")
    print("-" * 60)

    results = []
    start_time = time.time()

    async with httpx.AsyncClient(timeout=60) as client:
        for i, alert in enumerate(alerts):
            name = alert["name"]
            source = alert["source"]
            data = alert["data"]

            print(f"\n  [{i+1:02d}/{len(alerts)}] {name}")
            print(f"       Source: {source}")

            try:
                resp = await client.post(
                    f"{API_BASE}/alerts",
                    json={"source": source, "data": data},
                )

                if resp.status_code == 202:
                    result = resp.json()
                    alert_id = result["alert_id"]
                    print(f"       Alert ID: {alert_id[:12]}...")
                    print(f"       Status: ✅ Accepted — pipeline running")
                    results.append({"name": name, "alert_id": alert_id, "status": "accepted"})
                else:
                    print(f"       Status: ❌ HTTP {resp.status_code}")
                    results.append({"name": name, "status": "failed", "error": resp.text})

            except Exception as e:
                print(f"       Status: ❌ Error: {e}")
                results.append({"name": name, "status": "error", "error": str(e)})

            # Small delay between alerts to avoid overwhelming Claude API
            if i < len(alerts) - 1:
                await asyncio.sleep(1)

    elapsed = round(time.time() - start_time, 1)
    accepted = sum(1 for r in results if r["status"] == "accepted")
    failed = len(results) - accepted

    print("")
    print("=" * 60)
    print(f"  Dataset Loading Complete!")
    print(f"  ✅ Accepted: {accepted}")
    if failed > 0:
        print(f"  ❌ Failed: {failed}")
    print(f"  ⏱  Total time: {elapsed}s")
    print("")
    print("  The AI pipeline is processing alerts in the background.")
    print("  Watch the server logs to see Claude analyzing each one.")
    print("")
    print("  Check results:")
    print(f"    Invoke-RestMethod -Uri {API_BASE}/alerts")
    print(f"    Invoke-RestMethod -Uri {API_BASE}/stats/pipeline")
    print(f"    Invoke-RestMethod -Uri {API_BASE}/stats/overview")
    print("")
    print("  Open dashboard:")
    print("    dashboard/index.html (open in browser)")
    print("=" * 60)
    print("")


if __name__ == "__main__":
    asyncio.run(load_dataset())
