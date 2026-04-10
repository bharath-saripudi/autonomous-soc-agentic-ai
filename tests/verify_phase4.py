"""Phase 4 Verification — API Integration, Metrics, Monitoring.

Run: python tests/verify_phase4.py
"""

import asyncio
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

passed = 0
failed = 0
errors = []


def test(name):
    def decorator(func):
        async def wrapper():
            global passed, failed
            try:
                await func()
                print(f"  \u2705 {name}")
                passed += 1
            except Exception as e:
                print(f"  \u274c {name}")
                print(f"     Error: {e}")
                errors.append(f"{name}: {e}")
                failed += 1
        return wrapper
    return decorator


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  API ROUTES TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("API: All routes registered")
async def test_api_routes():
    from src.api.main import app
    routes = [r.path for r in app.routes]
    expected = [
        "/alerts", "/alerts/{alert_id}", "/feedback",
        "/stats/overview", "/stats/pipeline", "/stats/learning",
        "/metrics", "/health", "/ws/alerts",
    ]
    for route in expected:
        assert route in routes, f"Missing route: {route}"


@test("API: Version is 1.0.0")
async def test_api_version():
    from src.api.main import app
    assert app.version == "1.0.0"


@test("API: CORS middleware enabled")
async def test_cors():
    from src.api.main import app
    middleware_classes = [type(m).__name__ for m in app.user_middleware]
    # CORSMiddleware is wrapped, check it exists in the app
    assert any("CORS" in str(m) for m in app.user_middleware), "CORS middleware not found"


@test("API: POST /alerts accepts BackgroundTasks")
async def test_alert_endpoint_signature():
    import inspect
    from src.api.main import ingest_alert
    sig = inspect.signature(ingest_alert)
    params = list(sig.parameters.keys())
    assert "alert_input" in params
    assert "background_tasks" in params


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PIPELINE METRICS TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Metrics: PipelineMetrics tracks ingestion")
async def test_metrics_ingestion():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()
    m.record_ingestion()
    m.record_ingestion()
    assert m.alerts_ingested == 2


@test("Metrics: PipelineMetrics tracks completion with severity")
async def test_metrics_completion():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()

    # Critical alert
    m.record_completion({"triage_score": 0.95, "response_status": "responded",
                         "actions_taken": [{"action": "block_ip", "status": "executed"}]}, 2.5)
    assert m.severity_counts["critical"] == 1
    assert m.action_counts["block_ip"] == 1
    assert m.alerts_processed == 1

    # Low alert auto-closed
    m.record_completion({"triage_score": 0.10, "response_status": "closed",
                         "actions_taken": []}, 0.5)
    assert m.severity_counts["info"] == 1
    assert m.auto_closed == 1
    assert m.false_positives == 1

    # Escalated alert
    m.record_completion({"triage_score": 0.92, "response_status": "escalated",
                         "actions_taken": [{"action": "notify", "status": "executed"}]}, 1.5)
    assert m.escalated == 1
    assert m.action_counts["notify"] == 1


@test("Metrics: Average processing time calculation")
async def test_metrics_avg_time():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()
    m.record_completion({"triage_score": 0.5, "actions_taken": []}, 2.0)
    m.record_completion({"triage_score": 0.5, "actions_taken": []}, 4.0)
    assert m.avg_processing_time == 3.0


@test("Metrics: to_dict returns all fields")
async def test_metrics_dict():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()
    m.record_ingestion()
    m.record_completion({"triage_score": 0.75, "response_status": "responded",
                         "actions_taken": []}, 1.0)

    d = m.to_dict()
    assert "alerts_ingested" in d
    assert "alerts_processed" in d
    assert "severity_counts" in d
    assert "action_counts" in d
    assert "auto_closed" in d
    assert "escalated" in d
    assert "false_positives" in d
    assert "avg_processing_time_sec" in d


@test("Metrics: Prometheus export format")
async def test_metrics_prometheus():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()
    m.record_ingestion()
    m.record_completion({"triage_score": 0.95, "response_status": "responded",
                         "actions_taken": [{"action": "block_ip", "status": "executed"}]}, 2.0)

    prom = m.to_prometheus()
    assert "soc_alerts_ingested_total 1" in prom
    assert "soc_alerts_processed_total 1" in prom
    assert 'soc_alerts_by_severity{level="critical"} 1' in prom
    assert 'soc_actions_executed_total{action="block_ip"} 1' in prom
    assert "# TYPE soc_alerts_ingested_total counter" in prom
    assert "# HELP" in prom


@test("Metrics: Failure tracking")
async def test_metrics_failure():
    from src.api.main import PipelineMetrics
    m = PipelineMetrics()
    m.record_failure()
    m.record_failure()
    assert m.alerts_failed == 2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BACKGROUND PIPELINE TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Background: process_alert_background is async callable")
async def test_background_callable():
    from src.api.main import process_alert_background
    import inspect
    assert inspect.iscoroutinefunction(process_alert_background)


@test("Background: WebSocket manager broadcasts correctly")
async def test_ws_broadcast():
    from src.api.main import ConnectionManager
    mgr = ConnectionManager()
    # No connections — should not error
    await mgr.broadcast({"event": "test"})
    assert len(mgr.active) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ORCHESTRATOR INTEGRATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Integration: Orchestrator run_workflow importable from API")
async def test_orchestrator_import():
    from src.agents.orchestrator import run_workflow
    import inspect
    assert inspect.iscoroutinefunction(run_workflow)
    params = list(inspect.signature(run_workflow).parameters.keys())
    assert params == ["alert_id", "source", "raw_data"]


@test("Integration: Learning stats accessible from API")
async def test_learning_stats_api():
    from src.agents.learning import get_learning_stats
    stats = get_learning_stats()
    assert "pending_feedback" in stats
    assert "learned_rules_count" in stats
    assert "batch_size" in stats


@test("Integration: Feedback flows to learning buffer")
async def test_feedback_to_learning():
    from src.agents.learning import add_feedback, _feedback_buffer
    _feedback_buffer.clear()

    add_feedback({
        "alert_id": "test-001",
        "label": "false_positive",
        "ai_score": 0.65,
        "notes": "Known scanner IP",
    })

    assert len(_feedback_buffer) == 1
    assert _feedback_buffer[0]["label"] == "false_positive"
    _feedback_buffer.clear()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HEALTH CHECK LOGIC
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Health: LLM client stats accessible")
async def test_health_llm():
    from src.services.llm_client import get_llm
    llm = get_llm()
    stats = llm.stats
    assert "model" in stats
    assert stats["model"] == "claude-sonnet-4-20250514"


@test("Health: Cache module accessible")
async def test_health_cache():
    from src.services.cache import get_cache
    cache = get_cache()
    stats = cache.stats
    assert "hits" in stats
    assert "misses" in stats


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FULL PIPELINE SIMULATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("E2E Simulation: Metrics update correctly after mock pipeline run")
async def test_e2e_metrics_simulation():
    """Simulate what happens when alerts flow through the system."""
    from src.api.main import PipelineMetrics

    m = PipelineMetrics()

    # Simulate 5 alerts with different outcomes
    alerts = [
        {"triage_score": 0.95, "response_status": "responded",
         "actions_taken": [{"action": "block_ip", "status": "executed"},
                          {"action": "isolate_host", "status": "executed"},
                          {"action": "notify", "status": "executed"}]},
        {"triage_score": 0.08, "response_status": "closed", "actions_taken": []},
        {"triage_score": 0.55, "response_status": "responded",
         "actions_taken": [{"action": "notify", "status": "executed"}]},
        {"triage_score": 0.92, "response_status": "escalated",
         "actions_taken": [{"action": "notify", "status": "executed"}]},
        {"triage_score": 0.12, "response_status": "closed", "actions_taken": []},
    ]

    for i, alert in enumerate(alerts):
        m.record_ingestion()
        m.record_completion(alert, 1.0 + i * 0.5)

    assert m.alerts_ingested == 5
    assert m.alerts_processed == 5
    assert m.severity_counts["critical"] == 2  # 0.95 and 0.92
    assert m.severity_counts["medium"] == 1    # 0.55
    assert m.severity_counts["info"] == 2      # 0.08 and 0.12
    assert m.auto_closed == 2
    assert m.escalated == 1
    assert m.false_positives == 2
    assert m.action_counts["block_ip"] == 1
    assert m.action_counts["isolate_host"] == 1
    assert m.action_counts["notify"] == 3

    # Average time: (1.0 + 1.5 + 2.0 + 2.5 + 3.0) / 5 = 2.0
    assert m.avg_processing_time == 2.0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RUN ALL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    print("")
    print("=" * 55)
    print("  Autonomous SOC \u2014 Phase 4 Verification")
    print("=" * 55)
    print("")

    tests = [
        test_api_routes,
        test_api_version,
        test_cors,
        test_alert_endpoint_signature,
        test_metrics_ingestion,
        test_metrics_completion,
        test_metrics_avg_time,
        test_metrics_dict,
        test_metrics_prometheus,
        test_metrics_failure,
        test_background_callable,
        test_ws_broadcast,
        test_orchestrator_import,
        test_learning_stats_api,
        test_feedback_to_learning,
        test_health_llm,
        test_health_cache,
        test_e2e_metrics_simulation,
    ]

    for t in tests:
        await t()

    print("")
    print("-" * 55)
    print(f"  Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("-" * 55)

    if errors:
        print("\n  Failures:")
        for err in errors:
            print(f"    \u274c {err}")

    print("")
    if failed == 0:
        print("  \U0001f389 All tests passed! Phase 4 verified.")
        print("")
        print("  Full project status:")
        print("    Phase 1 \u2705 Infrastructure + Ingestion")
        print("    Phase 2 \u2705 Triage + Enrichment + Hunting")
        print("    Phase 3 \u2705 Response + Orchestrator + Learning")
        print("    Phase 4 \u2705 API Integration + Metrics + Monitoring")
        print("")
        print("  To start the server:")
        print("    uvicorn src.api.main:app --reload --port 8000")
        print("")
        print("  To test live:")
        print('    curl -X POST http://localhost:8000/alerts -H "Content-Type: application/json" -d "{\\"source\\": \\"api\\", \\"data\\": {\\"event_type\\": \\"ssh_brute_force\\", \\"src_ip\\": \\"45.33.32.156\\", \\"message\\": \\"342 failed SSH logins\\"}}"')
    else:
        print(f"  \u26a0\ufe0f  {failed} test(s) failed.")
    print("")
    return failed


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))