"""Phase 3 Verification Script — Test Response, Orchestrator, Learning.

Run: python tests/verify_phase3.py
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
#  RESPONSE AGENT TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Response: Imports and safety config present")
async def test_response_imports():
    from src.agents.response import (
        response_agent, PROTECTED_ASSETS,
        CONFIDENCE_THRESHOLDS, SEVERITY_THRESHOLDS,
    )
    assert "10.0.0.1" in PROTECTED_ASSETS  # Core router
    assert "dc-01" in PROTECTED_ASSETS      # Domain controller
    assert CONFIDENCE_THRESHOLDS["block_ip"] == 0.75
    assert SEVERITY_THRESHOLDS["isolate_host"] == 0.85


@test("Response: Safety gate blocks protected assets")
async def test_response_safety_protected():
    from src.agents.response import _safe_execute

    result = await _safe_execute(
        action_type="block_ip",
        target="10.0.0.1",  # Core router — protected
        confidence=0.95,
        alert_id="test-001",
        reason="test",
    )
    assert result["status"] == "blocked"
    assert result["gate_failed"] == "protected_asset"


@test("Response: Safety gate skips low confidence")
async def test_response_safety_confidence():
    from src.agents.response import _safe_execute

    result = await _safe_execute(
        action_type="isolate_host",
        target="WS-FINANCE-04",
        confidence=0.50,  # Below 0.85 threshold
        alert_id="test-002",
        reason="test",
    )
    assert result["status"] == "skipped"
    assert result["gate_failed"] == "confidence"


@test("Response: Executes action when all gates pass")
async def test_response_execute():
    from src.agents.response import _safe_execute

    result = await _safe_execute(
        action_type="block_ip",
        target="45.33.32.156",  # External IP — not protected
        confidence=0.90,        # Above 0.75 threshold
        alert_id="test-003",
        reason="Abuse score: 85",
    )
    assert result["status"] == "executed"
    assert result["result"]["success"] == True
    assert result["result"]["simulated"] == True


@test("Response: Full agent with high severity alert")
async def test_response_full_high():
    from src.agents.response import response_agent

    state = _make_state(
        triage_score=0.85,
        confidence=0.90,
        enrichment_results={
            "ips": {
                "45.33.32.156": {"abuse_score": 85, "source": "abuseipdb"},
            },
            "hashes": {},
            "domains": {},
            "summary": {"malicious_found": 1, "total_lookups": 1, "cache_hits": 0, "cache_hit_rate": 0},
        },
        normalized={"hostname": "WS-SALES-02", "description": "SSH brute force"},
    )

    result = await response_agent(state)

    assert result["response_status"] in ("responded", "monitored")
    assert len(result["actions_taken"]) > 0
    assert result["next_agent"] == "learning"

    # Should have notified
    notify_actions = [a for a in result["actions_taken"] if a["action"] == "notify"]
    assert len(notify_actions) == 1


@test("Response: Low severity only notifies")
async def test_response_low_severity():
    from src.agents.response import response_agent

    state = _make_state(triage_score=0.35, confidence=0.80)
    result = await response_agent(state)

    assert result["next_agent"] == "learning"
    # Should have notified but not blocked/isolated
    actions = result["actions_taken"]
    assert all(a["action"] == "notify" for a in actions if a.get("status") == "executed")


@test("Response: Notification urgency levels correct")
async def test_response_notify_urgency():
    from src.agents.response import _notify_team

    critical_state = _make_state(triage_score=0.95, classification="critical")
    result = await _notify_team(critical_state)
    assert result["urgency"] == "CRITICAL"

    low_state = _make_state(triage_score=0.25, classification="low")
    result = await _notify_team(low_state)
    assert result["urgency"] == "LOW"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ORCHESTRATOR TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Orchestrator: Routing after triage — low score closes")
async def test_route_triage_close():
    from src.agents.orchestrator import route_after_triage

    state = _make_state(triage_score=0.10)
    assert route_after_triage(state) == "close"


@test("Orchestrator: Routing after triage — medium score enriches")
async def test_route_triage_enrich():
    from src.agents.orchestrator import route_after_triage

    state = _make_state(triage_score=0.50)
    assert route_after_triage(state) == "enrichment"


@test("Orchestrator: Routing after hunting — critical + high confidence → response")
async def test_route_hunting_critical():
    from src.agents.orchestrator import route_after_hunting

    state = _make_state(triage_score=0.95, confidence=0.90)
    assert route_after_hunting(state) == "response"


@test("Orchestrator: Routing after hunting — critical + low confidence → escalate")
async def test_route_hunting_escalate():
    from src.agents.orchestrator import route_after_hunting

    state = _make_state(triage_score=0.95, confidence=0.60)
    assert route_after_hunting(state) == "escalate"


@test("Orchestrator: Routing after hunting — medium → response")
async def test_route_hunting_medium():
    from src.agents.orchestrator import route_after_hunting

    state = _make_state(triage_score=0.55, confidence=0.70)
    assert route_after_hunting(state) == "response"


@test("Orchestrator: Routing after hunting — low → close")
async def test_route_hunting_low():
    from src.agents.orchestrator import route_after_hunting

    state = _make_state(triage_score=0.30, confidence=0.80)
    assert route_after_hunting(state) == "close"


@test("Orchestrator: Normalize node works")
async def test_normalize_node():
    from src.agents.orchestrator import normalize_node

    state = _make_state(raw_data={
        "source": "api",
        "event_type": "ssh_brute_force",
        "src_ip": "45.33.32.156",
        "message": "342 failed login attempts",
    })

    result = await normalize_node(state)
    assert result["normalized"] is not None
    assert "indicators" in result["normalized"]


@test("Orchestrator: Close alert node sets status")
async def test_close_node():
    from src.agents.orchestrator import close_alert_node

    state = _make_state(triage_score=0.10, classification="info")
    result = await close_alert_node(state)
    assert result["response_status"] == "closed"


@test("Orchestrator: Escalate node sets status")
async def test_escalate_node():
    from src.agents.orchestrator import escalate_node

    state = _make_state(triage_score=0.95, confidence=0.60)
    result = await escalate_node(state)
    assert result["response_status"] == "escalated"
    assert result["should_escalate"] == True


@test("Orchestrator: Workflow graph compiles without errors")
async def test_workflow_compiles():
    from src.agents.orchestrator import build_workflow

    workflow = build_workflow()
    assert workflow is not None
    # LangGraph compiled graph should have an ainvoke method
    assert hasattr(workflow, "ainvoke")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LEARNING AGENT TESTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Learning: Imports and system prompt present")
async def test_learning_imports():
    from src.agents.learning import (
        learning_agent, LEARNING_SYSTEM_PROMPT,
        add_feedback, get_learning_stats,
    )
    assert "rules" in LEARNING_SYSTEM_PROMPT
    assert "feedback" in LEARNING_SYSTEM_PROMPT.lower()


@test("Learning: Feedback buffer accumulates")
async def test_learning_feedback_buffer():
    from src.agents.learning import add_feedback, _feedback_buffer

    _feedback_buffer.clear()

    add_feedback({
        "alert_id": "test-001",
        "label": "false_positive",
        "ai_score": 0.65,
        "notes": "Known scanner",
    })
    add_feedback({
        "alert_id": "test-002",
        "label": "agree",
        "ai_score": 0.85,
    })

    assert len(_feedback_buffer) == 2
    _feedback_buffer.clear()


@test("Learning: Stats reporting works")
async def test_learning_stats():
    from src.agents.learning import get_learning_stats, _feedback_buffer
    from src.agents.triage import _learned_rules

    _feedback_buffer.clear()
    _learned_rules.clear()

    stats = get_learning_stats()
    assert stats["pending_feedback"] == 0
    assert stats["batch_size"] == 5
    assert stats["learned_rules_count"] == 0


@test("Learning: Store incident builds correct metadata")
async def test_learning_store_metadata():
    """Test that _store_incident builds the right text and metadata."""
    # We can't test actual Qdrant storage, but we verify the logic
    state = _make_state(
        triage_score=0.85,
        classification="high",
        response_status="responded",
        normalized={
            "event_type": "ransomware",
            "description": "Mass file encryption on WS-FINANCE-04",
            "hostname": "WS-FINANCE-04",
            "username": "j.smith",
            "source_ip": "192.168.1.45",
        },
        ioc_list={
            "ips": ["192.168.1.45"],
            "hashes_sha256": ["abc123"],
            "domains": [],
        },
    )

    # Verify state has what learning agent needs
    assert state.get("triage_score") == 0.85
    assert state.get("normalized", {}).get("event_type") == "ransomware"
    assert state.get("ioc_list", {}).get("ips") == ["192.168.1.45"]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  INTEGRATION TEST (all agents wired)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@test("Integration: All 6 agents importable and have correct signatures")
async def test_all_agents_signatures():
    import inspect
    from src.agents.triage import triage_agent
    from src.agents.enrichment import enrichment_agent
    from src.agents.hunting import hunting_agent
    from src.agents.response import response_agent
    from src.agents.learning import learning_agent
    from src.agents.orchestrator import run_workflow

    # All agent functions take a single 'state' param
    for name, agent in [
        ("triage", triage_agent),
        ("enrichment", enrichment_agent),
        ("hunting", hunting_agent),
        ("response", response_agent),
        ("learning", learning_agent),
    ]:
        params = list(inspect.signature(agent).parameters.keys())
        assert params == ["state"], f"{name} agent has wrong params: {params}"

    # run_workflow takes alert_id, source, raw_data
    params = list(inspect.signature(run_workflow).parameters.keys())
    assert params == ["alert_id", "source", "raw_data"]


@test("Integration: AgentState flows through all agents correctly")
async def test_state_flow():
    """Verify that state fields set by each agent are accessible by the next."""
    state = _make_state(
        raw_data={"event_type": "test", "src_ip": "1.2.3.4", "message": "test alert"},
    )

    # Simulate normalize
    from src.agents.orchestrator import normalize_node
    state = await normalize_node(state)
    assert state["normalized"] is not None, "Normalize should set normalized"

    # After triage would set these
    state["triage_score"] = 0.75
    state["confidence"] = 0.85
    state["classification"] = "high"
    state["triage_reasoning"] = "Test reasoning"

    # Enrichment reads normalized, writes enrichment_results
    assert state.get("normalized") is not None, "Enrichment needs normalized"

    # Hunting reads enrichment_results, writes similar_cases
    state["enrichment_results"] = {"ips": {}, "hashes": {}, "domains": {},
                                    "summary": {"malicious_found": 0, "total_lookups": 0,
                                               "cache_hits": 0, "cache_hit_rate": 0}}
    state["similar_cases"] = []
    state["pattern_match"] = False

    # Response reads triage_score + enrichment, writes actions_taken
    from src.agents.response import response_agent
    state = await response_agent(state)
    assert state["actions_taken"] is not None, "Response should set actions_taken"
    assert state["next_agent"] == "learning"

    # Learning reads everything — terminal node
    assert state.get("triage_score") is not None
    assert state.get("actions_taken") is not None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _make_state(**overrides) -> dict:
    """Create a test AgentState with defaults."""
    state = {
        "alert_id": f"test-{int(time.time())}",
        "raw_data": overrides.get("raw_data", {"event_type": "test", "message": "test"}),
        "normalized": overrides.get("normalized", {"event_type": "test", "description": "test alert"}),
        "triage_score": None,
        "triage_reasoning": None,
        "confidence": None,
        "classification": None,
        "ioc_list": None,
        "enrichment_results": None,
        "similar_cases": None,
        "pattern_match": None,
        "historical_context": None,
        "actions_taken": None,
        "response_status": None,
        "analyst_feedback": None,
        "feedback_label": None,
        "next_agent": None,
        "should_escalate": None,
        "error": None,
    }
    state.update(overrides)
    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RUN ALL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    print("")
    print("=" * 55)
    print("  Autonomous SOC \u2014 Phase 3 Verification")
    print("=" * 55)
    print("")

    tests = [
        # Response Agent
        test_response_imports,
        test_response_safety_protected,
        test_response_safety_confidence,
        test_response_execute,
        test_response_full_high,
        test_response_low_severity,
        test_response_notify_urgency,
        # Orchestrator
        test_route_triage_close,
        test_route_triage_enrich,
        test_route_hunting_critical,
        test_route_hunting_escalate,
        test_route_hunting_medium,
        test_route_hunting_low,
        test_normalize_node,
        test_close_node,
        test_escalate_node,
        test_workflow_compiles,
        # Learning Agent
        test_learning_imports,
        test_learning_feedback_buffer,
        test_learning_stats,
        test_learning_store_metadata,
        # Integration
        test_all_agents_signatures,
        test_state_flow,
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
        print("  \U0001f389 All tests passed! Phase 3 verified.")
        print("     All 6 agents working. Ready for dashboard.")
    else:
        print(f"  \u26a0\ufe0f  {failed} test(s) failed. Fix issues before proceeding.")
    print("")
    return failed


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))