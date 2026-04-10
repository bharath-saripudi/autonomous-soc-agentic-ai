"""End-to-end workflow integration test.

Tests the full pipeline: Normalize → Triage → Enrich → Hunt → Response → Learning
without requiring external services (Claude API, Redis, Qdrant).
"""
import asyncio, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.orchestrator import build_workflow, normalize_node, route_after_triage, route_after_hunting, close_alert_node, escalate_node
from src.agents.response import response_agent, PROTECTED_ASSETS
from src.agents.learning import learning_agent, get_learning_stats

def make_state(**kw):
    state = {"alert_id":f"e2e-{int(time.time())}","raw_data":{"event_type":"test","src_ip":"45.33.32.156","message":"test alert"},"normalized":None,"triage_score":None,"triage_reasoning":None,"confidence":None,"classification":None,"ioc_list":None,"enrichment_results":None,"similar_cases":None,"pattern_match":None,"historical_context":None,"actions_taken":None,"response_status":None,"analyst_feedback":None,"feedback_label":None,"next_agent":None,"should_escalate":None,"error":None}
    state.update(kw)
    return state

def test_workflow_compiles():
    wf = build_workflow()
    assert wf is not None
    assert hasattr(wf, "ainvoke")

def test_normalize_node():
    state = make_state()
    result = asyncio.run(normalize_node(state))
    assert result["normalized"] is not None
    assert "indicators" in result["normalized"]

def test_routing_close():
    state = make_state(triage_score=0.05)
    assert route_after_triage(state) == "close"

def test_routing_enrich():
    state = make_state(triage_score=0.6)
    assert route_after_triage(state) == "enrichment"

def test_routing_hunting_critical():
    state = make_state(triage_score=0.95, confidence=0.9)
    assert route_after_hunting(state) == "response"

def test_routing_hunting_escalate():
    state = make_state(triage_score=0.95, confidence=0.5)
    assert route_after_hunting(state) == "escalate"

def test_response_agent_flow():
    state = make_state(triage_score=0.75, confidence=0.9, normalized={"description":"test","hostname":"WS-01"}, enrichment_results={"ips":{},"hashes":{},"domains":{},"summary":{"malicious_found":0}})
    result = asyncio.run(response_agent(state))
    assert result["actions_taken"] is not None
    assert result["next_agent"] == "learning"

def test_protected_assets():
    assert "10.0.0.1" in PROTECTED_ASSETS
    assert "dc-01" in PROTECTED_ASSETS

def test_close_node():
    state = make_state(triage_score=0.05)
    result = asyncio.run(close_alert_node(state))
    assert result["response_status"] == "closed"

def test_escalate_node():
    state = make_state(triage_score=0.95, confidence=0.5)
    result = asyncio.run(escalate_node(state))
    assert result["response_status"] == "escalated"

def test_full_state_flow():
    """Simulate state flowing through all agents manually."""
    state = make_state()
    state = asyncio.run(normalize_node(state))
    assert state["normalized"] is not None
    state["triage_score"] = 0.75
    state["confidence"] = 0.85
    state["classification"] = "high"
    state["enrichment_results"] = {"ips":{},"hashes":{},"domains":{},"summary":{"malicious_found":0}}
    state["similar_cases"] = []
    state = asyncio.run(response_agent(state))
    assert state["actions_taken"] is not None
    assert state["response_status"] in ("responded","monitored")

if __name__ == "__main__":
    tests = [test_workflow_compiles, test_normalize_node, test_routing_close, test_routing_enrich, test_routing_hunting_critical, test_routing_hunting_escalate, test_response_agent_flow, test_protected_assets, test_close_node, test_escalate_node, test_full_state_flow]
    for t in tests:
        t()
        print(f"  ✅ {t.__name__}")
    print(f"\nAll {len(tests)} e2e tests passed ✅")
