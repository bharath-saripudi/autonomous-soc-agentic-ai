"""Unit tests for the Triage Agent."""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from src.agents.triage import triage_agent, format_alert_for_llm, add_learned_rule, get_learned_rules, _learned_rules, TRIAGE_SYSTEM_PROMPT

def make_state(**kw):
    state = {"alert_id":"test-001","raw_data":{"event_type":"test","message":"test"},"normalized":{"event_type":"test","description":"test alert","indicators":{"ips":[],"hashes_sha256":[],"domains":[]}},"triage_score":None,"triage_reasoning":None,"confidence":None,"classification":None,"ioc_list":None,"enrichment_results":None,"similar_cases":None,"pattern_match":None,"historical_context":None,"actions_taken":None,"response_status":None,"analyst_feedback":None,"feedback_label":None,"next_agent":None,"should_escalate":None,"error":None}
    state.update(kw)
    return state

def test_system_prompt_has_severity_scale():
    assert "0.0" in TRIAGE_SYSTEM_PROMPT
    assert "1.0" in TRIAGE_SYSTEM_PROMPT
    assert "severity" in TRIAGE_SYSTEM_PROMPT.lower()

def test_format_alert():
    state = make_state(raw_data={"event_type":"ssh_brute_force","src_ip":"1.2.3.4","message":"500 failed logins"}, normalized={"event_type":"ssh_brute_force","description":"500 failed logins","indicators":{"ips":["1.2.3.4"],"hashes_sha256":[],"domains":[]}})
    text = format_alert_for_llm(state)
    assert "ssh_brute_force" in text
    assert "1.2.3.4" in text

def test_learned_rules():
    _learned_rules.clear()
    add_learned_rule("SSH from 10.50.0.0/16 is IT admin")
    rules = get_learned_rules()
    assert len(rules) == 1
    assert "IT admin" in rules[0]
    _learned_rules.clear()

def test_triage_agent_signature():
    import inspect
    sig = inspect.signature(triage_agent)
    assert list(sig.parameters.keys()) == ["state"]

def test_triage_sets_score_and_routes():
    """Triage should set a score and route to next agent."""
    state = make_state()
    result = asyncio.run(triage_agent(state))
    assert result["triage_score"] is not None
    assert result["next_agent"] in ("enrichment", "close")

if __name__ == "__main__":
    test_system_prompt_has_severity_scale()
    test_format_alert()
    test_learned_rules()
    test_triage_agent_signature()
    test_triage_sets_score_and_routes()
    print("All triage tests passed ✅")