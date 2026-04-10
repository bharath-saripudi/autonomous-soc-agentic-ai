"""Unit tests for the Enrichment Agent."""
import asyncio, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.enrichment import enrichment_agent, _merge_explicit_iocs
from src.services.threat_intel import _is_private_ip, _is_benign_domain, _empty_ip_result

def make_state(**kw):
    state = {"alert_id":"test-001","raw_data":{"event_type":"test","src_ip":"45.33.32.156"},"normalized":{"event_type":"test","description":"test","indicators":{"ips":["45.33.32.156"],"hashes_sha256":[],"domains":[]}},"triage_score":0.5,"triage_reasoning":None,"confidence":0.5,"classification":"medium","ioc_list":None,"enrichment_results":None,"similar_cases":None,"pattern_match":None,"historical_context":None,"actions_taken":None,"response_status":None,"analyst_feedback":None,"feedback_label":None,"next_agent":None,"should_escalate":None,"error":None}
    state.update(kw)
    return state

def test_private_ip_detection():
    assert _is_private_ip("10.0.0.1") == True
    assert _is_private_ip("192.168.1.1") == True
    assert _is_private_ip("45.33.32.156") == False

def test_benign_domain():
    assert _is_benign_domain("google.com") == True
    assert _is_benign_domain("evil-malware.xyz") == False

def test_empty_ip_result():
    r = _empty_ip_result("1.2.3.4", "abuseipdb", "no_api_key")
    assert r["ip"] == "1.2.3.4"
    assert r["source"] == "abuseipdb"

def test_merge_explicit_iocs():
    indicators = {"ips": [], "hashes_sha256": [], "hashes_md5": [], "hashes_sha1": [], "domains": []}
    normalized = {"src_ip":"1.2.3.4","dest_ip":"5.6.7.8","sha256":"abc123","domain":"evil.com","indicators":{"ips":[],"hashes_sha256":[],"domains":[]}}
    raw = {"src_ip":"1.2.3.4"}
    result = _merge_explicit_iocs(indicators, normalized, raw)
    assert "1.2.3.4" in result.get("ips",[])

def test_enrichment_agent_signature():
    import inspect
    sig = inspect.signature(enrichment_agent)
    assert list(sig.parameters.keys()) == ["state"]

def test_enrichment_sets_next_agent():
    state = make_state()
    result = asyncio.run(enrichment_agent(state))
    assert result["next_agent"] == "hunting"
    assert result["enrichment_results"] is not None

if __name__ == "__main__":
    test_private_ip_detection()
    test_benign_domain()
    test_empty_ip_result()
    test_merge_explicit_iocs()
    test_enrichment_agent_signature()
    test_enrichment_sets_next_agent()
    print("All enrichment tests passed ✅")