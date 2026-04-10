"""Phase 2 Verification Script — Test all components.

Run: python tests/verify_phase2.py
"""

import asyncio
import json
import sys
import os

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


# ━━━ TEST 1: Config ━━━
@test("Config loads settings from env")
async def test_config():
    from src.config import get_settings
    s = get_settings()
    assert s.db_name == "soc_db"
    assert s.qdrant_port == 6333

# ━━━ TEST 2: Models ━━━
@test("Models: Alert, Case, AuditLog, FeedbackQueue defined")
async def test_models():
    from src.models import Alert, Case, AuditLog, FeedbackQueue, AlertStatus
    assert AlertStatus.NEW.value == "new"
    assert Alert.__tablename__ == "alerts"
    assert FeedbackQueue.__tablename__ == "feedback_queue"

@test("Models: Pydantic schemas validate correctly")
async def test_schemas():
    from src.models import AlertInput, FeedbackInput
    alert = AlertInput(source="test", data={"event_type": "ssh_brute_force"})
    assert alert.source == "test"
    fb = FeedbackInput(alert_id="abc-123", label="false_positive", notes="Known scanner")
    assert fb.label == "false_positive"
    try:
        FeedbackInput(alert_id="abc", label="invalid_label")
        assert False, "Should have raised"
    except Exception:
        pass

# ━━━ TEST 3: AgentState ━━━
@test("AgentState TypedDict has all required fields")
async def test_state():
    from src.state import AgentState
    state: AgentState = {
        "alert_id": "test-001", "raw_data": {"event_type": "test"},
        "normalized": None, "triage_score": None, "triage_reasoning": None,
        "confidence": None, "classification": None, "ioc_list": None,
        "enrichment_results": None, "similar_cases": None, "pattern_match": None,
        "historical_context": None, "actions_taken": None, "response_status": None,
        "analyst_feedback": None, "feedback_label": None, "next_agent": None,
        "should_escalate": None, "error": None,
    }
    assert state["alert_id"] == "test-001"

# ━━━ TEST 4: Normalizer ━━━
@test("Normalizer: JSON alert parsing")
async def test_normalizer_json():
    from src.ingestion.normalizer import AlertNormalizer
    n = AlertNormalizer()
    result = n.normalize("api", {
        "event_type": "ssh_brute_force", "src_ip": "45.33.32.156",
        "dst_ip": "10.0.1.20", "dst_port": 22, "message": "342 failed SSH login attempts",
    })
    assert result["event_type"] == "ssh_brute_force"
    assert result["source_ip"] == "45.33.32.156"
    assert "45.33.32.156" in result["indicators"]["ips"]

@test("Normalizer: CEF format parsing")
async def test_normalizer_cef():
    from src.ingestion.normalizer import AlertNormalizer
    n = AlertNormalizer()
    result = n.normalize("syslog", {
        "message": "CEF:0|PaloAlto|Firewall|10.0|threat|Malware Blocked|9|src=1.2.3.4 dst=10.0.0.5 dpt=443"
    })
    assert result["event_type"] == "Malware Blocked"
    assert result["source_ip"] == "1.2.3.4"

@test("Normalizer: Syslog RFC 5424 parsing")
async def test_normalizer_syslog():
    from src.ingestion.normalizer import AlertNormalizer
    n = AlertNormalizer()
    result = n.normalize("syslog", {
        "message": "<131>1 2025-01-15T14:30:00Z IDS-01 snort 1234 - - ET MALWARE detected src=10.0.1.50 dst=198.51.100.100",
        "hostname": "IDS-01",
    })
    assert result["hostname"] == "IDS-01"
    assert "10.0.1.50" in result["indicators"]["ips"]

@test("Normalizer: IOC extraction - IPs, hashes, domains")
async def test_normalizer_iocs():
    from src.ingestion.normalizer import AlertNormalizer
    iocs = AlertNormalizer._extract_iocs(
        "Connection from 45.33.32.156 to evil-c2.xyz "
        "hash: a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890 "
        "md5: aabbccdd11223344aabbccdd11223344 "
        "url: https://malware.evil.com/payload"
    )
    assert "45.33.32.156" in iocs["ips"]
    assert len(iocs["hashes_sha256"]) == 1
    assert len(iocs["hashes_md5"]) == 1

# ━━━ TEST 5: LLM Client ━━━
@test("LLM Client: Imports and initializes (Anthropic only)")
async def test_llm_client():
    from src.services.llm_client import LLMClient
    client = LLMClient()
    assert client.model == "claude-sonnet-4-20250514"
    assert client._total_calls == 0

# ━━━ TEST 6: Triage Agent ━━━
@test("Triage Agent: Imports, prompt, and helper functions")
async def test_triage_imports():
    from src.agents.triage import TRIAGE_SYSTEM_PROMPT, format_alert_for_llm
    assert "STEP 1" in TRIAGE_SYSTEM_PROMPT
    assert "severity_score" in TRIAGE_SYSTEM_PROMPT

@test("Triage Agent: format_alert_for_llm handles nested data")
async def test_triage_formatter():
    from src.agents.triage import format_alert_for_llm
    result = format_alert_for_llm({
        "event_type": "ransomware", "hostname": "WS-01", "empty_field": None,
        "indicators": {"ips": ["1.2.3.4"]}, "raw_reference": {"skip": "me"},
    })
    assert "ransomware" in result
    assert "raw_reference" not in result

@test("Triage Agent: Learned rules append to system prompt")
async def test_triage_learned_rules():
    from src.agents.triage import add_learned_rule, get_full_system_prompt, _learned_rules
    _learned_rules.clear()
    base = get_full_system_prompt()
    assert "LEARNED RULES" not in base
    add_learned_rule("SSH from 10.50.0.0/16 is IT admin")
    updated = get_full_system_prompt()
    assert "LEARNED RULES" in updated
    assert "10.50.0.0/16" in updated
    _learned_rules.clear()

# ━━━ TEST 7: Threat Intel ━━━
@test("Threat Intel: Private IP detection")
async def test_private_ip():
    from src.services.threat_intel import _is_private_ip
    assert _is_private_ip("10.0.1.5") == True
    assert _is_private_ip("192.168.1.1") == True
    assert _is_private_ip("127.0.0.1") == True
    assert _is_private_ip("45.33.32.156") == False
    assert _is_private_ip("8.8.8.8") == False

@test("Threat Intel: Benign domain detection")
async def test_benign_domains():
    from src.services.threat_intel import _is_benign_domain
    assert _is_benign_domain("login.microsoft.com") == True
    assert _is_benign_domain("evil-c2.xyz") == False

@test("Threat Intel: Empty result helpers")
async def test_empty_results():
    from src.services.threat_intel import _empty_ip_result, _empty_hash_result
    ip_r = _empty_ip_result("1.2.3.4", "abuseipdb", "no_api_key")
    assert ip_r["ip"] == "1.2.3.4"
    assert ip_r["abuse_score"] is None
    hash_r = _empty_hash_result("abc123", "rate_limited")
    assert hash_r["hash"] == "abc123"

# ━━━ TEST 8: Enrichment Agent ━━━
@test("Enrichment Agent: IOC merge from explicit fields")
async def test_enrichment_merge():
    from src.agents.enrichment import _merge_explicit_iocs
    indicators = {"ips": ["1.1.1.1"], "hashes_sha256": [], "domains": []}
    normalized = {"source_ip": "2.2.2.2", "dest_ip": "3.3.3.3"}
    raw_data = {"hash_sha256": "a" * 64, "domain": "evil.com", "src_ips": ["4.4.4.4"]}
    result = _merge_explicit_iocs(indicators, normalized, raw_data)
    assert "2.2.2.2" in result["ips"]
    assert ("a" * 64) in result["hashes_sha256"]
    assert "evil.com" in result["domains"]

@test("Enrichment Agent: Function signature correct")
async def test_enrichment_signature():
    from src.agents.enrichment import enrichment_agent
    import inspect
    assert list(inspect.signature(enrichment_agent).parameters.keys()) == ["state"]

# ━━━ TEST 9: Vector Store — embedding + point ID (lazy import, no grpc) ━━━
@test("Vector Store: Embedding generation works")
async def test_embedding():
    from src.services.vector_store import generate_embedding
    embedding = generate_embedding("SSH brute force attack from 45.33.32.156")
    assert isinstance(embedding, list)
    assert len(embedding) == 384
    assert all(isinstance(x, float) for x in embedding)
    embedding2 = generate_embedding("Normal backup operation completed")
    assert embedding != embedding2

@test("Vector Store: Point ID generation is stable")
async def test_point_id():
    from src.services.vector_store import _string_to_point_id
    id1 = _string_to_point_id("alert-001")
    id2 = _string_to_point_id("alert-001")
    id3 = _string_to_point_id("alert-002")
    assert id1 == id2
    assert id1 != id3
    assert isinstance(id1, int)

# ━━━ TEST 10: Hunting Agent ━━━
@test("Hunting Agent: Search text builder")
async def test_hunting_search_text():
    from src.agents.hunting import _build_search_text
    state = {
        "alert_id": "test-001",
        "raw_data": {"event_type": "ransomware", "src_ip": "1.2.3.4"},
        "normalized": {
            "event_type": "suspicious_file_encryption",
            "description": "Mass file encryption on WS-FINANCE-04",
            "hostname": "WS-FINANCE-04", "username": "j.smith",
            "source_ip": "192.168.1.45",
        },
        "ioc_list": {"ips": ["192.168.1.45"], "hashes_sha256": ["abc123"], "domains": []},
        "triage_score": 0.95, "confidence": 0.9, "classification": "critical",
        "triage_reasoning": None, "enrichment_results": None, "similar_cases": None,
        "pattern_match": None, "historical_context": None, "actions_taken": None,
        "response_status": None, "analyst_feedback": None, "feedback_label": None,
        "next_agent": None, "should_escalate": None, "error": None,
    }
    text = _build_search_text(state)
    assert "suspicious_file_encryption" in text
    assert "WS-FINANCE-04" in text
    assert "192.168.1.45" in text

@test("Hunting Agent: RAG prompt contains analysis rules")
async def test_hunting_prompt():
    from src.agents.hunting import HUNTING_SYSTEM_PROMPT
    assert "repeat_attacker" in HUNTING_SYSTEM_PROMPT
    assert "adjusted_severity" in HUNTING_SYSTEM_PROMPT

# ━━━ TEST 11: Redis Cache ━━━
@test("Redis Cache: Module imports and stats work")
async def test_cache_module():
    from src.services.cache import RedisCache
    cache = RedisCache(ttl=3600)
    assert cache.default_ttl == 3600
    assert cache.hit_rate == 0.0

# ━━━ TEST 12: Sample Alerts ━━━
@test("Sample alerts fixture: Valid JSON with 20+ alerts")
async def test_fixtures():
    from pathlib import Path
    fixture_path = Path(__file__).parent / "fixtures" / "sample_alerts.json"
    with open(fixture_path) as f:
        alerts = json.load(f)
    assert len(alerts) >= 20
    sources = set(a["source"] for a in alerts)
    assert len(sources) >= 5

@test("Sample alerts: All normalize without errors")
async def test_normalize_all_fixtures():
    from pathlib import Path
    from src.ingestion.normalizer import AlertNormalizer
    n = AlertNormalizer()
    fixture_path = Path(__file__).parent / "fixtures" / "sample_alerts.json"
    with open(fixture_path) as f:
        alerts = json.load(f)
    for alert in alerts:
        result = n.normalize(alert["source"], alert["data"])
        assert "indicators" in result

# ━━━ TEST 13: FastAPI App ━━━
@test("FastAPI app: Imports and has expected routes")
async def test_fastapi_app():
    from src.api.main import app
    routes = [r.path for r in app.routes]
    assert "/alerts" in routes
    assert "/alerts/{alert_id}" in routes
    assert "/feedback" in routes
    assert "/stats/overview" in routes
    assert "/health" in routes


# ━━━ RUN ALL ━━━
async def main():
    print("")
    print("=" * 55)
    print("  Autonomous SOC \u2014 Phase 1 & 2 Verification")
    print("=" * 55)
    print("")

    tests = [
        test_config, test_models, test_schemas, test_state,
        test_normalizer_json, test_normalizer_cef, test_normalizer_syslog, test_normalizer_iocs,
        test_llm_client,
        test_triage_imports, test_triage_formatter, test_triage_learned_rules,
        test_private_ip, test_benign_domains, test_empty_results,
        test_enrichment_merge, test_enrichment_signature,
        test_embedding, test_point_id,
        test_hunting_search_text, test_hunting_prompt,
        test_cache_module,
        test_fixtures, test_normalize_all_fixtures,
        test_fastapi_app,
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
        print("  \U0001f389 All tests passed! Phase 1 & 2 verified.")
        print("     Ready to proceed to Phase 3.")
    else:
        print(f"  \u26a0\ufe0f  {failed} test(s) failed. Fix issues before proceeding.")
    print("")
    return failed


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))