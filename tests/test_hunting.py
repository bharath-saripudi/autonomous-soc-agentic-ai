"""Unit tests for the Hunting Agent."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.hunting import hunting_agent, _build_search_text, HUNTING_SYSTEM_PROMPT
from src.services.vector_store import generate_embedding, _string_to_point_id, VECTOR_SIZE

def test_embedding_dimensions():
    vec = generate_embedding("SSH brute force from 45.33.32.156")
    assert len(vec) == VECTOR_SIZE
    assert all(isinstance(v, float) for v in vec)

def test_embedding_deterministic():
    v1 = generate_embedding("ransomware detected")
    v2 = generate_embedding("ransomware detected")
    assert v1 == v2

def test_embedding_different_for_different_text():
    v1 = generate_embedding("SSH brute force")
    v2 = generate_embedding("DNS tunneling exfiltration")
    assert v1 != v2

def test_point_id_stable():
    id1 = _string_to_point_id("alert-001")
    id2 = _string_to_point_id("alert-001")
    assert id1 == id2
    assert isinstance(id1, int)

def test_build_search_text():
    state = {"normalized":{"event_type":"ssh_brute_force","description":"342 failed logins","hostname":"WS-01","source_ip":"45.33.32.156"},"raw_data":{}}
    text = _build_search_text(state)
    assert "ssh_brute_force" in text

def test_hunting_prompt_exists():
    assert len(HUNTING_SYSTEM_PROMPT) > 50
    assert "threat" in HUNTING_SYSTEM_PROMPT.lower() or "alert" in HUNTING_SYSTEM_PROMPT.lower()

def test_hunting_agent_signature():
    import inspect
    sig = inspect.signature(hunting_agent)
    assert list(sig.parameters.keys()) == ["state"]

if __name__ == "__main__":
    test_embedding_dimensions()
    test_embedding_deterministic()
    test_embedding_different_for_different_text()
    test_point_id_stable()
    test_build_search_text()
    test_hunting_prompt_exists()
    test_hunting_agent_signature()
    print("All hunting tests passed ✅")