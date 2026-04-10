"""Shared state that flows through all agents in the LangGraph workflow.

Every agent reads from and writes to this TypedDict. The LangGraph StateGraph
passes the updated state between agents automatically.
"""

from typing import Any, Dict, List, Optional, TypedDict


class AgentState(TypedDict):
    """Persistent state shared across all six agents."""

    # ── Identity ──
    alert_id: str
    raw_data: Dict[str, Any]
    normalized: Optional[Dict[str, Any]]

    # ── Triage Agent Output ──
    triage_score: Optional[float]           # 0.0 (benign) → 1.0 (critical)
    triage_reasoning: Optional[str]         # Step-by-step ReAct reasoning
    confidence: Optional[float]             # 0.0 → 1.0 how sure the AI is
    classification: Optional[str]           # critical/high/medium/low/info/false_positive

    # ── Enrichment Agent Output ──
    ioc_list: Optional[Dict[str, List]]     # {"ips": [], "hashes": [], "domains": []}
    enrichment_results: Optional[Dict]      # API lookup results per IOC

    # ── Hunting Agent Output ──
    similar_cases: Optional[List[Dict]]     # Top-5 similar past incidents from Qdrant
    pattern_match: Optional[bool]           # Does this match a known attack pattern?
    historical_context: Optional[str]       # LLM summary of historical relevance

    # ── Response Agent Output ──
    actions_taken: Optional[List[Dict]]     # [{"action": "block_ip", "target": "x", "status": "..."}]
    response_status: Optional[str]          # executed / skipped / escalated / closed

    # ── Learning Agent ──
    analyst_feedback: Optional[str]
    feedback_label: Optional[str]           # agree / false_positive / missed / severity_wrong

    # ── Routing Control ──
    next_agent: Optional[str]               # Used by conditional edges
    should_escalate: Optional[bool]         # Flag for human escalation
    error: Optional[str]                    # Error message if any agent fails