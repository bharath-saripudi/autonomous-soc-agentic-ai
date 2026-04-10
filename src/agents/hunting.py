"""Hunting Agent — Historical pattern detection via vector search + RAG.

Third agent in the pipeline (after Enrichment). Searches the Qdrant
vector database for similar past incidents, then feeds that historical
context to Claude via Retrieval-Augmented Generation to:
  - Identify repeat attackers
  - Detect attack campaign patterns
  - Adjust severity based on institutional memory
  - Rule out false positive scenarios seen before

Reads:  normalized, raw_data, triage_score, enrichment_results
Writes: similar_cases, pattern_match, historical_context, triage_score (adjusted), next_agent
"""

import time
from typing import Any, Dict, List

import structlog

from src.state import AgentState
from src.services.vector_store import search_similar_incidents
from src.services.llm_client import get_llm, LLMError
from src.services.audit import log_audit

logger = structlog.get_logger()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RAG System Prompt — Historical analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HUNTING_SYSTEM_PROMPT = """You are an expert threat hunter analyzing a current security alert 
in the context of similar past incidents from your organization's history.

Your job is to:
1. Compare the current alert against similar historical incidents
2. Identify if this is a repeat attack, part of a campaign, or a known pattern
3. Check if similar past alerts turned out to be false positives
4. Determine if historical context should raise or lower the severity assessment

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "pattern_match": true/false,
  "pattern_type": "repeat_attacker|campaign|similar_technique|false_positive_pattern|novel",
  "historical_context": "Summary of what past incidents tell us about this alert",
  "key_findings": ["finding1", "finding2"],
  "adjusted_severity": <float 0.0 to 1.0 or null if no change recommended>,
  "adjustment_reasoning": "Why severity should be changed (or null if no change)",
  "confidence_boost": <float -0.2 to +0.2, how much to adjust confidence>,
  "recommendation": "Brief recommendation based on historical analysis"
}

ANALYSIS RULES:
- If the same IP/hash attacked before and was confirmed malicious → INCREASE severity
- If the same IP/hash appeared before and was marked false positive → DECREASE severity
- If similar technique was seen recently (within 7 days) → flag as possible campaign
- If no similar incidents found → mark as "novel" (neither increase nor decrease)
- Multiple past incidents matching the same IOC = stronger signal
- Past incidents with "escalated" or "responded" outcomes indicate confirmed threats
- Past incidents with "closed" + false_positive = likely benign
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Hunting Agent Function
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def hunting_agent(state: AgentState) -> AgentState:
    """Search for similar past incidents and analyze patterns via RAG.

    Reads:  normalized, raw_data, triage_score, enrichment_results
    Writes: similar_cases, pattern_match, historical_context, next_agent
    """
    start_time = time.time()
    alert_id = state["alert_id"]

    logger.info("hunting_started", alert_id=alert_id)

    try:
        # ── Step 1: Build search text ────────────────────────────
        alert_text = _build_search_text(state)

        # ── Step 2: Vector similarity search ─────────────────────
        similar_cases = await search_similar_incidents(
            text=alert_text,
            limit=5,
            score_threshold=0.5,
        )

        state["similar_cases"] = similar_cases

        logger.info(
            "hunting_search_complete",
            alert_id=alert_id,
            similar_found=len(similar_cases),
            top_score=similar_cases[0]["score"] if similar_cases else 0,
        )

        # ── Step 3: RAG analysis with Claude ─────────────────────
        if similar_cases:
            rag_result = await _analyze_with_rag(state, alert_text, similar_cases)

            # Update state with RAG findings
            state["pattern_match"] = rag_result.get("pattern_match", False)
            state["historical_context"] = rag_result.get("historical_context", "")

            # Adjust severity if RAG recommends it
            adjusted = rag_result.get("adjusted_severity")
            if adjusted is not None:
                original_score = state.get("triage_score", 0)
                state["triage_score"] = _clamp(adjusted, 0.0, 1.0)

                logger.info(
                    "hunting_severity_adjusted",
                    alert_id=alert_id,
                    original=original_score,
                    adjusted=state["triage_score"],
                    reason=rag_result.get("adjustment_reasoning"),
                )

            # Adjust confidence
            confidence_boost = rag_result.get("confidence_boost", 0)
            if confidence_boost and state.get("confidence"):
                state["confidence"] = _clamp(
                    state["confidence"] + confidence_boost, 0.0, 1.0
                )

        else:
            # No similar cases found — mark as novel
            state["pattern_match"] = False
            state["historical_context"] = "No similar past incidents found. This appears to be a novel event."

        # ── Step 4: Route to next agent ──────────────────────────
        state["next_agent"] = "response"

        latency = round(time.time() - start_time, 2)

        # Audit log
        await log_audit(
            alert_id=alert_id,
            agent="hunting",
            action="historical_search_complete",
            details={
                "similar_cases_found": len(similar_cases),
                "top_similarity_score": similar_cases[0]["score"] if similar_cases else 0,
                "pattern_match": state.get("pattern_match", False),
                "severity_adjusted": state.get("triage_score"),
                "latency_sec": latency,
            },
        )

        logger.info(
            "hunting_complete",
            alert_id=alert_id,
            similar_found=len(similar_cases),
            pattern_match=state.get("pattern_match"),
            latency_sec=latency,
        )

    except Exception as e:
        logger.error("hunting_error", alert_id=alert_id, error=str(e))
        state["similar_cases"] = []
        state["pattern_match"] = False
        state["historical_context"] = f"Hunting error: {e}"
        state["next_agent"] = "response"  # Continue pipeline
        state["error"] = f"Hunting error: {e}"

        await log_audit(
            alert_id=alert_id,
            agent="hunting",
            action="hunting_failed",
            details={"error": str(e)},
        )

    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RAG Analysis
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _analyze_with_rag(
    state: AgentState,
    alert_text: str,
    similar_cases: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Feed current alert + similar past incidents to Claude for analysis.

    This is the RAG (Retrieval-Augmented Generation) step — we retrieve
    relevant historical incidents and augment the LLM's context with them.
    """
    # Format historical cases for the prompt
    history_lines = []
    for i, case in enumerate(similar_cases, 1):
        history_lines.append(
            f"--- Past Incident {i} (similarity: {case['score']}) ---\n"
            f"  Description: {case.get('description', 'N/A')}\n"
            f"  Severity: {case.get('severity', 'N/A')}\n"
            f"  Event Type: {case.get('event_type', 'N/A')}\n"
            f"  Outcome: {case.get('outcome', 'N/A')}\n"
            f"  Was False Positive: {case.get('was_false_positive', 'N/A')}\n"
            f"  Timestamp: {case.get('timestamp', 'N/A')}\n"
            f"  IOCs: {case.get('iocs', 'N/A')}"
        )
    history_text = "\n\n".join(history_lines)

    # Include enrichment context if available
    enrichment_summary = ""
    enrichment = state.get("enrichment_results", {})
    if enrichment:
        malicious = enrichment.get("summary", {}).get("malicious_found", 0)
        total = enrichment.get("summary", {}).get("total_lookups", 0)
        enrichment_summary = f"\n\nENRICHMENT FINDINGS: {malicious} malicious IOCs found out of {total} lookups."

    # Build the user prompt
    user_prompt = (
        f"CURRENT ALERT (triage score: {state.get('triage_score', 'N/A')}):\n"
        f"{alert_text}\n"
        f"{enrichment_summary}\n\n"
        f"SIMILAR PAST INCIDENTS ({len(similar_cases)} found):\n\n"
        f"{history_text}"
    )

    try:
        llm = get_llm()
        result = await llm.reason(
            system_prompt=HUNTING_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
        )
        return result

    except LLMError as e:
        logger.error("hunting_rag_error", error=str(e))
        return {
            "pattern_match": False,
            "historical_context": f"RAG analysis failed: {e}",
            "adjusted_severity": None,
            "confidence_boost": 0,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _build_search_text(state: AgentState) -> str:
    """Build a rich text representation of the alert for embedding search.

    Combines normalized fields, raw data highlights, and enrichment
    findings into a single text block that captures the alert's semantics.
    """
    parts = []
    normalized = state.get("normalized") or {}
    raw_data = state.get("raw_data") or {}

    # Event type and description are most important for similarity
    event_type = normalized.get("event_type") or raw_data.get("event_type", "")
    description = normalized.get("description") or raw_data.get("message", "")
    if event_type:
        parts.append(f"Event: {event_type}")
    if description:
        parts.append(f"Description: {description}")

    # Key fields that help match similar incidents
    for field in ["hostname", "username", "process", "protocol"]:
        val = normalized.get(field) or raw_data.get(field)
        if val:
            parts.append(f"{field}: {val}")

    # Source and destination context
    src_ip = normalized.get("source_ip") or raw_data.get("src_ip")
    dst_ip = normalized.get("dest_ip") or raw_data.get("dst_ip")
    dst_port = normalized.get("dest_port") or raw_data.get("dst_port")
    if src_ip:
        parts.append(f"source_ip: {src_ip}")
    if dst_ip:
        parts.append(f"dest_ip: {dst_ip}")
    if dst_port:
        parts.append(f"dest_port: {dst_port}")

    # IOCs for matching against past incidents with same indicators
    iocs = state.get("ioc_list") or normalized.get("indicators", {})
    for ioc_type in ["ips", "hashes_sha256", "domains"]:
        values = iocs.get(ioc_type, [])
        if values:
            parts.append(f"{ioc_type}: {', '.join(values[:5])}")  # Limit to 5

    return "\n".join(parts) if parts else str(raw_data)[:500]


def _clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp a value between min and max."""
    return max(min_val, min(max_val, value))