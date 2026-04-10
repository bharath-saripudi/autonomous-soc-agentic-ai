"""Learning Agent — RLHF feedback collection and prompt evolution.

Final agent in the pipeline. Responsible for:
  1. Storing the processed alert as an embedding in Qdrant (builds memory)
  2. Processing any pending analyst feedback from the feedback queue
  3. Generating new triage rules from feedback patterns
  4. Updating the Triage Agent's prompt with learned rules

This creates a continuous improvement loop:
  Alert → Process → Feedback → Learn → Better Triage → Repeat

Reads:  All state fields (full pipeline context)
Writes: (none — terminal node, writes to vector DB and triage rules)
"""

import time
from typing import Any, Dict, List

import structlog

from src.state import AgentState
from src.services.vector_store import store_incident_embedding
from src.services.llm_client import get_llm, LLMError
from src.services.audit import log_audit

logger = structlog.get_logger()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Learning System Prompt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LEARNING_SYSTEM_PROMPT = """You are analyzing analyst feedback on security alert triage decisions.
Your job is to extract actionable rules that can improve future triage accuracy.

Given a set of feedback entries (where analysts corrected the AI's triage), generate
specific, concrete rules that the triage agent should follow in the future.

Each rule should be:
  - Specific enough to apply to future similar alerts
  - Based on the pattern across multiple feedback entries (not just one)
  - Actionable (tells the triage agent exactly what to do differently)

Respond ONLY with valid JSON:
{
  "rules": [
    {
      "rule": "Clear, specific instruction for the triage agent",
      "pattern": "What pattern this rule addresses",
      "confidence": <float 0.0 to 1.0>
    }
  ],
  "summary": "Brief summary of what was learned"
}

If there isn't enough feedback to generate reliable rules, return:
{"rules": [], "summary": "Insufficient feedback for rule generation"}
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Learning Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def learning_agent(state: AgentState) -> AgentState:
    """Store incident embedding and process feedback for continuous learning.

    This is the terminal node in the workflow graph.
    """
    start_time = time.time()
    alert_id = state["alert_id"]

    logger.info("learning_started", alert_id=alert_id)

    try:
        # ── Step 1: Store incident in vector DB ──────────────────
        await _store_incident(state)

        # ── Step 2: Process pending feedback ─────────────────────
        feedback_processed = await _process_pending_feedback()

        latency = round(time.time() - start_time, 2)

        await log_audit(
            alert_id=alert_id,
            agent="learning",
            action="learning_complete",
            details={
                "incident_stored": True,
                "feedback_processed": feedback_processed,
                "latency_sec": latency,
            },
        )

        logger.info(
            "learning_complete",
            alert_id=alert_id,
            feedback_processed=feedback_processed,
            latency_sec=latency,
        )

    except Exception as e:
        logger.error("learning_error", alert_id=alert_id, error=str(e))

    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Incident Storage (builds institutional memory)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _store_incident(state: AgentState):
    """Store the completed alert as an embedding in Qdrant.

    This builds the vector database that the Hunting Agent searches
    to find similar past incidents.
    """
    alert_id = state["alert_id"]
    normalized = state.get("normalized") or {}
    raw = state.get("raw_data") or {}

    # Build text for embedding
    parts = []
    event_type = normalized.get("event_type") or raw.get("event_type", "")
    description = normalized.get("description") or raw.get("message", "")
    if event_type:
        parts.append(f"Event: {event_type}")
    if description:
        parts.append(f"Description: {description}")
    for field in ["hostname", "username", "process", "source_ip", "dest_ip"]:
        val = normalized.get(field) or raw.get(field)
        if val:
            parts.append(f"{field}: {val}")

    text = "\n".join(parts) if parts else str(raw)[:500]

    # Build metadata
    metadata = {
        "severity": state.get("triage_score", 0),
        "event_type": event_type or "unknown",
        "outcome": state.get("response_status", "unknown"),
        "was_false_positive": (state.get("triage_score", 1) <= 0.15),
        "classification": state.get("classification", "unknown"),
        "timestamp": time.time(),
        "actions_count": len(state.get("actions_taken") or []),
        "pattern_match": state.get("pattern_match", False),
    }

    # Store IOCs in metadata for future matching
    iocs = state.get("ioc_list") or normalized.get("indicators", {})
    if iocs:
        metadata["iocs"] = {
            "ips": iocs.get("ips", [])[:10],
            "hashes": iocs.get("hashes_sha256", [])[:5],
            "domains": iocs.get("domains", [])[:5],
        }

    success = await store_incident_embedding(alert_id, text, metadata)
    if success:
        logger.info("incident_stored_for_learning", alert_id=alert_id)
    else:
        logger.warning("incident_store_failed", alert_id=alert_id)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Feedback Processing (RLHF loop)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# In-memory feedback buffer (production: read from feedback_queue table)
_feedback_buffer: List[Dict[str, Any]] = []
FEEDBACK_BATCH_SIZE = 5  # Generate rules after every N feedback entries


def add_feedback(feedback: Dict[str, Any]):
    """Add analyst feedback to the buffer for batch processing."""
    _feedback_buffer.append(feedback)
    logger.info("feedback_buffered", total_pending=len(_feedback_buffer))


async def _process_pending_feedback() -> int:
    """Process buffered feedback and generate new triage rules.

    Returns the number of feedback entries processed.
    """
    if len(_feedback_buffer) < FEEDBACK_BATCH_SIZE:
        return 0

    # Take a batch
    batch = _feedback_buffer[:FEEDBACK_BATCH_SIZE]

    try:
        # Ask Claude to analyze feedback patterns
        rules = await _generate_rules_from_feedback(batch)

        if rules:
            from src.agents.triage import add_learned_rule

            for rule_entry in rules:
                rule_text = rule_entry.get("rule", "")
                confidence = rule_entry.get("confidence", 0)

                # Only add rules with sufficient confidence
                if rule_text and confidence >= 0.7:
                    add_learned_rule(rule_text)
                    logger.info(
                        "learned_rule_from_feedback",
                        rule=rule_text,
                        confidence=confidence,
                    )

        # Clear processed entries
        del _feedback_buffer[:FEEDBACK_BATCH_SIZE]

        return len(batch)

    except Exception as e:
        logger.error("feedback_processing_error", error=str(e))
        return 0


async def _generate_rules_from_feedback(
    feedback_batch: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Use Claude to analyze feedback patterns and generate triage rules."""
    # Format feedback for Claude
    feedback_text = ""
    for i, fb in enumerate(feedback_batch, 1):
        feedback_text += (
            f"--- Feedback {i} ---\n"
            f"  Alert ID: {fb.get('alert_id', 'N/A')}\n"
            f"  AI Classification: {fb.get('ai_classification', 'N/A')}\n"
            f"  AI Score: {fb.get('ai_score', 'N/A')}\n"
            f"  Analyst Label: {fb.get('label', 'N/A')}\n"
            f"  Correct Severity: {fb.get('correct_severity', 'N/A')}\n"
            f"  Alert Summary: {fb.get('summary', 'N/A')}\n"
            f"  Notes: {fb.get('notes', 'N/A')}\n\n"
        )

    try:
        llm = get_llm()
        result = await llm.reason(
            system_prompt=LEARNING_SYSTEM_PROMPT,
            user_prompt=f"Analyze these {len(feedback_batch)} feedback entries:\n\n{feedback_text}",
            temperature=0.2,
        )

        rules = result.get("rules", [])
        summary = result.get("summary", "")

        logger.info(
            "rules_generated",
            rules_count=len(rules),
            summary=summary,
        )

        return rules

    except LLMError as e:
        logger.error("rule_generation_error", error=str(e))
        return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Stats
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def get_learning_stats() -> Dict[str, Any]:
    """Return current learning system statistics."""
    from src.agents.triage import get_learned_rules

    return {
        "pending_feedback": len(_feedback_buffer),
        "batch_size": FEEDBACK_BATCH_SIZE,
        "learned_rules_count": len(get_learned_rules()),
        "learned_rules": get_learned_rules(),
    }