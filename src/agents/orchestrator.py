"""Orchestrator Agent — LangGraph StateGraph wiring all 6 agents.

The brain of the Autonomous SOC. Defines the workflow graph:

  Normalize → Triage → [route] → Enrichment → Hunting → [route] → Response → Learning → END
                          ↓                                 ↓
                        Close                            Escalate

Conditional routing after Triage:
  - score <= 0.15  → auto-close (false positive / info)
  - score > 0.15   → continue to enrichment

Conditional routing after Hunting:
  - critical + high confidence → response (auto-respond + escalate)
  - critical + low confidence  → escalate (human decides)
  - medium/high               → response
  - low                       → close

All agents share state via AgentState TypedDict.
"""

import time
import uuid
from datetime import datetime
from typing import Dict, Any

import structlog

from src.state import AgentState
from src.ingestion.normalizer import AlertNormalizer
from src.services.audit import log_audit

logger = structlog.get_logger()
normalizer = AlertNormalizer()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Workflow Graph Builder
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_workflow():
    """Construct the multi-agent LangGraph StateGraph.

    Returns a compiled graph ready to invoke with an AgentState.
    """
    from langgraph.graph import StateGraph, END
    from src.agents.triage import triage_agent
    from src.agents.enrichment import enrichment_agent
    from src.agents.hunting import hunting_agent
    from src.agents.response import response_agent
    from src.agents.learning import learning_agent

    graph = StateGraph(AgentState)

    # ── Define Nodes ─────────────────────────────────────────
    graph.add_node("normalize", normalize_node)
    graph.add_node("triage", triage_agent)
    graph.add_node("enrichment", enrichment_agent)
    graph.add_node("hunting", hunting_agent)
    graph.add_node("response", response_agent)
    graph.add_node("learning", learning_agent)
    graph.add_node("close_alert", close_alert_node)
    graph.add_node("escalate", escalate_node)

    # ── Define Edges ─────────────────────────────────────────

    # Entry point
    graph.set_entry_point("normalize")

    # Normalize always goes to triage
    graph.add_edge("normalize", "triage")

    # After triage: route based on severity
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "close": "close_alert",
            "enrichment": "enrichment",
        }
    )

    # Enrichment always goes to hunting
    graph.add_edge("enrichment", "hunting")

    # After hunting: route based on severity + confidence
    graph.add_conditional_edges(
        "hunting",
        route_after_hunting,
        {
            "response": "response",
            "escalate": "escalate",
            "close": "close_alert",
        }
    )

    # Response goes to learning
    graph.add_edge("response", "learning")

    # Close and escalate also go to learning (record everything)
    graph.add_edge("close_alert", "learning")
    graph.add_edge("escalate", "learning")

    # Learning is the final step
    graph.add_edge("learning", END)

    return graph.compile()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Routing Functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def route_after_triage(state: AgentState) -> str:
    """Decide what happens after triage.

    score <= 0.15 → close (false positive / informational)
    score > 0.15  → continue to enrichment
    """
    score = state.get("triage_score", 0.5)

    if score <= 0.15:
        logger.info("route_triage_close", alert_id=state["alert_id"], score=score)
        return "close"

    logger.info("route_triage_enrich", alert_id=state["alert_id"], score=score)
    return "enrichment"


def route_after_hunting(state: AgentState) -> str:
    """Decide what happens after hunting.

    critical (>=0.90) + high confidence (>=0.85) → response (auto-respond)
    critical (>=0.90) + low confidence            → escalate (human decides)
    medium/high (>=0.40)                          → response
    low (<0.40)                                   → close
    """
    score = state.get("triage_score", 0.5)
    confidence = state.get("confidence", 0.5)

    if score >= 0.90:
        if confidence >= 0.85:
            logger.info("route_hunting_response_critical", alert_id=state["alert_id"],
                       score=score, confidence=confidence)
            return "response"
        else:
            logger.info("route_hunting_escalate", alert_id=state["alert_id"],
                       score=score, confidence=confidence)
            return "escalate"

    if score >= 0.40:
        logger.info("route_hunting_response", alert_id=state["alert_id"], score=score)
        return "response"

    logger.info("route_hunting_close", alert_id=state["alert_id"], score=score)
    return "close"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helper Nodes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def normalize_node(state: AgentState) -> AgentState:
    """Normalize raw alert data into unified schema."""
    raw = state.get("raw_data") or {}
    source = raw.get("source", "unknown")

    state["normalized"] = normalizer.normalize(source, raw)

    await log_audit(
        alert_id=state["alert_id"],
        agent="orchestrator",
        action="alert_normalized",
        details={"source": source},
    )

    return state


async def close_alert_node(state: AgentState) -> AgentState:
    """Auto-close an alert as false positive or low severity."""
    state["response_status"] = "closed"

    await log_audit(
        alert_id=state["alert_id"],
        agent="orchestrator",
        action="alert_auto_closed",
        details={
            "triage_score": state.get("triage_score"),
            "classification": state.get("classification"),
            "reason": "Below severity threshold",
        },
    )

    logger.info("alert_auto_closed", alert_id=state["alert_id"],
               score=state.get("triage_score"))

    return state


async def escalate_node(state: AgentState) -> AgentState:
    """Escalate alert to human analysts."""
    state["response_status"] = "escalated"
    state["should_escalate"] = True

    await log_audit(
        alert_id=state["alert_id"],
        agent="orchestrator",
        action="alert_escalated",
        details={
            "triage_score": state.get("triage_score"),
            "confidence": state.get("confidence"),
            "reason": "Critical severity with insufficient confidence for auto-response",
        },
    )

    logger.info("alert_escalated", alert_id=state["alert_id"],
               score=state.get("triage_score"), confidence=state.get("confidence"))

    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Database Persistence
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def save_final_state(alert_id: str, state: AgentState):
    """Persist the final agent state to the database."""
    try:
        from src.database import get_db
        from src.models import Alert

        async with get_db() as db:
            from sqlalchemy import select
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()

            if alert:
                alert.status = state.get("response_status", "closed")
                alert.triage_score = state.get("triage_score")
                alert.triage_reasoning = state.get("triage_reasoning")
                alert.confidence = state.get("confidence")
                alert.enrichment_results = state.get("enrichment_results")
                alert.similar_cases = state.get("similar_cases")
                alert.actions_taken = state.get("actions_taken")
                alert.is_false_positive = (state.get("triage_score", 1) <= 0.15)
                alert.updated_at = datetime.utcnow()

                if state.get("response_status") == "closed":
                    alert.closed_at = datetime.utcnow()

                logger.info("final_state_saved", alert_id=alert_id,
                           status=alert.status, score=alert.triage_score)

    except Exception as e:
        logger.error("save_final_state_error", alert_id=alert_id, error=str(e))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Compile the workflow once at module level
_workflow = None


def get_workflow():
    """Get or build the compiled workflow (lazy singleton)."""
    global _workflow
    if _workflow is None:
        _workflow = build_workflow()
        logger.info("workflow_compiled")
    return _workflow


async def run_workflow(alert_id: str, source: str, raw_data: Dict[str, Any]) -> AgentState:
    """Execute the full multi-agent pipeline for one alert.

    This is the main entry point called by the API when a new alert arrives.

    Args:
        alert_id: Unique alert identifier
        source: Alert source (syslog, api, kafka, etc.)
        raw_data: Raw alert data dict

    Returns:
        Final AgentState with all fields populated
    """
    start_time = time.time()

    logger.info("workflow_started", alert_id=alert_id, source=source)

    # Initialize empty state
    initial_state: AgentState = {
        "alert_id": alert_id,
        "raw_data": raw_data,
        "normalized": None,
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

    # Run the workflow
    workflow = get_workflow()
    final_state = await workflow.ainvoke(initial_state)

    # Persist results to database
    await save_final_state(alert_id, final_state)

    total_time = round(time.time() - start_time, 2)

    logger.info(
        "workflow_complete",
        alert_id=alert_id,
        total_time_sec=total_time,
        triage_score=final_state.get("triage_score"),
        classification=final_state.get("classification"),
        response_status=final_state.get("response_status"),
        actions_count=len(final_state.get("actions_taken") or []),
    )

    await log_audit(
        alert_id=alert_id,
        agent="orchestrator",
        action="workflow_complete",
        details={
            "total_time_sec": total_time,
            "final_status": final_state.get("response_status"),
            "triage_score": final_state.get("triage_score"),
            "actions_taken": len(final_state.get("actions_taken") or []),
        },
    )

    return final_state