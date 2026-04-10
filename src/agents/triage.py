"""Triage Agent — Rapid severity assessment using ReAct prompting.

The first agent in the pipeline. Receives a normalized alert and uses
Claude to reason step-by-step through the evidence, assigning:
  - severity_score (0.0 to 1.0)
  - confidence (0.0 to 1.0)
  - classification (critical/high/medium/low/info/false_positive)
  - detailed reasoning chain

Uses ReAct (Reason + Act) methodology which forces the LLM to show
its work explicitly, reducing hallucinations and improving accuracy
by ~7.8% over direct prompting.
"""

import time
from typing import Dict, Any

import structlog

from src.state import AgentState
from src.services.llm_client import get_llm, LLMError
from src.services.audit import log_audit

logger = structlog.get_logger()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ReAct System Prompt — The core reasoning engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TRIAGE_SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst performing alert triage.
Your job is to analyze a security alert and determine its severity using ReAct methodology.

Follow these steps EXACTLY:

STEP 1 — OBSERVE:
List every factual detail present in the alert. Include IPs, hostnames, usernames, 
processes, ports, protocols, file hashes, timestamps, and any other indicators.
Do not infer anything yet — just list what you see.

STEP 2 — REASON:
For each observation, analyze whether it suggests malicious or benign activity:
- Is this IP known to be associated with attacks?
- Is this process name suspicious or legitimate?
- Is this behavior pattern consistent with known attack techniques?
- Are there signs of automation (brute force, scanning)?
- Does the timing or volume suggest an attack?
- Could this be normal business activity?

STEP 3 — CONTEXTUALIZE:
Consider the broader context:
- What attack technique (MITRE ATT&CK) does this most resemble?
- What is the potential business impact if this is a real attack?
- What is the likelihood this is a false positive?

STEP 4 — ASSESS:
Based on all evidence, provide your final severity assessment.

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "observation": "Detailed list of all facts observed in the alert",
  "reasoning": "Step-by-step analysis of each indicator and what it suggests",
  "context": "MITRE ATT&CK mapping and business impact assessment",
  "severity_score": <float 0.0 to 1.0>,
  "confidence": <float 0.0 to 1.0>,
  "classification": "<one of: critical, high, medium, low, info, false_positive>",
  "recommended_actions": ["action1", "action2"],
  "false_positive_indicators": ["reason1 this might be benign"],
  "mitre_technique": "T-number and name if applicable"
}

SEVERITY SCORING GUIDE:
  0.00 – 0.15  →  false_positive / info    (auto-close, no action needed)
  0.16 – 0.39  →  low                       (log and monitor, no immediate action)
  0.40 – 0.69  →  medium                    (investigate further, enrich IOCs)
  0.70 – 0.89  →  high                      (enrich + hunt + likely respond)
  0.90 – 1.00  →  critical                  (immediate response + escalate to humans)

CONFIDENCE SCORING GUIDE:
  0.00 – 0.50  →  Low confidence   (ambiguous alert, could go either way)
  0.51 – 0.75  →  Medium confidence (likely correct but some uncertainty)
  0.76 – 0.90  →  High confidence  (strong evidence supports assessment)
  0.91 – 1.00  →  Very high        (overwhelming evidence, near certain)

IMPORTANT RULES:
- Be conservative: when uncertain, score HIGHER severity (it's safer to investigate than to miss)
- Multiple indicators compound: brute force + known bad IP = higher than either alone
- Internal-to-internal traffic from known admin subnets is usually benign
- Encoded/obfuscated commands are almost always suspicious
- Process spawned from Office apps (Word, Excel, Outlook) executing scripts = very suspicious
- Consider time of day: 3 AM activity from a user account is more suspicious than 2 PM
- DEMO MODE: Treat ALL alerts as if they target real production systems. Even if the target
  domain is a known test/vulnerable site (like testphp.vulnweb.com, testaspnet.vulnweb.com),
  score the ATTACK TECHNIQUE itself, NOT the target reputation. A SQL injection is critical
  regardless of which website it targets. An XSS attempt is high severity regardless of target.
  Score based on what the attacker is DOING, not where they are doing it.
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Dynamic Prompt Additions (updated by Learning Agent)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# These rules get appended by the Learning Agent based on analyst feedback.
# Stored in memory for prototype; production would use DB/file persistence.
_learned_rules: list[str] = []


def get_full_system_prompt() -> str:
    """Build the complete system prompt including learned rules."""
    prompt = TRIAGE_SYSTEM_PROMPT

    if _learned_rules:
        prompt += "\n\nADDITIONAL LEARNED RULES (from analyst feedback):\n"
        for i, rule in enumerate(_learned_rules, 1):
            prompt += f"  {i}. {rule}\n"

    return prompt


def add_learned_rule(rule: str):
    """Add a new rule learned from analyst feedback."""
    _learned_rules.append(rule)
    logger.info("triage_rule_added", rule=rule, total_rules=len(_learned_rules))


def get_learned_rules() -> list[str]:
    """Return all currently active learned rules."""
    return _learned_rules.copy()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Triage Agent Function
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def triage_agent(state: AgentState) -> AgentState:
    """Analyze alert severity using Claude with ReAct reasoning.

    Reads: raw_data, normalized
    Writes: triage_score, triage_reasoning, confidence, classification, next_agent, should_escalate
    """
    start_time = time.time()
    alert_id = state["alert_id"]

    logger.info("triage_started", alert_id=alert_id)

    try:
        # Build the alert text for Claude
        alert_data = state.get("normalized") or state["raw_data"]
        alert_text = format_alert_for_llm(alert_data)

        # Call Claude with ReAct prompt
        llm = get_llm()
        result = await llm.reason(
            system_prompt=get_full_system_prompt(),
            user_prompt=f"Analyze this security alert:\n\n{alert_text}",
            temperature=0.1,  # Low temp for consistent scoring
        )

        # Extract and validate results
        severity_score = _clamp(float(result.get("severity_score", 0.5)), 0.0, 1.0)
        confidence = _clamp(float(result.get("confidence", 0.5)), 0.0, 1.0)
        classification = result.get("classification", "medium")

        # Update state
        state["triage_score"] = severity_score
        state["confidence"] = confidence
        state["classification"] = classification
        state["triage_reasoning"] = result.get("reasoning", "No reasoning provided")

        # Routing decision based on severity
        if severity_score <= 0.15:
            state["next_agent"] = "close"
            state["should_escalate"] = False
        elif severity_score >= 0.90:
            state["should_escalate"] = True
            state["next_agent"] = "enrichment"  # Still enrich before escalating
        else:
            state["should_escalate"] = False
            state["next_agent"] = "enrichment"

        latency = round(time.time() - start_time, 2)

        # Audit log
        await log_audit(
            alert_id=alert_id,
            agent="triage",
            action="severity_assessed",
            details={
                "severity_score": severity_score,
                "confidence": confidence,
                "classification": classification,
                "next_agent": state["next_agent"],
                "should_escalate": state["should_escalate"],
                "latency_sec": latency,
                "mitre_technique": result.get("mitre_technique"),
                "recommended_actions": result.get("recommended_actions", []),
                "false_positive_indicators": result.get("false_positive_indicators", []),
            },
        )

        logger.info(
            "triage_complete",
            alert_id=alert_id,
            score=severity_score,
            confidence=confidence,
            classification=classification,
            next_agent=state["next_agent"],
            latency_sec=latency,
        )

    except LLMError as e:
        logger.error("triage_llm_error", alert_id=alert_id, error=str(e))
        # Fail safe: score as medium so it gets investigated
        state["triage_score"] = 0.5
        state["confidence"] = 0.3
        state["classification"] = "medium"
        state["triage_reasoning"] = f"LLM error during triage: {e}. Defaulting to medium severity."
        state["next_agent"] = "enrichment"
        state["error"] = str(e)

    except Exception as e:
        logger.error("triage_unexpected_error", alert_id=alert_id, error=str(e))
        state["triage_score"] = 0.5
        state["confidence"] = 0.2
        state["classification"] = "medium"
        state["triage_reasoning"] = f"Unexpected error: {e}. Defaulting to medium severity."
        state["next_agent"] = "enrichment"
        state["error"] = str(e)

    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def format_alert_for_llm(data: Dict[str, Any]) -> str:
    """Flatten alert dict into a readable text block for Claude.

    Filters out None values and formats nested dicts/lists cleanly.
    """
    lines = []
    for key, value in data.items():
        if value is None:
            continue
        if key == "raw_reference":
            continue  # Skip the raw reference to avoid duplication
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for k, v in value.items():
                if v:
                    lines.append(f"  {k}: {v}")
        elif isinstance(value, list):
            if value:  # Skip empty lists
                lines.append(f"{key}: {', '.join(str(v) for v in value)}")
        else:
            lines.append(f"{key}: {value}")

    return "\n".join(lines)


def _clamp(value: float, min_val: float, max_val: float) -> float:
    """Clamp a value between min and max."""
    return max(min_val, min(max_val, value))