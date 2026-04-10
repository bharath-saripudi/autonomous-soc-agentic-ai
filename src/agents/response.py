"""Response Agent — Automated protective actions with safety controls.

Fourth agent in the pipeline (after Hunting). Executes automated
response actions based on severity, confidence, and enrichment results:
  - Block malicious IPs at the firewall
  - Isolate compromised hosts from the network
  - Kill malicious processes on infected systems
  - Send notifications to the security team

Safety gates prevent:
  - Actions on protected/critical assets (DC, DNS, core router)
  - Actions when AI confidence is below threshold
  - Destructive actions without high severity confirmation

Reads:  triage_score, confidence, enrichment_results, similar_cases, normalized
Writes: actions_taken, response_status, next_agent
"""

import time
from typing import Any, Dict, List

import structlog

from src.state import AgentState
from src.services.audit import log_audit

logger = structlog.get_logger()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Safety Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Critical systems that must NEVER be auto-blocked or isolated
PROTECTED_ASSETS = {
    # IPs
    "10.0.0.1",             # Core router
    "10.0.0.2",             # Primary DNS
    "10.0.0.3",             # Secondary DNS
    "10.0.0.10",            # Domain controller
    "10.0.0.11",            # Backup domain controller
    "10.0.0.50",            # SIEM server
    # Hostnames
    "dc-01",
    "dc-02",
    "dns-01",
    "dns-02",
    "svr-dc-01",
    "core-router",
    "siem-01",
}

# Minimum confidence required for each action type
CONFIDENCE_THRESHOLDS = {
    "block_ip": 0.75,
    "isolate_host": 0.85,
    "kill_process": 0.80,
    "disable_account": 0.85,
    "notify": 0.0,          # Always allowed
}

# Minimum severity score for each action type
SEVERITY_THRESHOLDS = {
    "block_ip": 0.60,
    "isolate_host": 0.85,
    "kill_process": 0.70,
    "disable_account": 0.80,
    "notify": 0.30,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Response Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def response_agent(state: AgentState) -> AgentState:
    """Execute automated response actions with safety controls.

    Reads:  triage_score, confidence, enrichment_results, normalized
    Writes: actions_taken, response_status, next_agent
    """
    start_time = time.time()
    alert_id = state["alert_id"]
    score = state.get("triage_score", 0)
    confidence = state.get("confidence", 0)

    logger.info("response_started", alert_id=alert_id, score=score, confidence=confidence)

    actions_taken = []

    try:
        # ── Notification (medium+) ───────────────────────────────
        if score >= SEVERITY_THRESHOLDS["notify"]:
            action = await _notify_team(state)
            actions_taken.append(action)

        # ── Block malicious IPs (high+) ──────────────────────────
        if score >= SEVERITY_THRESHOLDS["block_ip"]:
            enrichment = state.get("enrichment_results") or {}
            ip_results = enrichment.get("ips", {})

            for ip, ip_data in ip_results.items():
                abuse = ip_data.get("abuse_score") if isinstance(ip_data, dict) else None
                if abuse is not None and abuse >= 50:
                    action = await _safe_execute(
                        action_type="block_ip",
                        target=ip,
                        confidence=confidence,
                        alert_id=alert_id,
                        reason=f"Abuse score: {ip_data.get('abuse_score')}",
                    )
                    actions_taken.append(action)

        # ── Isolate compromised host (critical) ──────────────────
        if score >= SEVERITY_THRESHOLDS["isolate_host"]:
            normalized = state.get("normalized") or {}
            hostname = normalized.get("hostname") or state.get("raw_data", {}).get("hostname")

            if hostname:
                action = await _safe_execute(
                    action_type="isolate_host",
                    target=hostname,
                    confidence=confidence,
                    alert_id=alert_id,
                    reason=f"Critical severity: {score}",
                )
                actions_taken.append(action)

        # ── Kill malicious process (high+) ───────────────────────
        if score >= SEVERITY_THRESHOLDS["kill_process"]:
            normalized = state.get("normalized") or {}
            raw = state.get("raw_data") or {}
            process = normalized.get("process") or raw.get("process")
            hostname = normalized.get("hostname") or raw.get("hostname")
            pid = normalized.get("pid") or raw.get("pid")

            if process and hostname:
                action = await _safe_execute(
                    action_type="kill_process",
                    target=f"{process} (PID: {pid}) on {hostname}",
                    confidence=confidence,
                    alert_id=alert_id,
                    reason=f"Suspicious process: {process}",
                )
                actions_taken.append(action)

        # ── Determine overall response status ────────────────────
        executed_actions = [a for a in actions_taken if a.get("status") == "executed"]
        blocked_actions = [a for a in actions_taken if a.get("status") == "blocked"]
        skipped_actions = [a for a in actions_taken if a.get("status") == "skipped"]

        if executed_actions:
            state["response_status"] = "responded"
        elif state.get("should_escalate"):
            state["response_status"] = "escalated"
        elif score <= 0.15:
            state["response_status"] = "closed"
        else:
            state["response_status"] = "monitored"

        state["actions_taken"] = actions_taken
        state["next_agent"] = "learning"

        latency = round(time.time() - start_time, 2)

        # Audit log
        await log_audit(
            alert_id=alert_id,
            agent="response",
            action="response_complete",
            details={
                "total_actions": len(actions_taken),
                "executed": len(executed_actions),
                "blocked": len(blocked_actions),
                "skipped": len(skipped_actions),
                "response_status": state["response_status"],
                "latency_sec": latency,
            },
        )

        logger.info(
            "response_complete",
            alert_id=alert_id,
            total_actions=len(actions_taken),
            executed=len(executed_actions),
            blocked=len(blocked_actions),
            status=state["response_status"],
            latency_sec=latency,
        )

    except Exception as e:
        logger.error("response_error", alert_id=alert_id, error=str(e))
        state["actions_taken"] = actions_taken
        state["response_status"] = "error"
        state["next_agent"] = "learning"
        state["error"] = f"Response error: {e}"

    return state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Safety Gate Execution
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _safe_execute(
    action_type: str,
    target: str,
    confidence: float,
    alert_id: str,
    reason: str = "",
) -> Dict[str, Any]:
    """Safety gate: check thresholds and protected assets before acting.

    Gate 1: Confidence must meet minimum for action type
    Gate 2: Target must not be a protected asset
    Gate 3: Execute (simulated in prototype)
    """
    action_record = {
        "action": action_type,
        "target": target,
        "reason": reason,
        "confidence": confidence,
        "timestamp": time.time(),
    }

    # Gate 1: Confidence check
    min_confidence = CONFIDENCE_THRESHOLDS.get(action_type, 1.0)
    if confidence < min_confidence:
        action_record["status"] = "skipped"
        action_record["gate_failed"] = "confidence"
        action_record["detail"] = f"Confidence {confidence} < required {min_confidence}"
        logger.warning(
            "response_skipped_confidence",
            alert_id=alert_id,
            action=action_type,
            target=target,
            confidence=confidence,
            required=min_confidence,
        )
        return action_record

    # Gate 2: Protected asset check
    target_lower = target.lower()
    if target_lower in PROTECTED_ASSETS or any(
        protected in target_lower for protected in PROTECTED_ASSETS
    ):
        action_record["status"] = "blocked"
        action_record["gate_failed"] = "protected_asset"
        action_record["detail"] = f"Target '{target}' is a protected asset"
        logger.warning(
            "response_blocked_protected",
            alert_id=alert_id,
            action=action_type,
            target=target,
        )
        return action_record

    # Gate 3: Execute action (simulated in prototype)
    result = await _execute_action(action_type, target, alert_id)
    action_record["status"] = "executed"
    action_record["result"] = result

    await log_audit(
        alert_id=alert_id,
        agent="response",
        action=f"executed_{action_type}",
        details={"target": target, "reason": reason, "result": result},
    )

    logger.info(
        "response_executed",
        alert_id=alert_id,
        action=action_type,
        target=target,
    )
    return action_record


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Action Executors (Stubs for Prototype)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _execute_action(action_type: str, target: str, alert_id: str) -> Dict[str, Any]:
    """Execute the actual action. Simulated in prototype.

    In production, these would call real APIs:
      block_ip       → Firewall API (PaloAlto, Fortinet, pfSense)
      isolate_host   → EDR API (CrowdStrike, SentinelOne, Carbon Black)
      kill_process   → EDR API remote kill
      disable_account → Active Directory / IAM API
    """
    executors = {
        "block_ip": _stub_block_ip,
        "isolate_host": _stub_isolate_host,
        "kill_process": _stub_kill_process,
        "disable_account": _stub_disable_account,
    }

    executor = executors.get(action_type)
    if executor:
        return await executor(target, alert_id)

    return {"success": False, "error": f"Unknown action type: {action_type}"}


async def _stub_block_ip(target: str, alert_id: str) -> Dict[str, Any]:
    """Simulate blocking an IP at the firewall."""
    logger.info("stub_block_ip", ip=target, alert_id=alert_id)
    return {"success": True, "simulated": True, "firewall_rule_id": f"RULE-{alert_id[:8]}"}


async def _stub_isolate_host(target: str, alert_id: str) -> Dict[str, Any]:
    """Simulate isolating a host via EDR."""
    logger.info("stub_isolate_host", host=target, alert_id=alert_id)
    return {"success": True, "simulated": True, "isolation_id": f"ISO-{alert_id[:8]}"}


async def _stub_kill_process(target: str, alert_id: str) -> Dict[str, Any]:
    """Simulate killing a malicious process."""
    logger.info("stub_kill_process", process=target, alert_id=alert_id)
    return {"success": True, "simulated": True, "killed": True}


async def _stub_disable_account(target: str, alert_id: str) -> Dict[str, Any]:
    """Simulate disabling a user account."""
    logger.info("stub_disable_account", account=target, alert_id=alert_id)
    return {"success": True, "simulated": True, "account_disabled": True}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Notification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _notify_team(state: AgentState) -> Dict[str, Any]:
    """Send alert notification to the security team.

    In production: Slack webhook, email, PagerDuty, etc.
    """
    alert_id = state["alert_id"]
    score = state.get("triage_score", 0)
    classification = state.get("classification", "unknown")
    description = (state.get("normalized") or {}).get("description", "No description")

    # Determine urgency
    if score >= 0.90:
        urgency = "CRITICAL"
    elif score >= 0.70:
        urgency = "HIGH"
    elif score >= 0.40:
        urgency = "MEDIUM"
    else:
        urgency = "LOW"

    logger.info(
        "notification_sent",
        alert_id=alert_id,
        urgency=urgency,
        classification=classification,
        description=description[:100],
    )

    return {
        "action": "notify",
        "status": "executed",
        "urgency": urgency,
        "channel": "slack+email",
        "simulated": True,
    }