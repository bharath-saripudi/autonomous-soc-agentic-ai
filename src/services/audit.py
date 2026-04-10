"""Audit logging service — records every action taken by the system.

Every agent action, routing decision, and response execution gets
logged to the audit_log table for compliance and debugging.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import structlog
from sqlalchemy import insert

from src.database import get_db
from src.models import AuditLog

logger = structlog.get_logger()


async def log_audit(
    alert_id: str,
    agent: str,
    action: str,
    details: Optional[Dict[str, Any]] = None,
) -> str:
    """Write an audit log entry to PostgreSQL.

    Args:
        alert_id: UUID of the alert being processed
        agent: Name of the agent (triage, enrichment, hunting, response, learning, orchestrator)
        action: What was done (e.g., "severity_assessed", "ip_blocked", "alert_closed")
        details: Additional context as JSON

    Returns:
        UUID of the audit log entry
    """
    log_id = str(uuid.uuid4())

    try:
        async with get_db() as db:
            stmt = insert(AuditLog).values(
                id=log_id,
                alert_id=alert_id,
                agent=agent,
                action=action,
                details=details or {},
                timestamp=datetime.utcnow(),
            )
            await db.execute(stmt)

        logger.info(
            "audit_logged",
            log_id=log_id,
            alert_id=alert_id,
            agent=agent,
            action=action,
        )
    except Exception as e:
        # Audit logging should never crash the pipeline
        logger.error(
            "audit_log_error",
            alert_id=alert_id,
            agent=agent,
            action=action,
            error=str(e),
        )

    return log_id