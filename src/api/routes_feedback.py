"""Feedback Routes — Analyst correction interface (RLHF).

Allows SOC analysts to submit corrections to AI triage decisions,
which feed into the Learning Agent for continuous improvement.
"""

import structlog
from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from src.database import get_db
from src.models import Alert, FeedbackInput, FeedbackQueue
from src.services.audit import log_audit

logger = structlog.get_logger()

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post("")
async def submit_feedback(fb: FeedbackInput):
    """Analyst submits correction — feeds into the learning agent RLHF loop."""
    async with get_db() as db:
        result = await db.execute(select(Alert).where(Alert.id == fb.alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.analyst_feedback = fb.notes
        alert.feedback_label = fb.label
        if fb.label == "false_positive":
            alert.is_false_positive = True

        feedback_entry = FeedbackQueue(
            alert_id=fb.alert_id, label=fb.label,
            correct_severity=fb.correct_severity, notes=fb.notes,
        )
        db.add(feedback_entry)

    # Feed into in-memory learning buffer
    from src.agents.learning import add_feedback
    add_feedback({
        "alert_id": fb.alert_id,
        "label": fb.label,
        "correct_severity": fb.correct_severity,
        "ai_score": alert.triage_score,
        "ai_classification": alert.status,
        "notes": fb.notes,
        "summary": (alert.normalized or {}).get("description", ""),
    })

    await log_audit(
        alert_id=fb.alert_id, agent="analyst", action="feedback_submitted",
        details={"label": fb.label, "correct_severity": fb.correct_severity},
    )

    logger.info("feedback_submitted", alert_id=fb.alert_id, label=fb.label)
    return {"status": "recorded", "alert_id": fb.alert_id}


@router.get("/pending")
async def list_pending_feedback():
    """List alerts awaiting analyst review (no feedback yet)."""
    async with get_db() as db:
        result = await db.execute(
            select(Alert)
            .where(Alert.feedback_label.is_(None))
            .where(Alert.triage_score.isnot(None))
            .order_by(Alert.triage_score.desc())
            .limit(20)
        )
        alerts = result.scalars().all()

    return {
        "pending_count": len(alerts),
        "alerts": [
            {
                "id": str(a.id), "source": a.source, "triage_score": a.triage_score,
                "status": a.status, "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }
