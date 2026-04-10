"""Alert CRUD Routes — List, get, update, delete alerts.

Mounted at /alerts in the main app.
"""

import uuid
from datetime import datetime
from typing import Optional

import structlog
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from sqlalchemy import func, select, and_

from src.database import get_db
from src.models import Alert, AlertInput, AlertListResponse, AlertResponse, AlertStatus, AuditLog
from src.ingestion.normalizer import AlertNormalizer
from src.services.audit import log_audit

logger = structlog.get_logger()
normalizer = AlertNormalizer()

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", status_code=202)
async def create_alert(alert_input: AlertInput, background_tasks: BackgroundTasks):
    """Ingest a new alert and trigger the full AI pipeline."""
    alert_id = str(uuid.uuid4())
    normalized = normalizer.normalize(alert_input.source, alert_input.data)

    async with get_db() as db:
        new_alert = Alert(
            id=alert_id, source=alert_input.source,
            raw_data=alert_input.data, normalized=normalized,
            status=AlertStatus.NEW.value, created_at=datetime.utcnow(),
        )
        db.add(new_alert)

    await log_audit(alert_id=alert_id, agent="ingestion", action="alert_received",
                    details={"source": alert_input.source})

    from src.api.main import process_alert_background, metrics
    metrics.record_ingestion()
    background_tasks.add_task(process_alert_background, alert_id, alert_input.source, alert_input.data)

    return {"alert_id": alert_id, "status": "accepted", "message": "Alert received — AI pipeline started"}


@router.get("")
async def list_alerts(
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None, ge=0.0, le=1.0),
    max_score: Optional[float] = Query(None, ge=0.0, le=1.0),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    """List alerts with filtering and pagination."""
    async with get_db() as db:
        query = select(Alert).order_by(Alert.created_at.desc())
        conditions = []
        if status:
            conditions.append(Alert.status == status)
        if source:
            conditions.append(Alert.source == source)
        if min_score is not None:
            conditions.append(Alert.triage_score >= min_score)
        if max_score is not None:
            conditions.append(Alert.triage_score <= max_score)
        if conditions:
            query = query.where(and_(*conditions))

        count_q = select(func.count()).select_from(Alert)
        if conditions:
            count_q = count_q.where(and_(*conditions))
        total = (await db.execute(count_q)).scalar() or 0

        offset = (page - 1) * per_page
        result = await db.execute(query.offset(offset).limit(per_page))
        alerts = result.scalars().all()

    return AlertListResponse(
        total=total, page=page, per_page=per_page,
        alerts=[_to_response(a) for a in alerts],
    )


@router.get("/{alert_id}")
async def get_alert(alert_id: str):
    """Get full alert details + audit trail."""
    async with get_db() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.alert_id == alert_id).order_by(AuditLog.timestamp.asc())
        )
        audit_logs = audit_result.scalars().all()

    return {
        "alert": _to_response(alert),
        "raw_data": alert.raw_data,
        "normalized": alert.normalized,
        "audit_trail": [
            {"agent": l.agent, "action": l.action, "details": l.details,
             "timestamp": l.timestamp.isoformat()}
            for l in audit_logs
        ],
    }


@router.delete("/{alert_id}")
async def delete_alert(alert_id: str):
    """Delete an alert by ID."""
    async with get_db() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        await db.delete(alert)

    return {"status": "deleted", "alert_id": alert_id}


def _to_response(a: Alert) -> AlertResponse:
    return AlertResponse(
        id=str(a.id), source=a.source,
        status=a.status if isinstance(a.status, str) else a.status.value,
        triage_score=a.triage_score, triage_reasoning=a.triage_reasoning,
        confidence=a.confidence, is_false_positive=a.is_false_positive or False,
        enrichment_results=a.enrichment_results, similar_cases=a.similar_cases,
        actions_taken=a.actions_taken, created_at=a.created_at, closed_at=a.closed_at,
    )
