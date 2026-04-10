"""FastAPI application — the main entry point for the Autonomous SOC.

Endpoints:
  POST /alerts              → Ingest + trigger full AI pipeline
  GET  /alerts              → List alerts with filtering
  GET  /alerts/{id}         → Alert details + audit trail
  POST /feedback            → Analyst corrections (RLHF)
  GET  /stats/overview      → Dashboard KPIs
  GET  /stats/learning      → Learning agent stats
  GET  /stats/pipeline      → Pipeline performance metrics
  WS   /ws/alerts           → Real-time alert stream
  GET  /health              → Health check
  GET  /metrics             → Prometheus metrics
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import structlog
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select, and_

from src.config import get_settings
from src.database import get_db, init_db, close_db
from src.models import (
    Alert, AlertInput, AlertListResponse, AlertResponse,
    AlertStatus, AuditLog, FeedbackInput, FeedbackQueue,
)
from src.ingestion.normalizer import AlertNormalizer
from src.services.audit import log_audit

logger = structlog.get_logger()
settings = get_settings()
normalizer = AlertNormalizer()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WebSocket Manager
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        disconnected = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            if ws in self.active:
                self.active.remove(ws)


ws_manager = ConnectionManager()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Pipeline Metrics
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from src.monitoring.metrics import PipelineMetrics, get_metrics

metrics = get_metrics()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Background Pipeline Executor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def process_alert_background(alert_id: str, source: str, raw_data: dict):
    """Run the full multi-agent pipeline in the background.

    Called by POST /alerts after the alert is saved to DB.
    Results are persisted by the orchestrator's save_final_state().
    """
    import time
    start = time.time()

    try:
        from src.agents.orchestrator import run_workflow

        final_state = await run_workflow(alert_id, source, raw_data)

        elapsed = round(time.time() - start, 2)
        metrics.record_completion(final_state, elapsed)

        # Push result to WebSocket
        await ws_manager.broadcast({
            "event": "alert_processed",
            "alert_id": alert_id,
            "triage_score": final_state.get("triage_score"),
            "classification": final_state.get("classification"),
            "response_status": final_state.get("response_status"),
            "actions_count": len(final_state.get("actions_taken") or []),
            "processing_time_sec": elapsed,
        })

        logger.info("pipeline_complete", alert_id=alert_id, elapsed=elapsed,
                    status=final_state.get("response_status"))

    except Exception as e:
        metrics.record_failure()
        logger.error("pipeline_failed", alert_id=alert_id, error=str(e))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  App Lifecycle
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("soc_api_starting")
    await init_db()
    logger.info("database_initialized")

    # Initialize target monitor with alert callback
    from src.monitoring.target_monitor import get_monitor
    monitor = get_monitor()
    monitor.alert_callback = _monitor_alert_callback
    logger.info("target_monitor_initialized")

    yield
    await close_db()
    logger.info("soc_api_stopped")


async def _monitor_alert_callback(alert_data: dict):
    """Called by TargetMonitor when an attack is detected. Sends through full pipeline."""
    import uuid
    alert_id = str(uuid.uuid4())
    source = alert_data.get("source", "target_monitor")
    raw_data = alert_data.get("data", alert_data)

    normalized = normalizer.normalize(source, raw_data)

    async with get_db() as db:
        new_alert = Alert(
            id=alert_id, source=source,
            raw_data=raw_data, normalized=normalized,
            status=AlertStatus.NEW.value, created_at=datetime.utcnow(),
        )
        db.add(new_alert)

    metrics.record_ingestion()

    # Process through full AI pipeline in background
    asyncio.create_task(process_alert_background(alert_id, source, raw_data))

    logger.info("monitor_alert_ingested", alert_id=alert_id,
                event_type=raw_data.get("event_type", "unknown"))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FastAPI App
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

app = FastAPI(
    title="Autonomous SOC API",
    description="Multi-Agent AI Security Operations Center",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Chrome Private Network Access — allows external sites to reach localhost
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class PrivateNetworkMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            response = Response(status_code=200)
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "*"
            response.headers["Access-Control-Allow-Private-Network"] = "true"
            return response
        response = await call_next(request)
        response.headers["Access-Control-Allow-Private-Network"] = "true"
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

app.add_middleware(PrivateNetworkMiddleware)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Alert Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.delete("/alerts/clear", tags=["alerts"])
async def clear_all_alerts():
    """Delete ALL alerts and audit logs. Use for demo reset."""
    async with get_db() as db:
        await db.execute(AuditLog.__table__.delete())
        await db.execute(Alert.__table__.delete())
    logger.info("all_alerts_cleared")
    return {"status": "cleared", "message": "All alerts and audit logs deleted"}


@app.post("/alerts", status_code=202, tags=["alerts"])
async def ingest_alert(alert_input: AlertInput, background_tasks: BackgroundTasks):
    """Ingest a new alert and trigger the full AI pipeline."""
    alert_id = str(uuid.uuid4())

    normalized = normalizer.normalize(alert_input.source, alert_input.data)

    # Save to database
    async with get_db() as db:
        new_alert = Alert(
            id=alert_id,
            source=alert_input.source,
            raw_data=alert_input.data,
            normalized=normalized,
            status=AlertStatus.NEW.value,
            created_at=datetime.utcnow(),
        )
        db.add(new_alert)

    await log_audit(
        alert_id=alert_id,
        agent="ingestion",
        action="alert_received",
        details={"source": alert_input.source},
    )

    metrics.record_ingestion()

    # Push new alert to WebSocket
    await ws_manager.broadcast({
        "event": "new_alert",
        "alert_id": alert_id,
        "source": alert_input.source,
        "description": normalized.get("description", "")[:200],
        "timestamp": datetime.utcnow().isoformat(),
    })

    # Trigger the full multi-agent pipeline in the background
    background_tasks.add_task(
        process_alert_background,
        alert_id,
        alert_input.source,
        alert_input.data,
    )

    logger.info("alert_ingested", alert_id=alert_id, source=alert_input.source)

    return {
        "alert_id": alert_id,
        "status": "accepted",
        "message": "Alert received — AI pipeline started",
    }


@app.get("/alerts", tags=["alerts"])
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
        alerts=[
            AlertResponse(
                id=str(a.id), source=a.source,
                status=a.status if isinstance(a.status, str) else a.status.value,
                triage_score=a.triage_score, triage_reasoning=a.triage_reasoning,
                confidence=a.confidence, is_false_positive=a.is_false_positive or False,
                enrichment_results=a.enrichment_results, similar_cases=a.similar_cases,
                actions_taken=a.actions_taken, created_at=a.created_at, closed_at=a.closed_at,
            )
            for a in alerts
        ],
    )


@app.get("/alerts/{alert_id}", tags=["alerts"])
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
        "alert": AlertResponse(
            id=str(alert.id), source=alert.source,
            status=alert.status if isinstance(alert.status, str) else alert.status.value,
            triage_score=alert.triage_score, triage_reasoning=alert.triage_reasoning,
            confidence=alert.confidence, is_false_positive=alert.is_false_positive or False,
            enrichment_results=alert.enrichment_results, similar_cases=alert.similar_cases,
            actions_taken=alert.actions_taken, created_at=alert.created_at, closed_at=alert.closed_at,
        ),
        "raw_data": alert.raw_data,
        "normalized": alert.normalized,
        "audit_trail": [
            {"agent": l.agent, "action": l.action, "details": l.details,
             "timestamp": l.timestamp.isoformat()}
            for l in audit_logs
        ],
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Feedback Endpoint (RLHF)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.post("/feedback", tags=["feedback"])
async def submit_feedback(fb: FeedbackInput):
    """Analyst submits correction — feeds into learning agent."""
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

    # Also feed into the in-memory learning buffer
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
        alert_id=fb.alert_id,
        agent="analyst",
        action="feedback_submitted",
        details={"label": fb.label, "correct_severity": fb.correct_severity},
    )

    return {"status": "recorded", "alert_id": fb.alert_id}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Statistics Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/stats/overview", tags=["statistics"])
async def get_stats():
    """Dashboard KPIs from database."""
    async with get_db() as db:
        total = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today = (await db.execute(
            select(func.count()).select_from(Alert).where(Alert.created_at >= today_start)
        )).scalar() or 0
        avg_score = (await db.execute(
            select(func.avg(Alert.triage_score)).where(Alert.triage_score.isnot(None))
        )).scalar()
        fp_count = (await db.execute(
            select(func.count()).select_from(Alert).where(Alert.is_false_positive == True)
        )).scalar() or 0
        fp_rate = round((fp_count / total) * 100, 2) if total > 0 else 0.0

        severity_dist = {}
        for label, low, high in [
            ("critical", 0.90, 1.01), ("high", 0.70, 0.90),
            ("medium", 0.40, 0.70), ("low", 0.16, 0.40), ("info", 0.0, 0.16),
        ]:
            count = (await db.execute(
                select(func.count()).select_from(Alert)
                .where(and_(Alert.triage_score >= low, Alert.triage_score < high))
            )).scalar() or 0
            severity_dist[label] = count

        sources = (await db.execute(
            select(Alert.source, func.count().label("count"))
            .group_by(Alert.source).order_by(func.count().desc()).limit(5)
        )).all()

    return {
        "total_alerts": total,
        "alerts_today": today,
        "avg_triage_score": round(avg_score, 3) if avg_score else None,
        "false_positive_rate": fp_rate,
        "severity_distribution": severity_dist,
        "top_sources": [{"source": s[0], "count": s[1]} for s in sources],
    }


@app.get("/stats/pipeline", tags=["statistics"])
async def get_pipeline_stats():
    """Real-time pipeline performance metrics."""
    return metrics.to_dict()


@app.get("/stats/learning", tags=["statistics"])
async def get_learning_stats():
    """Learning agent status and rules."""
    from src.agents.learning import get_learning_stats
    return get_learning_stats()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Monitoring Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/metrics", tags=["monitoring"])
async def prometheus_metrics():
    """Prometheus-compatible metrics endpoint."""
    return PlainTextResponse(content=metrics.to_prometheus(), media_type="text/plain")


@app.get("/health", tags=["monitoring"])
async def health_check():
    """System health check."""
    health = {"status": "healthy", "services": {}, "version": "1.0.0"}

    # Check database
    try:
        async with get_db() as db:
            await db.execute(select(func.count()).select_from(Alert))
        health["services"]["database"] = "connected"
    except Exception as e:
        health["services"]["database"] = f"error: {e}"
        health["status"] = "degraded"

    # Check Redis
    try:
        from src.services.cache import get_cache
        cache = get_cache()
        if await cache.health_check():
            health["services"]["redis"] = "connected"
        else:
            health["services"]["redis"] = "unavailable"
            health["status"] = "degraded"
    except Exception as e:
        health["services"]["redis"] = f"error: {e}"
        health["status"] = "degraded"

    # Check LLM
    try:
        from src.services.llm_client import get_llm
        llm = get_llm()
        health["services"]["llm"] = {"model": llm.model, "calls": llm.stats["total_calls"]}
    except Exception as e:
        health["services"]["llm"] = f"error: {e}"

    # Pipeline metrics
    health["pipeline"] = {
        "alerts_processed": metrics.alerts_processed,
        "avg_processing_time": metrics.avg_processing_time,
    }

    return health


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WebSocket
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Dashboard (serves dashboard/index.html)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Remediation & Playback Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/alerts/{alert_id}/remediation", tags=["alerts"])
async def get_alert_remediation(alert_id: str):
    """Get remediation suggestions for a specific alert."""
    from src.services.remediation import get_remediation_for_alert
    async with get_db() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

    return get_remediation_for_alert({
        "raw_data": alert.raw_data or {},
        "normalized": alert.normalized or {},
    })


@app.get("/alerts/{alert_id}/playback", tags=["alerts"])
async def get_alert_playback(alert_id: str):
    """Get full attack playback timeline for an alert — step by step."""
    async with get_db() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        audit_result = await db.execute(
            select(AuditLog).where(AuditLog.alert_id == alert_id)
            .order_by(AuditLog.timestamp.asc())
        )
        audit_logs = audit_result.scalars().all()

    raw = alert.raw_data or {}
    normalized = alert.normalized or {}
    steps = []

    # Step 1: Alert received
    steps.append({
        "step": 1, "phase": "INGESTION",
        "title": "Alert Received",
        "description": f"Alert from source '{alert.source}' ingested into the pipeline",
        "details": {"source": alert.source, "event_type": raw.get("event_type", "unknown")},
        "icon": "📥", "color": "#5b8def",
    })

    # Step 2: Normalization
    steps.append({
        "step": 2, "phase": "NORMALIZATION",
        "title": "Data Normalized",
        "description": f"Raw data parsed and normalized. Event: {normalized.get('event_type', 'unknown')}",
        "details": {k: v for k, v in normalized.items() if v and k != 'raw_reference' and k != 'indicators'},
        "icon": "🔄", "color": "#5b8def",
    })

    # Step 3: Triage
    sev = alert.triage_score or 0
    steps.append({
        "step": 3, "phase": "TRIAGE",
        "title": f"AI Triage: {int(sev*100)}% Threat Score",
        "description": alert.triage_reasoning or "Claude analyzed the alert using ReAct methodology",
        "details": {
            "score": sev, "confidence": alert.confidence,
            "classification": "critical" if sev >= 0.9 else "high" if sev >= 0.7 else "medium" if sev >= 0.4 else "low",
        },
        "icon": "🧠", "color": "#ff3b5c" if sev >= 0.9 else "#ff8b3e" if sev >= 0.7 else "#ffd43e",
    })

    # Step 4: Enrichment
    enrichment = alert.enrichment_results or {}
    ioc_count = sum(len(v) for v in enrichment.values() if isinstance(v, dict))
    steps.append({
        "step": 4, "phase": "ENRICHMENT",
        "title": f"IOC Enrichment ({ioc_count} indicators checked)",
        "description": "Checked indicators against VirusTotal and AbuseIPDB threat intelligence",
        "details": enrichment.get("summary", {}),
        "icon": "🔍", "color": "#ffd43e",
    })

    # Step 5: Hunting
    similar = alert.similar_cases or []
    steps.append({
        "step": 5, "phase": "HUNTING",
        "title": f"Threat Hunting ({len(similar)} similar cases)",
        "description": "Searched vector database for similar historical incidents",
        "details": {"similar_found": len(similar)},
        "icon": "🎯", "color": "#3edfcf",
    })

    # Step 6: Response
    actions = alert.actions_taken or []
    executed = [a for a in actions if a.get("status") == "executed"]
    steps.append({
        "step": 6, "phase": "RESPONSE",
        "title": f"Automated Response ({len(executed)} actions)",
        "description": "Executed automated containment actions based on severity and confidence",
        "details": {"actions": [{"action": a.get("action"), "target": a.get("target"), "status": a.get("status")} for a in actions]},
        "icon": "⚡", "color": "#ff3b5c" if executed else "#666680",
    })

    # Step 7: Learning
    steps.append({
        "step": 7, "phase": "LEARNING",
        "title": "Learning & Storage",
        "description": "Alert stored for future pattern matching. Feedback loop active.",
        "details": {"status": alert.status},
        "icon": "📚", "color": "#3edfcf",
    })

    return {
        "alert_id": alert_id,
        "total_steps": len(steps),
        "steps": steps,
        "audit_trail": [
            {"agent": l.agent, "action": l.action, "timestamp": l.timestamp.isoformat()}
            for l in audit_logs
        ],
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Target Monitor Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from pydantic import BaseModel as PydanticModel

class TargetInput(PydanticModel):
    url: str
    name: str = ""

class TrafficInput(PydanticModel):
    target: str
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    body: str = ""
    source_ip: str = "unknown"
    user_agent: str = ""
    status_code: int = 200


@app.post("/targets", tags=["targets"])
async def add_target(target_input: TargetInput):
    """Add a website/IP to monitor for attacks."""
    from src.monitoring.target_monitor import get_monitor
    monitor = get_monitor()
    target = monitor.add_target(target_input.url, target_input.name)

    # Run initial active scan in background
    asyncio.create_task(monitor.run_active_scan(target))

    return {"status": "added", "target": target.to_dict()}


@app.get("/targets", tags=["targets"])
async def list_targets():
    """List all monitored targets with stats."""
    from src.monitoring.target_monitor import get_monitor
    return {"targets": get_monitor().get_all_targets()}


@app.get("/targets/{hostname}", tags=["targets"])
async def get_target(hostname: str):
    """Get detailed stats for a specific monitored target."""
    from src.monitoring.target_monitor import get_monitor
    target = get_monitor().get_target(hostname)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Also get alerts from DB for this target
    async with get_db() as db:
        result = await db.execute(
            select(Alert)
            .where(Alert.source == "target_monitor")
            .order_by(Alert.created_at.desc())
            .limit(50)
        )
        alerts = result.scalars().all()
        # Filter alerts that match this target
        target_alerts = []
        for a in alerts:
            raw = a.raw_data or {}
            if raw.get("target") == hostname or hostname in str(raw):
                target_alerts.append({
                    "id": str(a.id), "event_type": raw.get("event_type"),
                    "severity": raw.get("severity"),
                    "message": raw.get("message", ""),
                    "triage_score": a.triage_score,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                })

    target["alerts"] = target_alerts
    return target


@app.delete("/targets/{hostname}", tags=["targets"])
async def remove_target(hostname: str):
    """Stop monitoring a target."""
    from src.monitoring.target_monitor import get_monitor
    get_monitor().remove_target(hostname)
    return {"status": "removed", "hostname": hostname}


@app.post("/targets/analyze", tags=["targets"])
async def analyze_traffic(traffic: TrafficInput):
    """Analyze an HTTP request for attack patterns. Use this to feed
    traffic data from a reverse proxy, WAF, or access logs.

    Send each request through this endpoint and it will auto-detect
    SQLi, XSS, path traversal, command injection, etc.
    """
    from src.monitoring.target_monitor import get_monitor
    monitor = get_monitor()

    # Auto-add target if not already monitored
    if traffic.target not in monitor.targets:
        monitor.add_target(traffic.target)

    attacks = await monitor.analyze_request(
        target_hostname=traffic.target,
        method=traffic.method,
        path=traffic.path,
        query_string=traffic.query_string,
        body=traffic.body,
        source_ip=traffic.source_ip,
        user_agent=traffic.user_agent,
        status_code=traffic.status_code,
    )

    return {
        "attacks_detected": len(attacks),
        "attacks": attacks,
        "target": traffic.target,
    }


@app.post("/targets/{hostname}/scan", tags=["targets"])
async def scan_target(hostname: str, background_tasks: BackgroundTasks):
    """Trigger an active vulnerability scan against a monitored target."""
    from src.monitoring.target_monitor import get_monitor
    monitor = get_monitor()
    target = monitor.targets.get(hostname)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found. Add it first via POST /targets")

    background_tasks.add_task(monitor.run_active_scan, target)
    return {"status": "scan_started", "target": hostname}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ML Endpoints
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_ml_classifier = None

def _get_ml_classifier():
    global _ml_classifier
    if _ml_classifier is None:
        try:
            from src.ml.threat_classifier import ThreatClassifier
            _ml_classifier = ThreatClassifier.load()
        except Exception:
            return None
    return _ml_classifier


@app.post("/ml/predict", tags=["ml"])
async def ml_predict(alert_input: AlertInput):
    """Score an alert using the ML classifier (no Claude API call)."""
    clf = _get_ml_classifier()
    if not clf:
        return {"error": "ML model not trained. Run: python scripts/train_ml.py"}
    normalized = normalizer.normalize(alert_input.source, alert_input.data)
    score, label = clf.predict(normalized, alert_input.data)
    return {"ml_score": score, "ml_label": label, "model": "ensemble_rf_gb"}


@app.get("/ml/stats", tags=["ml"])
async def ml_stats():
    """Get ML model stats and feature importances."""
    clf = _get_ml_classifier()
    if not clf:
        return {"trained": False, "error": "No model loaded"}
    return {
        "trained": True,
        "training_stats": clf.training_stats,
        "top_features": clf.get_feature_importance(),
    }


@app.get("/ml/compare", tags=["ml"])
async def ml_compare():
    """Compare ML vs Claude scores for all alerts in DB."""
    clf = _get_ml_classifier()
    if not clf:
        return {"error": "ML model not trained"}

    async with get_db() as db:
        result = await db.execute(
            select(Alert).where(Alert.triage_score.isnot(None)).limit(100)
        )
        alerts = result.scalars().all()

    comparisons = []
    matches = 0
    for alert in alerts:
        try:
            normalized = alert.normalized or {}
            raw_data = alert.raw_data or {}
            ml_score, ml_label = clf.predict(normalized, raw_data)
            claude_score = alert.triage_score or 0.5
            claude_label = clf._score_to_label(claude_score)
            match = claude_label == ml_label
            if match:
                matches += 1
            comparisons.append({
                "alert_id": str(alert.id),
                "claude_score": claude_score,
                "ml_score": ml_score,
                "claude_label": claude_label,
                "ml_label": ml_label,
                "agreement": match,
            })
        except Exception:
            continue

    return {
        "total": len(comparisons),
        "agreement_rate": round(matches / len(comparisons) * 100, 1) if comparisons else 0,
        "comparisons": comparisons,
    }


@app.get("/dashboard", tags=["dashboard"])
async def serve_dashboard():
    """Serve the SOC dashboard."""
    import os
    # Try multiple possible locations
    candidates = [
        os.path.join(os.getcwd(), "dashboard", "index.html"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "dashboard", "index.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return FileResponse(path, media_type="text/html")
    return {"error": "Dashboard not found", "tried": candidates}


@app.get("/inject.js", tags=["targets"])
async def serve_inject_script():
    """Serve the browser traffic monitoring script.

    Usage: Open target site → F12 Console → paste:
      fetch("http://localhost:8000/inject.js").then(r=>r.text()).then(eval)
    """
    script = """
(function() {
  const SOC = 'http://localhost:8000';
  const T = window.location.hostname;
  let n = 0;

  fetch(SOC + '/targets', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: window.location.origin, name: T})
  }).catch(() => {});

  function send(method, path, qs, body) {
    n++;
    fetch(SOC + '/targets/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target:T, method:method, path:path, query_string:qs||'', body:body||'', source_ip:'browser', user_agent:navigator.userAgent})
    }).then(r => r.json()).then(d => {
      if (d.attacks_detected > 0) console.log('%c[SOC] ATTACK: ' + d.attacks.map(a=>a.data.event_type).join(', '), 'color:red;font-weight:bold');
      else console.log('[SOC] OK:', method, path, '(#' + n + ')');
    }).catch(() => {});
  }

  document.addEventListener('click', function(e) {
    const a = e.target.closest('a[href]');
    if (a) { try { const u = new URL(a.href); send('GET', u.pathname, u.search.slice(1), ''); } catch(x){} }
  }, true);

  document.addEventListener('submit', function(e) {
    if (e.target.tagName === 'FORM') {
      const f = e.target, fd = new URLSearchParams(new FormData(f)).toString();
      try { const u = new URL(f.action||location.href); send(f.method||'POST', u.pathname, u.search.slice(1), fd); } catch(x){}
    }
  }, true);

  const _f = window.fetch;
  window.fetch = function(i, o) {
    try { const u = new URL(i, location.origin); send((o&&o.method)||'GET', u.pathname, u.search.slice(1), (o&&typeof o.body==='string')?o.body:''); } catch(x){}
    return _f.apply(this, arguments);
  };

  const _o = XMLHttpRequest.prototype.open, _s = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(m, u) { this._m=m; this._u=u; return _o.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function(b) {
    try { const u = new URL(this._u, location.origin); send(this._m, u.pathname, u.search.slice(1), b||''); } catch(x){}
    return _s.apply(this, arguments);
  };

  const _ps = history.pushState;
  history.pushState = function() { _ps.apply(this,arguments); const u=new URL(location.href); send('GET',u.pathname,u.search.slice(1),''); };

  window.addEventListener('hashchange', () => { const u=new URL(location.href); send('GET',u.pathname,u.search.slice(1),''); });

  send('GET', location.pathname, location.search.slice(1), '');
  console.log('%c[SOC] Traffic monitor active for: ' + T, 'color:#3edfcf;font-weight:bold;font-size:14px');
  console.log('[SOC] Try: ' + location.origin + "/search.php?test=<script>alert(1)<\\/script>");
})();
""".strip()
    return PlainTextResponse(script, media_type="application/javascript")