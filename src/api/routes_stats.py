"""Statistics Routes — Dashboard KPIs, pipeline metrics, learning stats.

Mounted at /stats in the main app.
"""

from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import func, select, and_

from src.database import get_db
from src.models import Alert

router = APIRouter(prefix="/stats", tags=["statistics"])


@router.get("/overview")
async def get_overview():
    """Dashboard KPI overview from database."""
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

        auto_resolved = (await db.execute(
            select(func.count()).select_from(Alert)
            .where(Alert.status.in_(["responded", "closed"]))
        )).scalar() or 0

    return {
        "total_alerts": total, "alerts_today": today,
        "avg_triage_score": round(avg_score, 3) if avg_score else None,
        "false_positive_rate": fp_rate,
        "severity_distribution": severity_dist,
        "top_sources": [{"source": s[0], "count": s[1]} for s in sources],
        "auto_resolved": auto_resolved,
    }


@router.get("/pipeline")
async def get_pipeline_stats():
    """Real-time pipeline performance metrics."""
    from src.monitoring.metrics import get_metrics
    return get_metrics().to_dict()


@router.get("/learning")
async def get_learning_stats():
    """Learning agent status and learned rules."""
    from src.agents.learning import get_learning_stats
    return get_learning_stats()