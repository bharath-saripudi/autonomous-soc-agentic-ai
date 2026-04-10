"""Health Check Module — Service connectivity verification.

Checks: Database, Redis, Qdrant, LLM client availability.
Returns structured health status for monitoring systems.
"""

from typing import Any, Dict

import structlog
from fastapi import APIRouter
from sqlalchemy import func, select

from src.database import get_db
from src.models import Alert

logger = structlog.get_logger()

router = APIRouter(tags=["monitoring"])


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """System health check — verifies all service connections."""
    health = {"status": "healthy", "services": {}, "version": "1.0.0"}

    # Database
    try:
        async with get_db() as db:
            await db.execute(select(func.count()).select_from(Alert))
        health["services"]["database"] = "connected"
    except Exception as e:
        health["services"]["database"] = f"error: {e}"
        health["status"] = "degraded"

    # Redis
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

    # Qdrant
    try:
        from src.services.vector_store import get_qdrant
        client = get_qdrant()
        if client:
            health["services"]["qdrant"] = "connected"
        else:
            health["services"]["qdrant"] = "unavailable"
    except Exception as e:
        health["services"]["qdrant"] = f"error: {e}"

    # LLM
    try:
        from src.services.llm_client import get_llm
        llm = get_llm()
        health["services"]["llm"] = {"model": llm.model, "calls": llm.stats["total_calls"]}
    except Exception as e:
        health["services"]["llm"] = f"error: {e}"

    # Pipeline metrics
    try:
        from src.monitoring.metrics import get_metrics
        m = get_metrics()
        health["pipeline"] = {
            "alerts_processed": m.alerts_processed,
            "avg_processing_time": m.avg_processing_time,
            "alerts_failed": m.alerts_failed,
        }
    except Exception:
        pass

    return health
