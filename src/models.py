"""Database models (SQLAlchemy ORM) and API schemas (Pydantic).

Uses SQLite-compatible types for prototype (String IDs, JSON).
For production PostgreSQL: switch String(36) to UUID, JSON to JSONB.
"""

import enum
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, String, Text, JSON,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ENRICHED = "enriched"
    INVESTIGATED = "investigated"
    RESPONDED = "responded"
    CLOSED = "closed"
    ESCALATED = "escalated"


class CaseStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    source = Column(String(100), nullable=False, index=True)
    raw_data = Column(JSON, nullable=False)
    normalized = Column(JSON)
    status = Column(String(20), default=AlertStatus.NEW.value, nullable=False, index=True)
    triage_score = Column(Float)
    triage_reasoning = Column(Text)
    confidence = Column(Float)
    is_false_positive = Column(Boolean, default=False)
    enrichment_results = Column(JSON)
    similar_cases = Column(JSON)
    actions_taken = Column(JSON)
    analyst_feedback = Column(Text)
    feedback_label = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime)
    audit_logs = relationship("AuditLog", back_populates="alert", lazy="selectin")
    case = relationship("Case", back_populates="alert", uselist=False, lazy="selectin")


class Case(Base):
    __tablename__ = "cases"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False, unique=True)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default=CaseStatus.OPEN.value, nullable=False)
    assigned_analyst = Column(String(100))
    recommended_actions = Column(JSON)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    alert = relationship("Alert", back_populates="case")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False)
    agent = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert = relationship("Alert", back_populates="audit_logs")


class FeedbackQueue(Base):
    __tablename__ = "feedback_queue"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=False)
    label = Column(String(50), nullable=False)
    correct_severity = Column(Float)
    notes = Column(Text)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ━━━ Pydantic Schemas ━━━

class AlertInput(BaseModel):
    source: str = Field(default="api", examples=["syslog", "api", "kafka", "endpoint"])
    data: Dict[str, Any]

class AlertResponse(BaseModel):
    id: str
    source: str
    status: str
    triage_score: Optional[float] = None
    triage_reasoning: Optional[str] = None
    confidence: Optional[float] = None
    is_false_positive: bool = False
    enrichment_results: Optional[Dict[str, Any]] = None
    similar_cases: Optional[List[Dict[str, Any]]] = None
    actions_taken: Optional[List[Dict[str, Any]]] = None
    created_at: datetime
    closed_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class AlertListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    alerts: List[AlertResponse]

class FeedbackInput(BaseModel):
    alert_id: str
    label: str = Field(..., pattern="^(agree|false_positive|missed|severity_wrong)$")
    correct_severity: Optional[float] = Field(None, ge=0.0, le=1.0)
    notes: Optional[str] = None

class StatsResponse(BaseModel):
    total_alerts: int
    alerts_today: int
    avg_triage_score: Optional[float]
    false_positive_rate: float
    avg_processing_time_sec: Optional[float]
    severity_distribution: Dict[str, int]
    top_sources: List[Dict[str, Any]]