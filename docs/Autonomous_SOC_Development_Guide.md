# Autonomous SOC — Prototype Development Guide

---

## CODEBASE STRUCTURE

```
autonomous-soc/
├── docker-compose.yml              # All services (Postgres, Redis, Qdrant, Kafka)
├── .env.example                    # API keys template
├── pyproject.toml                  # Python deps (Poetry)
├── alembic/                        # DB migrations
│   └── versions/
│
├── src/
│   ├── config.py                   # Pydantic Settings (env vars, secrets)
│   ├── models.py                   # SQLAlchemy ORM + Pydantic schemas
│   ├── state.py                    # AgentState TypedDict definition
│   │
│   ├── ingestion/
│   │   ├── syslog_listener.py      # UDP port 514 syslog receiver
│   │   ├── rest_api.py             # FastAPI POST /alerts endpoint
│   │   ├── kafka_consumer.py       # Kafka batch consumer
│   │   └── normalizer.py           # CEF/LEEF/JSON → unified schema
│   │
│   ├── agents/
│   │   ├── orchestrator.py         # LangGraph StateGraph definition + routing
│   │   ├── triage.py               # LLM severity scoring (ReAct prompt)
│   │   ├── enrichment.py           # IOC lookup (VT, AbuseIPDB) + Redis cache
│   │   ├── hunting.py              # Qdrant vector search + RAG context
│   │   ├── response.py             # Automated actions (block/isolate/kill)
│   │   └── learning.py             # RLHF feedback collector + prompt updater
│   │
│   ├── services/
│   │   ├── llm_client.py           # OpenAI/Anthropic abstraction layer
│   │   ├── threat_intel.py         # VirusTotal, AbuseIPDB API wrappers
│   │   ├── vector_store.py         # Qdrant CRUD + embedding generation
│   │   ├── cache.py                # Redis get/set with TTL
│   │   └── action_executor.py      # Firewall/EDR API stubs (safe mode)
│   │
│   ├── api/
│   │   ├── main.py                 # FastAPI app factory
│   │   ├── routes_alerts.py        # CRUD endpoints for alerts
│   │   ├── routes_stats.py         # Dashboard statistics
│   │   ├── routes_feedback.py      # Analyst feedback submission
│   │   └── websocket.py            # Real-time alert push
│   │
│   └── monitoring/
│       ├── metrics.py              # Prometheus counters/histograms
│       └── health.py               # /health endpoint
│
├── dashboard/                      # React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── pages/
│   │   │   ├── AlertFeed.jsx       # Live alert table with severity colors
│   │   │   ├── AlertDetail.jsx     # Full investigation trail view
│   │   │   ├── FeedbackForm.jsx    # Analyst correction interface
│   │   │   └── Statistics.jsx      # Charts (volume, FP rate, cost)
│   │   ├── components/
│   │   │   ├── SeverityBadge.jsx
│   │   │   ├── TimelineView.jsx    # Triage→Enrich→Hunt→Response timeline
│   │   │   └── MetricsCard.jsx
│   │   └── hooks/
│   │       └── useWebSocket.js     # Real-time alert subscription
│   └── package.json
│
├── tests/
│   ├── test_triage.py
│   ├── test_enrichment.py
│   ├── test_hunting.py
│   ├── test_workflow_e2e.py
│   └── fixtures/
│       └── sample_alerts.json      # 20+ realistic test alerts
│
├── scripts/
│   ├── seed_db.py                  # Load sample alerts into Postgres
│   ├── seed_qdrant.py              # Load historical incidents into vector DB
│   └── simulate_attack.py          # Generate realistic alert streams
│
└── docs/
    └── architecture.mermaid        # System diagram
```

---

## PHASE 1 — FOUNDATION (Week 1–2)

**Goal:** Infrastructure running, alerts flowing in and persisting.

### 1A. Docker Environment

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: soc
      POSTGRES_PASSWORD: ${DB_PASS}
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

  qdrant:
    image: qdrant/qdrant:v1.7.4
    ports: ["6333:6333"]
    volumes: [qdrant_data:/qdrant/storage]

  zookeeper:
    image: confluentinc/cp-zookeeper:7.5.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  kafka:
    image: confluentinc/cp-kafka:7.5.0
    depends_on: [zookeeper]
    ports: ["9092:9092"]
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1

volumes:
  pgdata:
  qdrant_data:
```

### 1B. Database Models

```python
# src/models.py
from sqlalchemy import Column, String, Float, Boolean, DateTime, JSON, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
from datetime import datetime
import uuid
import enum

Base = declarative_base()

class AlertStatus(str, enum.Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ENRICHED = "enriched"
    INVESTIGATED = "investigated"
    RESPONDED = "responded"
    CLOSED = "closed"
    ESCALATED = "escalated"

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(100), nullable=False)          # "syslog", "api", "kafka"
    raw_data = Column(JSON, nullable=False)
    normalized = Column(JSON)                              # Unified schema
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    triage_score = Column(Float)                           # 0.0 – 1.0
    triage_reasoning = Column(Text)
    confidence = Column(Float)
    is_false_positive = Column(Boolean, default=False)
    enrichment_results = Column(JSON)
    similar_cases = Column(JSON)
    actions_taken = Column(JSON)
    analyst_feedback = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True))
    agent = Column(String(50))           # Which agent acted
    action = Column(String(100))         # What was done
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
```

### 1C. Shared Agent State

```python
# src/state.py
from typing import TypedDict, Optional, List, Dict, Any

class AgentState(TypedDict):
    alert_id: str
    raw_data: Dict[str, Any]
    normalized: Optional[Dict[str, Any]]

    # Triage output
    triage_score: Optional[float]         # 0.0 (benign) to 1.0 (critical)
    triage_reasoning: Optional[str]
    confidence: Optional[float]

    # Enrichment output
    ioc_list: Optional[List[Dict]]        # Extracted IPs, hashes, domains
    enrichment_results: Optional[Dict]    # API lookup results

    # Hunting output
    similar_cases: Optional[List[Dict]]   # Top-5 from Qdrant

    # Response output
    actions_taken: Optional[List[Dict]]   # {"action": "block_ip", "target": "1.2.3.4"}
    response_status: Optional[str]

    # Learning
    analyst_feedback: Optional[str]
    feedback_label: Optional[str]         # "agree", "false_positive", "missed"

    # Routing
    next_agent: Optional[str]
    should_escalate: Optional[bool]
```

### 1D. Alert Normalizer

```python
# src/ingestion/normalizer.py
import re
from datetime import datetime

class AlertNormalizer:
    """Converts diverse alert formats into unified schema."""

    def normalize(self, source: str, raw: dict) -> dict:
        """Route to format-specific parser."""
        if source == "syslog":
            return self._parse_syslog(raw)
        elif "CEF" in str(raw.get("message", "")):
            return self._parse_cef(raw)
        else:
            return self._parse_json(raw)

    def _parse_json(self, raw: dict) -> dict:
        return {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "source_ip": raw.get("src_ip") or raw.get("source_ip"),
            "dest_ip": raw.get("dst_ip") or raw.get("dest_ip"),
            "hostname": raw.get("hostname") or raw.get("host"),
            "event_type": raw.get("event_type") or raw.get("type"),
            "severity_hint": raw.get("severity") or raw.get("priority"),
            "description": raw.get("message") or raw.get("description"),
            "indicators": self._extract_iocs(str(raw)),
            "raw_reference": raw,
        }

    def _parse_syslog(self, raw: dict) -> dict:
        msg = raw.get("message", "")
        return {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "hostname": raw.get("hostname"),
            "event_type": "syslog",
            "severity_hint": raw.get("severity"),
            "description": msg,
            "indicators": self._extract_iocs(msg),
            "raw_reference": raw,
        }

    def _parse_cef(self, raw: dict) -> dict:
        msg = raw.get("message", "")
        # CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        parts = msg.split("|", 7)
        return {
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "event_type": parts[5] if len(parts) > 5 else "unknown",
            "severity_hint": parts[6] if len(parts) > 6 else None,
            "description": parts[5] if len(parts) > 5 else msg,
            "indicators": self._extract_iocs(msg),
            "raw_reference": raw,
        }

    @staticmethod
    def _extract_iocs(text: str) -> dict:
        return {
            "ips": re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
            "hashes_md5": re.findall(r'\b[a-fA-F0-9]{32}\b', text),
            "hashes_sha256": re.findall(r'\b[a-fA-F0-9]{64}\b', text),
            "domains": re.findall(
                r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text
            ),
        }
```

### 1E. FastAPI Ingestion Endpoint

```python
# src/ingestion/rest_api.py
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Any, Dict
import uuid

app = FastAPI(title="Autonomous SOC")

class AlertInput(BaseModel):
    source: str = "api"
    data: Dict[str, Any]

@app.post("/alerts", status_code=202)
async def ingest_alert(alert: AlertInput, bg: BackgroundTasks):
    alert_id = str(uuid.uuid4())
    # 1. Save to Postgres with status "new"
    # 2. Kick off async processing
    bg.add_task(process_alert_pipeline, alert_id, alert.source, alert.data)
    return {"alert_id": alert_id, "status": "accepted"}

async def process_alert_pipeline(alert_id: str, source: str, raw: dict):
    """Entry point — hands off to orchestrator."""
    from src.agents.orchestrator import run_workflow
    await run_workflow(alert_id, source, raw)
```

### Phase 1 Deliverable Checklist

- [ ] `docker-compose up` boots Postgres, Redis, Qdrant, Kafka
- [ ] Alembic migration creates alerts + audit_log tables
- [ ] POST `/alerts` accepts JSON, returns alert_id
- [ ] Alert saved to Postgres with status `new`
- [ ] Normalizer handles JSON and syslog formats
- [ ] 20+ sample alerts in `fixtures/sample_alerts.json`

---

## PHASE 2 — CORE AGENTS (Week 3–5)

**Goal:** Triage, Enrichment, and Hunting agents working end-to-end.

### 2A. LLM Client Abstraction

```python
# src/services/llm_client.py
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic
import os

class LLMClient:
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "openai")  # or "anthropic"
        if self.provider == "openai":
            self.client = AsyncOpenAI()
        else:
            self.client = AsyncAnthropic()

    async def reason(self, system_prompt: str, user_prompt: str) -> dict:
        """Send ReAct prompt, return structured response."""
        if self.provider == "openai":
            resp = await self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )
            return json.loads(resp.choices[0].message.content)

        else:  # anthropic
            resp = await self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return json.loads(resp.content[0].text)
```

### 2B. Triage Agent (ReAct Prompting)

```python
# src/agents/triage.py
from src.state import AgentState
from src.services.llm_client import LLMClient

TRIAGE_SYSTEM_PROMPT = """You are an expert SOC analyst performing alert triage.
Analyze the security alert using ReAct (Reason + Act) methodology.

STEP 1 — OBSERVE: List every factual detail in the alert.
STEP 2 — REASON: For each detail, explain if it suggests malicious or benign activity.
STEP 3 — ASSESS: Weigh all evidence and assign severity.
STEP 4 — DECIDE: Output your final assessment.

Respond ONLY with valid JSON:
{
  "observation": "what you see in the alert",
  "reasoning": "step-by-step analysis of each indicator",
  "severity_score": 0.0 to 1.0,
  "confidence": 0.0 to 1.0,
  "classification": "critical|high|medium|low|info|false_positive",
  "recommended_actions": ["list of suggested next steps"],
  "false_positive_indicators": ["reasons this might be benign, if any"]
}

Scoring guide:
  0.0–0.15  → false_positive / info (auto-close)
  0.16–0.39 → low (log and monitor)
  0.40–0.69 → medium (investigate further)
  0.70–0.89 → high (enrich + hunt + respond)
  0.90–1.00 → critical (immediate escalation + auto-respond)
"""

llm = LLMClient()

async def triage_agent(state: AgentState) -> AgentState:
    """Score alert severity using LLM with ReAct reasoning."""
    alert_text = format_alert_for_llm(state["normalized"] or state["raw_data"])

    result = await llm.reason(
        system_prompt=TRIAGE_SYSTEM_PROMPT,
        user_prompt=f"Analyze this security alert:\n\n{alert_text}"
    )

    state["triage_score"] = result["severity_score"]
    state["triage_reasoning"] = result["reasoning"]
    state["confidence"] = result["confidence"]

    # Routing decision
    score = result["severity_score"]
    if score <= 0.15:
        state["next_agent"] = "close"
    elif score >= 0.90:
        state["should_escalate"] = True
        state["next_agent"] = "enrichment"  # Still enrich before escalating
    else:
        state["next_agent"] = "enrichment"

    return state

def format_alert_for_llm(data: dict) -> str:
    """Flatten alert dict into readable text block for the LLM."""
    lines = []
    for k, v in data.items():
        if v is not None:
            lines.append(f"{k}: {v}")
    return "\n".join(lines)
```

### 2C. Enrichment Agent + Redis Cache

```python
# src/agents/enrichment.py
import aiohttp
import hashlib
from src.services.cache import RedisCache
from src.state import AgentState

cache = RedisCache(ttl=3600)  # 1-hour TTL

async def enrichment_agent(state: AgentState) -> AgentState:
    """Look up IOCs against threat intel APIs, with caching."""
    iocs = state.get("ioc_list") or extract_iocs(state)
    results = {"ips": {}, "hashes": {}, "domains": {}}

    for ip in iocs.get("ips", []):
        results["ips"][ip] = await lookup_ip(ip)

    for h in iocs.get("hashes_sha256", []) + iocs.get("hashes_md5", []):
        results["hashes"][h] = await lookup_hash(h)

    state["enrichment_results"] = results
    state["next_agent"] = "hunting"
    return state

async def lookup_ip(ip: str) -> dict:
    """Check AbuseIPDB for IP reputation, cached in Redis."""
    cache_key = f"ip:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}

    # Call AbuseIPDB API
    async with aiohttp.ClientSession() as session:
        resp = await session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": os.getenv("ABUSEIPDB_KEY"), "Accept": "application/json"},
        )
        data = (await resp.json()).get("data", {})

    result = {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "total_reports": data.get("totalReports", 0),
        "is_tor": data.get("isTor", False),
    }
    await cache.set(cache_key, result)
    return result

async def lookup_hash(file_hash: str) -> dict:
    """Check VirusTotal for file hash reputation, cached in Redis."""
    cache_key = f"hash:{file_hash}"
    cached = await cache.get(cache_key)
    if cached:
        return {**cached, "_cache": "hit"}

    async with aiohttp.ClientSession() as session:
        resp = await session.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": os.getenv("VIRUSTOTAL_KEY")},
        )
        data = (await resp.json()).get("data", {}).get("attributes", {})

    stats = data.get("last_analysis_stats", {})
    result = {
        "hash": file_hash,
        "malicious_count": stats.get("malicious", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "threat_label": data.get("popular_threat_classification", {})
                            .get("suggested_threat_label"),
    }
    await cache.set(cache_key, result)
    return result
```

### 2D. Hunting Agent (Qdrant Vector Search + RAG)

```python
# src/agents/hunting.py
from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer
from src.state import AgentState
from src.services.llm_client import LLMClient

encoder = SentenceTransformer("all-MiniLM-L6-v2")  # 384-dim (or all-mpnet for 768)
qdrant = QdrantClient(host="localhost", port=6333)
llm = LLMClient()
COLLECTION = "incidents"

async def hunting_agent(state: AgentState) -> AgentState:
    """Find similar past incidents via vector search, feed as RAG context."""
    # 1. Generate embedding of current alert
    alert_text = str(state.get("normalized") or state["raw_data"])
    embedding = encoder.encode(alert_text).tolist()

    # 2. Search Qdrant for top-5 similar past incidents
    hits = qdrant.search(
        collection_name=COLLECTION,
        query_vector=embedding,
        limit=5,
        score_threshold=0.6,  # Only return reasonably similar results
    )

    similar = []
    for hit in hits:
        similar.append({
            "score": round(hit.score, 3),
            "description": hit.payload.get("description"),
            "severity": hit.payload.get("severity"),
            "outcome": hit.payload.get("outcome"),
            "timestamp": hit.payload.get("timestamp"),
        })

    state["similar_cases"] = similar

    # 3. RAG: Ask LLM to factor historical context into assessment
    if similar:
        context = "\n".join(
            f"- [similarity={c['score']}] {c['description']} → outcome: {c['outcome']}"
            for c in similar
        )
        rag_result = await llm.reason(
            system_prompt="You are a threat hunter. Given the current alert and "
                          "similar past incidents, assess if this is a repeat attack, "
                          "a known pattern, or novel. Output JSON with fields: "
                          "pattern_match (bool), historical_context (str), "
                          "adjusted_severity (float), reasoning (str).",
            user_prompt=f"CURRENT ALERT:\n{alert_text}\n\n"
                        f"SIMILAR PAST INCIDENTS:\n{context}"
        )
        # Optionally adjust triage score based on historical pattern
        if rag_result.get("adjusted_severity"):
            state["triage_score"] = max(
                state["triage_score"],
                rag_result["adjusted_severity"]
            )

    state["next_agent"] = "response"
    return state
```

### Phase 2 Deliverable Checklist

- [ ] Triage agent returns severity score + reasoning in <4 seconds
- [ ] Enrichment agent queries VT and AbuseIPDB with Redis cache hits
- [ ] Hunting agent finds similar incidents from Qdrant
- [ ] RAG context adjusts severity when historical matches are strong
- [ ] All three agents update AgentState correctly
- [ ] Unit tests pass for each agent with mocked LLM/API calls

---

## PHASE 3 — ORCHESTRATION + RESPONSE (Week 6–7)

**Goal:** Full LangGraph workflow with conditional routing and automated response.

### 3A. LangGraph StateGraph Workflow

```python
# src/agents/orchestrator.py
from langgraph.graph import StateGraph, END
from src.state import AgentState
from src.agents.triage import triage_agent
from src.agents.enrichment import enrichment_agent
from src.agents.hunting import hunting_agent
from src.agents.response import response_agent
from src.agents.learning import learning_agent
from src.ingestion.normalizer import AlertNormalizer

normalizer = AlertNormalizer()

def build_workflow() -> StateGraph:
    """Construct the multi-agent workflow graph."""
    graph = StateGraph(AgentState)

    # --- Nodes ---
    graph.add_node("normalize", normalize_node)
    graph.add_node("triage", triage_agent)
    graph.add_node("enrichment", enrichment_agent)
    graph.add_node("hunting", hunting_agent)
    graph.add_node("response", response_agent)
    graph.add_node("learning", learning_agent)
    graph.add_node("close_alert", close_alert_node)
    graph.add_node("escalate", escalate_node)

    # --- Edges ---
    graph.set_entry_point("normalize")
    graph.add_edge("normalize", "triage")

    # Conditional routing after triage
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "close": "close_alert",
            "enrichment": "enrichment",
        }
    )

    graph.add_edge("enrichment", "hunting")

    # Conditional routing after hunting
    graph.add_conditional_edges(
        "hunting",
        route_after_hunting,
        {
            "response": "response",
            "escalate": "escalate",
            "close": "close_alert",
        }
    )

    graph.add_edge("response", "learning")
    graph.add_edge("learning", END)
    graph.add_edge("close_alert", "learning")
    graph.add_edge("learning", END)
    graph.add_edge("escalate", "learning")

    return graph.compile()

# --- Routing Functions ---

def route_after_triage(state: AgentState) -> str:
    score = state.get("triage_score", 0)
    if score <= 0.15:
        return "close"
    return "enrichment"

def route_after_hunting(state: AgentState) -> str:
    score = state.get("triage_score", 0)
    confidence = state.get("confidence", 0)
    if state.get("should_escalate") or score >= 0.90:
        if confidence >= 0.85:
            return "response"     # Auto-respond then escalate
        return "escalate"         # Low confidence → human decides
    if score >= 0.40:
        return "response"
    return "close"

# --- Helper Nodes ---

async def normalize_node(state: AgentState) -> AgentState:
    state["normalized"] = normalizer.normalize("auto", state["raw_data"])
    return state

async def close_alert_node(state: AgentState) -> AgentState:
    state["response_status"] = "closed"
    # Update Postgres status → "closed"
    return state

async def escalate_node(state: AgentState) -> AgentState:
    state["response_status"] = "escalated"
    state["should_escalate"] = True
    # Create case in Postgres, notify analyst via WebSocket
    return state

# --- Entry Point ---

workflow = build_workflow()

async def run_workflow(alert_id: str, source: str, raw_data: dict):
    """Execute the full agent pipeline for one alert."""
    initial_state: AgentState = {
        "alert_id": alert_id,
        "raw_data": raw_data,
        "normalized": None,
        "triage_score": None,
        "triage_reasoning": None,
        "confidence": None,
        "ioc_list": None,
        "enrichment_results": None,
        "similar_cases": None,
        "actions_taken": None,
        "response_status": None,
        "analyst_feedback": None,
        "feedback_label": None,
        "next_agent": None,
        "should_escalate": None,
    }
    final_state = await workflow.ainvoke(initial_state)
    # Persist final_state to Postgres
    await save_final_state(alert_id, final_state)
    return final_state
```

### 3B. Response Agent with Safety Gates

```python
# src/agents/response.py
from src.state import AgentState

# Critical systems that must never be auto-blocked/isolated
PROTECTED_ASSETS = {
    "10.0.0.1",        # Core router
    "10.0.0.2",        # DNS server
    "10.0.0.10",       # Domain controller
    "dc01.corp.local",
    "dns.corp.local",
}

CONFIDENCE_THRESHOLDS = {
    "block_ip": 0.80,
    "isolate_host": 0.90,
    "kill_process": 0.85,
    "notify": 0.0,       # Always allowed
}

async def response_agent(state: AgentState) -> AgentState:
    """Execute automated response actions with safety controls."""
    score = state.get("triage_score", 0)
    confidence = state.get("confidence", 0)
    actions_taken = []

    # Always notify on medium+
    if score >= 0.40:
        actions_taken.append(await notify_team(state))

    # Block malicious IPs (high+)
    if score >= 0.70:
        for ip_result in (state.get("enrichment_results") or {}).get("ips", {}).values():
            if ip_result.get("abuse_score", 0) >= 50:
                ip = ip_result["ip"]
                action = await safe_execute(
                    "block_ip", ip, confidence, state
                )
                actions_taken.append(action)

    # Isolate host (critical only)
    if score >= 0.90 and confidence >= CONFIDENCE_THRESHOLDS["isolate_host"]:
        hostname = (state.get("normalized") or {}).get("hostname")
        if hostname:
            action = await safe_execute(
                "isolate_host", hostname, confidence, state
            )
            actions_taken.append(action)

    state["actions_taken"] = actions_taken
    return state

async def safe_execute(action_type: str, target: str, confidence: float, state: dict) -> dict:
    """Safety gate: check thresholds and protected assets before acting."""
    # Gate 1: Confidence check
    if confidence < CONFIDENCE_THRESHOLDS.get(action_type, 1.0):
        return {"action": action_type, "target": target,
                "status": "skipped", "reason": "confidence too low"}

    # Gate 2: Protected asset check
    if target in PROTECTED_ASSETS:
        return {"action": action_type, "target": target,
                "status": "blocked", "reason": "protected asset"}

    # Gate 3: Execute (stub in prototype — log instead of real action)
    result = await execute_action(action_type, target)
    return {"action": action_type, "target": target,
            "status": "executed", "result": result}

async def execute_action(action_type: str, target: str) -> dict:
    """Stub for actual firewall/EDR API calls. Logs action in prototype."""
    # In production, these call real APIs:
    #   block_ip → firewall API
    #   isolate_host → CrowdStrike/SentinelOne API
    #   kill_process → EDR API
    print(f"[RESPONSE] Executing {action_type} on {target}")
    return {"success": True, "simulated": True}

async def notify_team(state: dict) -> dict:
    """Send alert notification (Slack webhook / email in production)."""
    print(f"[NOTIFY] Alert {state['alert_id']} — "
          f"score={state.get('triage_score')}")
    return {"action": "notify", "status": "sent"}
```

### Phase 3 Deliverable Checklist

- [ ] `run_workflow()` executes full Normalize → Triage → Enrich → Hunt → Respond pipeline
- [ ] Low-severity alerts auto-close without hitting enrichment/hunting
- [ ] Critical alerts trigger response actions + escalation
- [ ] Protected assets are never auto-blocked/isolated
- [ ] Confidence gates prevent action when AI is uncertain
- [ ] Audit log captures every agent action
- [ ] E2E test: submit ransomware alert → verify full pipeline completes in <3 min

---

## PHASE 4 — LEARNING + FEEDBACK (Week 8–9)

**Goal:** RLHF loop working — analyst feedback improves triage accuracy.

### 4A. Learning Agent

```python
# src/agents/learning.py
from src.state import AgentState
from src.services.vector_store import store_incident_embedding

FEEDBACK_THRESHOLD = 100  # Trigger prompt update after N feedback samples

async def learning_agent(state: AgentState) -> AgentState:
    """Record incident for future hunting + collect feedback patterns."""
    # 1. Store embedding in Qdrant for future similarity search
    await store_incident_embedding(
        alert_id=state["alert_id"],
        text=str(state.get("normalized") or state["raw_data"]),
        metadata={
            "severity": state.get("triage_score"),
            "outcome": state.get("response_status"),
            "actions": state.get("actions_taken"),
            "was_false_positive": state.get("feedback_label") == "false_positive",
        }
    )

    # 2. Check if we have enough feedback to trigger prompt refinement
    feedback_count = await get_pending_feedback_count()
    if feedback_count >= FEEDBACK_THRESHOLD:
        await trigger_prompt_refinement()

    return state

async def trigger_prompt_refinement():
    """Analyze feedback patterns and update triage system prompt."""
    feedbacks = await get_all_pending_feedback()

    # Group by feedback type
    false_positives = [f for f in feedbacks if f["label"] == "false_positive"]
    missed_threats = [f for f in feedbacks if f["label"] == "missed"]

    # Generate prompt patch using LLM
    from src.services.llm_client import LLMClient
    llm = LLMClient()
    analysis = await llm.reason(
        system_prompt="Analyze these analyst corrections and produce specific "
                      "rules to add to the triage prompt. Output JSON: "
                      '{"new_rules": ["rule1", "rule2"], "rationale": "..."}',
        user_prompt=f"FALSE POSITIVES ({len(false_positives)} cases):\n"
                    f"{summarize_feedback(false_positives)}\n\n"
                    f"MISSED THREATS ({len(missed_threats)} cases):\n"
                    f"{summarize_feedback(missed_threats)}"
    )

    # Append new rules to triage system prompt
    await update_triage_prompt(analysis["new_rules"])
    await mark_feedback_processed(feedbacks)
```

### 4B. Feedback API Endpoint

```python
# src/api/routes_feedback.py
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Literal

router = APIRouter(prefix="/feedback", tags=["feedback"])

class FeedbackInput(BaseModel):
    alert_id: str
    label: Literal["agree", "false_positive", "missed", "severity_wrong"]
    correct_severity: float | None = None  # Analyst's assessment
    notes: str | None = None

@router.post("/")
async def submit_feedback(fb: FeedbackInput):
    """Analyst submits correction for an alert assessment."""
    # 1. Update alert record with feedback
    await update_alert_feedback(fb.alert_id, fb.label, fb.notes)

    # 2. Store in feedback queue for learning agent
    await queue_feedback({
        "alert_id": fb.alert_id,
        "label": fb.label,
        "correct_severity": fb.correct_severity,
        "notes": fb.notes,
    })

    return {"status": "recorded", "alert_id": fb.alert_id}
```

### Phase 4 Deliverable Checklist

- [ ] Every processed alert gets stored as embedding in Qdrant
- [ ] Feedback endpoint accepts analyst corrections
- [ ] After 100+ feedback samples, prompt refinement triggers
- [ ] New rules get appended to triage system prompt
- [ ] Before/after accuracy comparison logged

---

## PHASE 5 — DASHBOARD + REAL-TIME (Week 10–12)

**Goal:** React dashboard with live feed, investigation drill-down, and feedback UI.

### 5A. WebSocket Server

```python
# src/api/websocket.py
from fastapi import WebSocket, WebSocketDisconnect
from typing import List
import json

class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        for ws in self.active:
            await ws.send_text(json.dumps(message))

manager = ConnectionManager()

# In your FastAPI app:
# @app.websocket("/ws/alerts")
# async def ws_alerts(ws: WebSocket):
#     await manager.connect(ws)
#     try:
#         while True:
#             await ws.receive_text()  # Keep alive
#     except WebSocketDisconnect:
#         manager.disconnect(ws)
```

### 5B. React Dashboard Key Components

```
dashboard/src/
├── pages/
│   ├── AlertFeed.jsx         →  Table: severity badge, source, timestamp, status
│   │                             Auto-updates via WebSocket
│   │                             Color: red (critical), orange (high),
│   │                                    yellow (medium), green (low), gray (info)
│   │
│   ├── AlertDetail.jsx       →  Full investigation timeline:
│   │                             [Ingestion] → [Triage Score + Reasoning]
│   │                             → [Enrichment: IP/hash results]
│   │                             → [Hunting: similar cases]
│   │                             → [Response: actions taken]
│   │                             + Analyst feedback form at bottom
│   │
│   ├── Statistics.jsx        →  Recharts dashboards:
│   │                             • Alert volume over time (line chart)
│   │                             • Severity distribution (pie chart)
│   │                             • False positive rate trend (area chart)
│   │                             • Avg processing time (bar chart)
│   │                             • Cost per alert (KPI card)
│   │
│   └── FeedbackForm.jsx      →  Dropdown: agree / false_positive / missed
│                                 Optional severity override slider (0–1)
│                                 Notes textarea
│                                 Submit → POST /feedback
```

### 5C. Statistics API

```python
# src/api/routes_stats.py
from fastapi import APIRouter

router = APIRouter(prefix="/stats", tags=["statistics"])

@router.get("/overview")
async def get_overview():
    """Dashboard KPI endpoint."""
    return {
        "total_alerts": await count_alerts(),
        "alerts_today": await count_alerts_today(),
        "avg_triage_score": await avg_score(),
        "false_positive_rate": await fp_rate(),
        "avg_processing_time_sec": await avg_processing_time(),
        "cost_per_alert": 0.10,
        "severity_distribution": {
            "critical": await count_by_severity(0.90, 1.0),
            "high": await count_by_severity(0.70, 0.89),
            "medium": await count_by_severity(0.40, 0.69),
            "low": await count_by_severity(0.16, 0.39),
            "info": await count_by_severity(0.0, 0.15),
        },
        "top_sources": await top_alert_sources(limit=5),
    }
```

### Phase 5 Deliverable Checklist

- [ ] WebSocket pushes new alerts to dashboard in <100ms
- [ ] Alert feed table with color-coded severity badges
- [ ] Click-through to full investigation timeline
- [ ] Feedback form submits corrections to API
- [ ] Statistics page with 4+ charts (Recharts)
- [ ] Responsive layout works on desktop + tablet

---

## PHASE 6 — TESTING + DEMO (Week 13–14)

**Goal:** Attack simulation, benchmarks, and polished demo flow.

### 6A. Attack Simulator

```python
# scripts/simulate_attack.py
"""Generate realistic alert streams for demo and testing."""
import random, time, requests

SCENARIOS = [
    {
        "name": "Ransomware via Email",
        "source": "endpoint",
        "data": {
            "event_type": "suspicious_file_encryption",
            "hostname": "WS-FINANCE-04",
            "username": "j.smith",
            "process": "svchost_update.exe",
            "parent_process": "OUTLOOK.EXE",
            "files_affected": 847,
            "encryption_rate": "120 files/min",
            "file_extensions_changed": ".locked",
            "src_ip": "192.168.1.45",
            "hash_sha256": "a1b2c3d4e5f6...",
        }
    },
    {
        "name": "Brute Force SSH",
        "source": "firewall",
        "data": {
            "event_type": "multiple_failed_auth",
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.1.20",
            "dst_port": 22,
            "protocol": "SSH",
            "failed_attempts": 342,
            "timeframe": "5 minutes",
            "username_pattern": "root, admin, ubuntu",
        }
    },
    {
        "name": "DNS Exfiltration",
        "source": "dns_monitor",
        "data": {
            "event_type": "anomalous_dns",
            "hostname": "WS-DEV-12",
            "query_count": 4500,
            "unique_subdomains": 4200,
            "domain": "data.evil-c2.xyz",
            "avg_query_length": 180,
            "timeframe": "30 minutes",
        }
    },
    {
        "name": "False Positive — IT Admin SSH",
        "source": "ids",
        "data": {
            "event_type": "ssh_connection",
            "src_ip": "10.50.0.15",
            "dst_ip": "10.0.1.5",
            "dst_port": 22,
            "username": "sysadmin",
            "description": "SSH session from IT subnet",
        }
    },
    # Add 15+ more scenarios covering:
    # - SQL injection attempts
    # - Credential stuffing
    # - Lateral movement
    # - C2 beacon traffic
    # - Phishing link clicks
    # - Privilege escalation
    # - Port scanning
    # - DDoS indicators
]

def run_simulation(rate: float = 1.0):
    """Send alerts at specified rate (alerts/second)."""
    while True:
        scenario = random.choice(SCENARIOS)
        requests.post("http://localhost:8000/alerts", json={
            "source": scenario["source"],
            "data": scenario["data"],
        })
        print(f"[SIM] Sent: {scenario['name']}")
        time.sleep(1.0 / rate)
```

### 6B. End-to-End Test

```python
# tests/test_workflow_e2e.py
import pytest
from src.agents.orchestrator import run_workflow

@pytest.mark.asyncio
async def test_ransomware_full_pipeline():
    """Critical alert should trigger full pipeline + response."""
    result = await run_workflow(
        alert_id="test-001",
        source="endpoint",
        raw_data={
            "event_type": "suspicious_file_encryption",
            "hostname": "WS-FINANCE-04",
            "process": "svchost_update.exe",
            "parent_process": "OUTLOOK.EXE",
            "files_affected": 847,
        }
    )
    assert result["triage_score"] >= 0.70
    assert result["response_status"] in ("executed", "escalated")
    assert result["actions_taken"] is not None
    assert len(result["actions_taken"]) > 0

@pytest.mark.asyncio
async def test_false_positive_auto_close():
    """Benign IT admin SSH should auto-close."""
    result = await run_workflow(
        alert_id="test-002",
        source="ids",
        raw_data={
            "event_type": "ssh_connection",
            "src_ip": "10.50.0.15",
            "dst_ip": "10.0.1.5",
            "username": "sysadmin",
            "description": "Routine SSH from IT subnet",
        }
    )
    assert result["triage_score"] <= 0.30
    assert result["response_status"] == "closed"
```

---

## DEPENDENCY LIST

```toml
# pyproject.toml
[tool.poetry.dependencies]
python = "^3.11"

# Core framework
fastapi = "^0.115"
uvicorn = "^0.30"
langgraph = "^0.2"
langchain-core = "^0.3"

# LLM providers
openai = "^1.50"
anthropic = "^0.37"

# Databases
sqlalchemy = "^2.0"
asyncpg = "^0.30"
alembic = "^1.13"
redis = "^5.0"
qdrant-client = "^1.12"

# ML / Embeddings
sentence-transformers = "^3.0"

# Ingestion
aiokafka = "^0.10"
pydantic = "^2.9"

# HTTP clients
aiohttp = "^3.10"
httpx = "^0.27"

# Monitoring
prometheus-client = "^0.21"

# Testing
pytest = "^8.0"
pytest-asyncio = "^0.24"
```

```json
// dashboard/package.json
{
  "dependencies": {
    "react": "^18",
    "react-dom": "^18",
    "react-router-dom": "^6",
    "recharts": "^2.12",
    "axios": "^1.7",
    "tailwindcss": "^3.4",
    "@heroicons/react": "^2.1"
  }
}
```

---

## QUICK-START COMMANDS

```bash
# 1. Boot infrastructure
docker-compose up -d

# 2. Install Python deps
poetry install

# 3. Run DB migrations
alembic upgrade head

# 4. Seed sample data
python scripts/seed_db.py
python scripts/seed_qdrant.py

# 5. Start API server
uvicorn src.api.main:app --reload --port 8000

# 6. Start dashboard
cd dashboard && npm install && npm run dev

# 7. Run attack simulation
python scripts/simulate_attack.py --rate 2

# 8. Open browser
#    Dashboard:  http://localhost:5173
#    API docs:   http://localhost:8000/docs
#    Qdrant UI:  http://localhost:6333/dashboard
```

---

## KEY METRICS TO DEMO

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Alert → Conclusion time | < 3 min | Timestamp diff (created_at → closed_at) |
| Triage accuracy | > 90% | Compare AI score vs analyst label on test set |
| False positive rate | < 10% | Count FP feedback / total alerts |
| Cache hit rate | > 70% | Redis cache stats endpoint |
| Concurrent throughput | 50+ alerts/min | Simulator at rate=1 for 1 min |
| Response safety | 0 protected-asset actions | Check audit log for blocked actions |
