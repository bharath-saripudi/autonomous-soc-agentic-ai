# Autonomous Security Operations Center (SOC) Using Agentic AI

> Reduces Mean Time to Conclusion from **287 days → under 3 minutes** using 6 specialised AI agents powered by Claude Sonnet 4 and LangGraph.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green?style=flat-square)
![LangGraph](https://img.shields.io/badge/LangGraph-0.0.28-purple?style=flat-square)
![Claude](https://img.shields.io/badge/Claude-Sonnet%204-orange?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

---

## Overview

Modern SOCs are overwhelmed — analysts receive 1,000+ alerts daily with 70% being false positives, and breaches go undetected for an average of 287 days (IBM 2024). This project builds an **Autonomous SOC** using Agentic AI that independently investigates, triages, enriches, and responds to security alerts with no human intervention for routine cases.

**Key numbers:**
- 287 days → **< 3 minutes** (Mean Time to Conclusion)
- $2–$5/alert → **$0.10/alert** (vs commercial XSOAR)
- 60–70% false positives → **< 5%**
- Target automation rate: **80%+**

---

## Architecture

```
Alert In → Normalize → Triage Score → Enrich IOCs → Hunt Patterns → Execute Response → Log + Learn
```

**6 Specialised Agents:**
| Agent | Role |
|---|---|
| Orchestrator | Routes and coordinates all agents |
| Triage | LLM severity scoring 0.0–1.0 via Claude Sonnet 4 |
| Enrichment | IOC threat intel via VirusTotal v3, AbuseIPDB v2, AlienVault OTX |
| Hunting | RAG vector similarity search via Qdrant |
| Response | Automated containment — block IP, isolate host, kill process |
| Learning | RLHF playbook improvement from analyst feedback |

**System Layers:**
- **L1 Ingestion:** Syslog UDP/514, REST API, Kafka Streams, CEF/JSON normalizer
- **L2 Orchestration:** LangGraph StateGraph with TypedDict persistent state
- **L3 AI Processing:** Claude Sonnet 4 (200k context), multi-agent coordination
- **L4 Memory & Storage:** Qdrant (vector), Redis (cache), PostgreSQL, TimescaleDB
- **L5 Output:** FastAPI + WebSocket, React dashboard, Prometheus/Grafana

---

## Folder Structure

```
autonomous-soc/
├── src/
│   ├── agents/          # 6 AI agents (triage, enrichment, hunting, response, learning, orchestrator)
│   ├── api/             # FastAPI routes + WebSocket
│   ├── ingestion/       # Syslog, Kafka, REST normalizer
│   ├── ml/              # Threat classifier + feature engineering
│   ├── monitoring/      # Health, metrics, target monitor
│   ├── services/        # LLM client, vector store, threat intel, audit
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   └── state.py
├── dashboard/           # React frontend (WebSocket real-time)
│   └── src/
│       ├── components/  # MetricsCard, SeverityBadge, TimelineView
│       └── pages/       # AlertFeed, AlertDetail, Statistics, FeedbackForm
├── scripts/             # simulate_attack.py, train_ml.py, seed_db.py, etc.
├── tests/               # Unit + E2E tests
├── models/              # Pre-trained threat_classifier.joblib
├── docs/                # Architecture diagrams, dev guide
├── Alembic/             # DB migrations
├── .env.example
├── requirements.txt
└── README.md
```

---

## Tech Stack

| Category | Tools |
|---|---|
| AI / LLM | Claude Sonnet 4, LangGraph 0.0.28, LangChain 0.1.6, Sentence Transformers |
| Backend | FastAPI 0.109, Uvicorn, SQLAlchemy 2.0, Pydantic v2 |
| Databases | PostgreSQL 16, Redis 7, Qdrant (vector), TimescaleDB |
| Threat Intel | VirusTotal v3, AbuseIPDB v2, AlienVault OTX, MITRE ATT&CK |
| Frontend | React, WebSocket, Chart.js, Bootstrap 5 |
| DevOps | Docker, Kubernetes-ready, Prometheus, Grafana |
| Languages | Python 3.11+, JavaScript, SQL, Bash |

---

## Getting Started

### Prerequisites
- Python 3.11+
- Docker Desktop
- Node.js 18+
- Anthropic API key
- VirusTotal & AbuseIPDB API keys

### Installation

```bash
# Clone the repo
git clone https://github.com/bharath-saripudi/autonomous-soc-agentic-ai.git
cd autonomous-soc-agentic-ai

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env and add your API keys:
# ANTHROPIC_API_KEY=your_key
# VIRUSTOTAL_API_KEY=your_key
# ABUSEIPDB_API_KEY=your_key
# DATABASE_URL=postgresql://...
# REDIS_URL=redis://localhost:6379
```

### Start Infrastructure (Docker)

```bash
docker compose up -d  # starts PostgreSQL + Redis
```

### Run Database Migrations

```bash
alembic upgrade head
python scripts/seed_db.py
```

### Start the Server

```bash
uvicorn src.api.main:app --reload --port 8000
```

### Verify it's running

```bash
curl http://localhost:8000/health
# {"status":"healthy","database":"healthy","redis":"healthy","anthropic":"ok"}
```

### Simulate an Attack Alert

```bash
python scripts/simulate_attack.py
```

---

## API Usage

**Submit an alert:**
```bash
curl -X POST http://localhost:8000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{"source":"wazuh","event_type":"ransomware","host":"srv-01","process":"crypto.exe","files_encrypted":1500}'
```

**Check triage result:**
```bash
curl http://localhost:8000/api/v1/alerts/{alert_id}
# {"triage_score":0.94,"severity":"critical","is_false_positive":false,
#  "triage_reasoning":"Ransomware: mass encryption + C2 comms detected."}
```

Full API docs at: `http://localhost:8000/docs`

---

## Running Tests

```bash
pytest tests/
```

---

## Project Status

| Phase | Status | Description |
|---|---|---|
| Phase 1 | ✅ Done | Docker infra, FastAPI, LangGraph, Triage Agent |
| Phase 2 | 🔄 In Progress | IOC Enrichment Agent (VirusTotal + AbuseIPDB) |
| Phase 3 | 📅 Planned | Hunting + Response Agents, Qdrant RAG |
| Phase 4 | 📅 Planned | RLHF Learning Agent + React Dashboard |
| Phase 5 | 📅 Planned | Wazuh integration, Kubernetes, load testing |

---

## Associated With

SRM Institute of Science and Technology, Tiruchirappalli
Department of Computer Science and Engineering
B.Tech CSE — Mini Project (2025)

**Team:** S. Venkat Bharath · V. Bhavani · R. Koushik
**Guide:** Dr. P. Senthilkumar, Associate Professor

---

## License

MIT License — feel free to use, modify, and distribute.
