# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Autonomous SOC — Windows Environment Setup (PowerShell)
#  Run: .\setup.ps1  (in PowerShell as Administrator)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   Autonomous SOC - Windows Environment Setup      " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# ── STEP 1: Check Prerequisites ──────────────────────────────

Write-Host "[Step 1] Checking prerequisites..." -ForegroundColor Yellow
Write-Host ""

# Python 3.11+
try {
    $pyVersion = python --version 2>&1
    $pyMatch = [regex]::Match($pyVersion, "(\d+)\.(\d+)\.(\d+)")
    $pyMajor = [int]$pyMatch.Groups[1].Value
    $pyMinor = [int]$pyMatch.Groups[2].Value
    if ($pyMajor -ge 3 -and $pyMinor -ge 11) {
        Write-Host "  [OK] $pyVersion" -ForegroundColor Green
    } else {
        Write-Host "  [X] Python 3.11+ required (found $pyVersion)" -ForegroundColor Red
        Write-Host "      Download: https://www.python.org/downloads/" -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Host "  [X] Python not found" -ForegroundColor Red
    Write-Host "      Download: https://www.python.org/downloads/" -ForegroundColor Gray
    Write-Host "      Make sure to check 'Add Python to PATH' during install" -ForegroundColor Gray
    exit 1
}

# Docker
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "  [OK] $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "  [X] Docker not found" -ForegroundColor Red
    Write-Host "      Download: https://docs.docker.com/desktop/install/windows-install/" -ForegroundColor Gray
    exit 1
}

# Docker Compose
try {
    $dcVersion = docker compose version 2>&1
    Write-Host "  [OK] $dcVersion" -ForegroundColor Green
} catch {
    Write-Host "  [X] Docker Compose not found" -ForegroundColor Red
    Write-Host "      It should come with Docker Desktop" -ForegroundColor Gray
    exit 1
}

# Node.js (optional for now)
try {
    $nodeVersion = node --version 2>&1
    Write-Host "  [OK] Node.js $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  [!] Node.js not found (needed for dashboard in Phase 5)" -ForegroundColor DarkYellow
    Write-Host "      Download later: https://nodejs.org/" -ForegroundColor Gray
}

Write-Host ""

# ── STEP 2: Create Virtual Environment ──────────────────────

Write-Host "[Step 2] Creating Python virtual environment..." -ForegroundColor Yellow
Write-Host ""

if (Test-Path ".venv") {
    Write-Host "  [!] .venv already exists - skipping creation" -ForegroundColor DarkYellow
} else {
    python -m venv .venv
    Write-Host "  [OK] Virtual environment created at .venv\" -ForegroundColor Green
}

# Activate
& .\.venv\Scripts\Activate.ps1
Write-Host "  [OK] Virtual environment activated" -ForegroundColor Green
Write-Host ""

# ── STEP 3: Upgrade pip ─────────────────────────────────────

Write-Host "[Step 3] Upgrading pip..." -ForegroundColor Yellow
pip install --upgrade pip setuptools wheel --quiet 2>&1 | Out-Null
Write-Host "  [OK] pip upgraded" -ForegroundColor Green
Write-Host ""

# ── STEP 4: Install Python Dependencies ─────────────────────

Write-Host "[Step 4] Installing Python dependencies..." -ForegroundColor Yellow
Write-Host "         This may take a few minutes on first run..." -ForegroundColor Gray
Write-Host ""

$packages = @(
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.9",
    "pydantic-settings>=2.5",
    "anthropic>=0.37",
    "langgraph>=0.2",
    "langchain-core>=0.3",
    "sqlalchemy[asyncio]>=2.0",
    "asyncpg>=0.30",
    "alembic>=1.13",
    "redis[hiredis]>=5.0",
    "qdrant-client>=1.12",
    "sentence-transformers>=3.0",
    "aiokafka>=0.10",
    "aiohttp>=3.10",
    "httpx>=0.27",
    "prometheus-client>=0.21",
    "python-dotenv>=1.0",
    "structlog>=24.4"
)

pip install @packages
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [X] Some packages failed to install" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  [OK] All Python packages installed" -ForegroundColor Green
Write-Host ""

# Dev dependencies
Write-Host "[Step 4b] Installing dev dependencies..." -ForegroundColor Yellow
pip install "pytest>=8.0" "pytest-asyncio>=0.24" "pytest-cov>=5.0" "ruff>=0.6" --quiet
Write-Host "  [OK] Dev dependencies installed" -ForegroundColor Green
Write-Host ""

# ── STEP 5: Setup .env File ─────────────────────────────────

Write-Host "[Step 5] Setting up environment variables..." -ForegroundColor Yellow
Write-Host ""

if (Test-Path ".env") {
    Write-Host "  [!] .env already exists - skipping" -ForegroundColor DarkYellow
} else {
    Copy-Item .env.example .env
    Write-Host "  [OK] .env created from .env.example" -ForegroundColor Green
    Write-Host ""
    Write-Host "  >>> IMPORTANT: Edit .env and add your API keys <<<" -ForegroundColor Red
    Write-Host "      - ANTHROPIC_API_KEY  (required)" -ForegroundColor White
    Write-Host "      - VIRUSTOTAL_API_KEY (optional)" -ForegroundColor Gray
    Write-Host "      - ABUSEIPDB_API_KEY  (optional)" -ForegroundColor Gray
}
Write-Host ""

# ── STEP 6: Start Docker Services ───────────────────────────

Write-Host "[Step 6] Starting Docker services..." -ForegroundColor Yellow
Write-Host "         Make sure Docker Desktop is running!" -ForegroundColor Gray
Write-Host ""

docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [X] Docker Compose failed. Is Docker Desktop running?" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Waiting for services to start..." -ForegroundColor Gray
Start-Sleep -Seconds 8

# Check services
$services = @("soc-postgres", "soc-redis", "soc-qdrant", "soc-kafka")
foreach ($svc in $services) {
    $status = docker inspect -f '{{.State.Running}}' $svc 2>&1
    if ($status -eq "true") {
        Write-Host "  [OK] $svc is running" -ForegroundColor Green
    } else {
        Write-Host "  [!] $svc may still be starting..." -ForegroundColor DarkYellow
    }
}
Write-Host ""

# ── STEP 7: Initialize Database ─────────────────────────────

Write-Host "[Step 7] Initializing database..." -ForegroundColor Yellow
Write-Host ""

# Wait for Postgres
Write-Host "  Waiting for PostgreSQL..." -ForegroundColor Gray
$ready = $false
for ($i = 1; $i -le 20; $i++) {
    $result = docker compose exec -T postgres pg_isready -U soc_user -d soc_db 2>&1
    if ($result -match "accepting") {
        Write-Host "  [OK] PostgreSQL is ready" -ForegroundColor Green
        $ready = $true
        break
    }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    Write-Host "  [!] PostgreSQL not ready yet - will try anyway..." -ForegroundColor DarkYellow
}

# Create tables
python -c "
import asyncio
from src.database import init_db
asyncio.run(init_db())
print('  [OK] Database tables created')
"
Write-Host ""

# ── STEP 8: Seed Sample Data ────────────────────────────────

Write-Host "[Step 8] Seeding sample alerts..." -ForegroundColor Yellow
Write-Host ""
python -m scripts.seed_db
Write-Host ""

# ── STEP 9: Verify Installation ─────────────────────────────

Write-Host "[Step 9] Verifying installation..." -ForegroundColor Yellow
Write-Host ""

python -c "
errors = []

checks = {
    'Config module': lambda: __import__('src.config', fromlist=['get_settings']),
    'Models module': lambda: __import__('src.models', fromlist=['Alert']),
    'AgentState': lambda: __import__('src.state', fromlist=['AgentState']),
    'Normalizer': lambda: __import__('src.ingestion.normalizer', fromlist=['AlertNormalizer']),
    'Redis cache': lambda: __import__('src.services.cache', fromlist=['RedisCache']),
    'FastAPI app': lambda: __import__('src.api.main', fromlist=['app']),
    'Anthropic SDK': lambda: __import__('anthropic'),
    'LangGraph': lambda: __import__('langgraph'),
    'Qdrant client': lambda: __import__('qdrant_client'),
    'Sentence Transformers': lambda: __import__('sentence_transformers'),
}

for name, check in checks.items():
    try:
        check()
        print(f'  [OK] {name}')
    except Exception as e:
        errors.append(f'{name}: {e}')
        print(f'  [X] {name}: {e}')

print()
if errors:
    print(f'  Issues found: {len(errors)}')
else:
    print('  All modules verified!')
"

Write-Host ""

# ── DONE ─────────────────────────────────────────────────────

Write-Host "==================================================" -ForegroundColor Green
Write-Host "   Setup Complete!                                 " -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Edit .env and add your ANTHROPIC_API_KEY" -ForegroundColor White
Write-Host "     notepad .env" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Activate venv in new terminals:" -ForegroundColor White
Write-Host "     .\.venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Start the API server:" -ForegroundColor White
Write-Host "     uvicorn src.api.main:app --reload --port 8000" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Open in browser:" -ForegroundColor White
Write-Host "     API docs:  http://localhost:8000/docs" -ForegroundColor Gray
Write-Host "     Health:    http://localhost:8000/health" -ForegroundColor Gray
Write-Host "     Alerts:    http://localhost:8000/alerts" -ForegroundColor Gray
Write-Host ""
Write-Host "  5. Test with PowerShell:" -ForegroundColor White
Write-Host '     Invoke-RestMethod -Method Post -Uri "http://localhost:8000/alerts" `' -ForegroundColor Gray
Write-Host '       -ContentType "application/json" `' -ForegroundColor Gray
Write-Host '       -Body ''{"source":"test","data":{"event_type":"test","message":"hello"}}''' -ForegroundColor Gray
Write-Host ""
Write-Host "  Docker commands:" -ForegroundColor White
Write-Host "     docker compose ps        # Check status" -ForegroundColor Gray
Write-Host "     docker compose logs -f   # View logs" -ForegroundColor Gray
Write-Host "     docker compose down      # Stop all" -ForegroundColor Gray
Write-Host ""