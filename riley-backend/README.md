# Riley — AI False Positive Slayer 🔪

> Riley automatically identifies, tags, and suppresses false positives using AI pattern recognition and analyst feedback loops. Built for lean security teams that can't afford to drown in noise.

---

## The Problem

Security teams get **2,000+ alerts daily** and waste **14+ hours/week** investigating false positives. Riley cuts through the noise with a three-layer hybrid scoring engine: deterministic rules → learned patterns → LLM enrichment (gpt-4o-mini).

---

## Architecture

```
Incoming Alert
      │
      ▼
┌─────────────────────────────────────────────┐
│  Layer 1: Rules Engine (deterministic, fast) │
│  • IT Ops + PowerShell + biz hours → +40%   │
│  • Threat intel score > 70 → −40%           │
│  • Critical alert at 2am → −30%             │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Layer 2: Pattern Matching (self-learning)   │
│  • Jaccard similarity vs LearnedPatterns DB  │
│  • Weighted by pattern confidence & hits     │
│  • Confidence recalculated on every verdict  │
└────────────────────┬────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Layer 3: LLM (OpenAI gpt-4o-mini)          │
│  • Only fires for ambiguous scores           │
│  • Returns {score, reason, suggested_action} │
│  • Falls back to mock when no API key set    │
└────────────────────┬────────────────────────┘
                     │
                     ▼
         FP Confidence Score (0–100)
                     │
        ┌────────────┴────────────┐
       ≥85%                   60–84%               <60%
   AUTO_SUPPRESS         LOW_PRIORITY_REVIEW      ESCALATE
  (status=fp,           (tag: low_priority,     (tag: escalate,
  webhook fires)         queued for review)      notify analyst)
```

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — set OPENAI_API_KEY if you have one (optional)

# 2. Start everything
docker-compose up --build

# 3. API is live
open http://localhost:8000/docs
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/alerts` | Submit alert for Riley to triage |
| `GET` | `/api/v1/alerts` | List alerts (filter by status, severity, source) |
| `GET` | `/api/v1/alerts/{id}` | Get single alert with FP score |
| `POST` | `/api/v1/feedback/{alert_id}` | Submit analyst verdict → triggers learning |
| `GET` | `/api/v1/feedback/{alert_id}` | Get all feedback for an alert |
| `POST` | `/api/v1/users` | Create analyst user |
| `GET` | `/api/v1/stats` | Dashboard brag sheet (KPIs + accuracy trend) |
| `POST` | `/api/v1/stats/digest` | Fire daily Slack/Discord digest immediately |
| `POST` | `/api/v1/simulate` | Run accuracy benchmark with labelled mock alerts |
| `GET` | `/api/v1/patterns` | Browse Riley's learned pattern library |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | Swagger UI (auto-generated) |

---

## Submit Your First Alert

```bash
curl -X POST http://localhost:8000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source_system": "crowdstrike",
    "alert_type": "powershell_execution",
    "severity": "high",
    "raw_data": {
      "username": "jsmith",
      "hostname": "dc01.corp.local",
      "command": "powershell.exe -ExecutionPolicy Bypass -File backup.ps1",
      "src_ip": "10.0.1.5"
    }
  }'
```

Riley responds with the alert ID. Poll `GET /api/v1/alerts/{id}` to see the score (background processing takes ~200ms).

---

## Submit Analyst Feedback (Powers the Learning Loop)

```bash
curl -X POST http://localhost:8000/api/v1/feedback/1 \
  -H "Content-Type: application/json" \
  -d '{
    "analyst_id": 1,
    "verdict": "fp",
    "comment": "This is the nightly IT Ops backup script — safe to suppress."
  }'
```

Every verdict immediately:
1. Updates alert status
2. Extracts normalised alert signature (IPs/domains/timestamps stripped)
3. Upserts into `LearnedPatterns` with incremented confidence
4. Recalculates pattern weights

Riley gets smarter on every verdict.

---

## Run Accuracy Simulation

```bash
curl -X POST http://localhost:8000/api/v1/simulate | python3 -m json.tool
```

Runs 10 labelled mock alerts and returns accuracy metrics:

```json
{
  "summary": {
    "total_alerts": 10,
    "correct": 8,
    "accuracy_pct": 80.0,
    "fp_recall": 83.3,
    "verdict": "🟢 Riley is production-ready"
  }
}
```

---

## Run Tests

```bash
# Install dependencies (if not using Docker)
pip install -r requirements.txt

# Run tests (uses SQLite in-memory — no Postgres needed)
pytest tests/ -v
```

Expected output:
```
tests/test_fp_scorer.py::test_business_hours_weekday_9am PASSED
tests/test_fp_scorer.py::test_itops_powershell_fires PASSED
tests/test_fp_scorer.py::test_threat_intel_high_reduces_score PASSED
tests/test_fp_scorer.py::test_score_alert_itops_returns_high_fp_confidence PASSED
tests/test_fp_scorer.py::test_score_alert_threat_intel_returns_low_fp_confidence PASSED
... (12 tests total)
```

---

## Configure Webhooks

Add to `.env`:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/.../...
```

Then trigger the daily digest:
```bash
curl -X POST http://localhost:8000/api/v1/stats/digest
```

---

## FP Threshold Tuning

Edit `.env` to tune Riley's aggressiveness:

```env
FP_AUTO_SUPPRESS_THRESHOLD=85.0   # > this → auto-close as FP (default 85)
FP_LOW_PRIORITY_THRESHOLD=60.0    # > this → tag for review queue (default 60)
```

Start conservative (90/70) and lower thresholds as Riley's pattern library grows.

---

## Project Structure

```
riley-backend/
├── app/
│   ├── main.py                  # FastAPI app, lifespan, middleware
│   ├── config.py                # Settings (pydantic-settings + .env)
│   ├── database.py              # Async SQLAlchemy engine + session
│   ├── models/
│   │   ├── alert.py             # Alert table
│   │   ├── feedback.py          # AnalystFeedback table
│   │   ├── pattern.py           # LearnedPatterns table
│   │   └── user.py              # User table
│   ├── schemas/                 # Pydantic I/O schemas
│   ├── services/
│   │   ├── fp_scorer.py         # 🧠 Main scoring engine (3-layer hybrid)
│   │   ├── enrichment.py        # AD / Asset / ThreatIntel lookups (mocked)
│   │   ├── pattern_engine.py    # Signature extraction + pattern matching
│   │   ├── llm_service.py       # OpenAI gpt-4o-mini integration + mock
│   │   └── webhook_service.py   # Slack / Discord notifications
│   ├── api/v1/
│   │   ├── alerts.py            # Alert CRUD + Riley pipeline trigger
│   │   ├── feedback.py          # Analyst verdict endpoint
│   │   ├── stats.py             # Dashboard KPIs + digest trigger
│   │   ├── simulate.py          # Accuracy benchmark
│   │   ├── patterns.py          # Pattern library browser
│   │   └── users.py             # User management
│   └── core/
│       ├── exceptions.py        # Custom exception types
│       └── logging.py           # structlog setup
├── tests/
│   ├── conftest.py              # In-memory SQLite fixtures
│   └── test_fp_scorer.py        # 12 unit + integration tests
├── docker-compose.yml           # Postgres + Redis + API
├── Dockerfile                   # Non-root sentinel user, healthcheck
├── requirements.txt
├── .env.example
└── README.md
```

---

## Week 1 Brag Sheet Template

Track these metrics and post to LinkedIn/Twitter:

```
🤖 Riley Week 1 Stats

📊 Alerts processed:     ____
🛡️  False positives blocked: ____  
⏱️  Analyst hours saved:  ____ hrs
🎯  Accuracy rate:        ____%
🧠  Patterns learned:     ____
💤  Auto-suppressed:       ____ (zero analyst touch)

"Riley saved my team X hours this week. 
  That's X pizza lunches worth of analyst time."

#SOC #SecurityAutomation #FalsePositive #AI #CyberSecurity
```

Get your numbers from: `GET /api/v1/stats → brag_sheet`

---

## Roadmap

- [ ] Replace mock enrichment with real AD/Okta API
- [ ] SOAR integration (Splunk SOAR, Palo Alto XSOAR)
- [ ] Multi-tenant support
- [ ] MITRE ATT&CK tagging on all alerts
- [ ] LangChain agent for autonomous investigation
- [ ] Weekly accuracy trend charts API
- [ ] Analyst leaderboard (who catches the most TPs?)

---

Built with FastAPI · PostgreSQL · Redis · OpenAI · structlog · Love ❤️
