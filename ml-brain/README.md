# ORBITAL SHIELD — ML Correlation Brain

> **Person 5 Module** | Smart India Hackathon 2026  
> Service runs on **port 8005** by default.

---

## What this module does

Four other modules each independently watch a different part of a simulated satellite ground station:

| Module | Source tag | What it watches |
|--------|------------|-----------------|
| Module 2 | `DOWNLINK` | Telemetry for spoofing / anomalies |
| Module 3 | `UPLINK` | Commands for unauthorized / malformed requests |
| Module 4 | `FIRMWARE` | Firmware update integrity |
| Module 4 | `ACCESS` | Operator login behaviour |

Each module produces its own independent security events. Individually, each event might look low-to-medium severity. **This module's job is to find when multiple separate events are actually connected** — same operator, same satellite, same time window — and reclassify them together as one higher-severity incident.

This module does **not** re-analyse raw telemetry, commands, or firmware. It only processes the structured event reports the other four modules have already produced. It is a **correlation and reasoning layer**, not a duplicate detector.

---

## Why this module has no enforcement power

**This is a deliberate security design decision, not a shortcut.**

The ML Correlation Brain operates in advisory-only mode: it produces flagged, explained, ranked incident reports that go to a human (CISO) for review via the audit/dashboard module. It never blocks a command, disables an uplink, revokes a session, or changes any system configuration by itself — even when its risk score exceeds the CRITICAL threshold.

The reason is simple: no automated system, however accurate, should have unilateral authority to interrupt satellite operations without a human in the loop. A false positive that auto-blocks an uplink during a critical orbital manoeuvre could be more damaging than the attack it was trying to prevent. By keeping enforcement authority entirely with human operators, we ensure that the system's mistakes are always recoverable and its actions always auditable. The model's role is to *surface signal*, not to *pull levers* — and that distinction is what makes it trustworthy enough to deploy in a safety-critical environment.

---

## Architecture

```
┌───────────────┐  POST /events/ingest   ┌─────────────────────────────────────────────────┐
│  DOWNLINK Mod │ ──────────────────────▶│                                                 │
│  UPLINK Mod   │ ──────────────────────▶│  ML Correlation Brain (port 8005)               │
│  FIRMWARE Mod │ ──────────────────────▶│                                                 │
│  ACCESS Mod   │ ──────────────────────▶│  ┌──────────────┐  ┌───────────────────────┐   │
└───────────────┘                        │  │ Event Store  │  │ Sliding Window (30m)  │   │
                                         │  │  (SQLite)    │  │  (in-memory, hot)     │   │
                                         │  └──────────────┘  └───────────────────────┘   │
                                         │         │                      │                │
                                         │         └──────────┬───────────┘                │
                                         │                    ▼                             │
                                         │  ┌─────────────────────────────────────────┐   │
                                         │  │  Rule Engine (YAML-driven, explainable) │   │
                                         │  │  RULE_001: cross_module_same_session     │   │
                                         │  │  RULE_002: escalating_severity_chain     │   │
                                         │  │  RULE_003: firmware_plus_access_anomaly  │   │
                                         │  │  RULE_004: multi_source_same_satellite   │   │
                                         │  │  RULE_005: high_confidence_critical_pair │   │
                                         │  └──────────────────┬──────────────────────┘   │
                                         │                     ▼                            │
                                         │  ┌─────────────────────────────────────────┐   │
                                         │  │  Risk Scoring (additive, explainable)   │   │
                                         │  │  ± ML Refiner (bounded, optional)       │   │
                                         │  └──────────────────┬──────────────────────┘   │
                                         │                     ▼                            │
                                         │  ┌─────────────────────────────────────────┐   │
                                         │  │  Incident Store (SQLite)                │   │
                                         └──┤  → POST to Audit Module (port 8006)     │   │
                                            │  → GET /correlations/active (dashboard) │   │
                                            └─────────────────────────────────────────┘   
```

---

## Quick Start

```powershell
# 1. Navigate into the module directory
cd ml-brain

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the API server
python main.py
# or:
uvicorn main:app --host 0.0.0.0 --port 8005 --reload

# 4. Open Swagger docs
# → http://localhost:8005/docs

# 5. Run standalone demo (no other services needed)
python tests/mock_events.py

# 6. Run tests
pytest tests/test_correlation.py -v
```

---

## Input Contract

All four upstream modules must `POST` to `/events/ingest` with this schema:

```json
{
  "event_id":      "EVT-100",
  "timestamp":     "2026-08-24T12:00:00Z",
  "source":        "DOWNLINK",
  "satellite_id":  "SAT-EO-01",
  "event_type":    "TELEMETRY_ANOMALY",
  "severity":      "HIGH",
  "confidence":    0.93,
  "description":   "Unexpected thermal increase",
  "action":        "REVIEW",
  "evidence":      {},
  "related_events": [],
  "operator_id":   "OP-02",
  "session_id":    "S123"
}
```

**Valid `source` values:** `DOWNLINK`, `UPLINK`, `FIRMWARE`, `ACCESS`  
**Valid `severity` values:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`  
**Valid `action` values:** `REVIEW`, `MONITOR`, `HUMAN_REVIEW`, `ALERT`, `LOG`

---

## Output Contract

### 1. Correlation incidents → forwarded to Audit module (Person 6)

```json
{
  "event_id":       "INC-001",
  "timestamp":      "2026-08-24T12:04:30Z",
  "source":         "ML_BRAIN",
  "event_type":     "CROSS_MODULE_ATTACK",
  "severity":       "CRITICAL",
  "confidence":     0.91,
  "description":    "Possible compromised operator session...",
  "related_events": ["EVT-100", "EVT-201", "EVT-401"],
  "action":         "HUMAN_REVIEW",
  "risk_score":     85
}
```

### 2. Dashboard API (Person 6 frontend)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/correlations/active` | List all open incidents |
| `GET` | `/correlations/{id}` | Full incident + contributing raw events |
| `GET` | `/brain/status` | Health + rule config + score weights |
| `POST` | `/brain/feedback` | CISO verdict on an incident |
| `POST` | `/brain/retrain` | Trigger threshold/model update |
| `GET` | `/brain/audit-log` | All BRAIN_CONFIG_UPDATED events |
| `GET` | `/brain/feedback-log` | All CISO feedback records |
| `GET` | `/events/recent` | Recently ingested raw events (debug) |

---

## Correlation Rules

Rules are defined in [`config/rules.yaml`](config/rules.yaml) — **editable without restarting the service**. Every change is config-version-tracked and visible via `GET /brain/status`.

| Rule ID | Name | Trigger | Output Type |
|---------|------|---------|-------------|
| RULE_001 | cross_module_same_session | 2+ sources, same `session_id`, within 5 min | CROSS_MODULE_ATTACK |
| RULE_002 | escalating_severity_chain | LOW→MEDIUM→HIGH on same satellite, within 10 min | ESCALATING_INCIDENT |
| RULE_003 | firmware_plus_access_anomaly | FIRMWARE + ACCESS events on same satellite, within 15 min | SUPPLY_CHAIN_RISK |
| RULE_004 | multi_source_same_satellite | 3+ modules fire on same satellite, within 10 min | MULTI_VECTOR_ATTACK |
| RULE_005 | high_confidence_critical_pair | 2+ HIGH/CRITICAL events, confidence ≥0.85, within 5 min | CRITICAL_THREAT_CLUSTER |

---

## Risk Scoring

All weights are in `config/rules.yaml` under `scoring:` — fully editable:

| Event Type | Base Score |
|-----------|------------|
| FIRMWARE_TAMPERING | +50 |
| UNAUTHORIZED_COMMAND | +35 |
| INTEGRITY_FAILURE | +35 |
| DATA_EXFILTRATION | +40 |
| COMMAND_INJECTION | +30 |
| TELEMETRY_ANOMALY | +25 |
| REPLAY_ATTACK | +25 |
| SUSPICIOUS_LOGIN | +20 |
| ACCESS_VIOLATION | +20 |
| SIGNAL_INTERFERENCE | +15 |
| Each extra module (beyond 1st) | +10 |

| Score | Severity |
|-------|---------|
| > 70 | CRITICAL |
| > 40 | HIGH |
| > 20 | MEDIUM |
| ≤ 20 | LOW |

---

## Self-Training / Feedback Loop

This is a **human-in-the-loop, scheduled retraining pattern** — not unsupervised learning.

```
1. [Always ON]  Rule engine + optional ML layer produce scored incidents
2. [CISO]       Reviews incidents on the dashboard → POST /brain/feedback
3. [Stored]     Verdicts go into feedback_log table (never deleted — audit trail)
4. [Scheduled]  POST /brain/retrain (nightly in production, manual for demo):
                  a) Widens time-window thresholds for rules with 3+ false positives
                  b) Retrains ML classifier if ≥5 labeled samples available
                  c) Validates new model on held-out data before replacing live model
                  d) Logs every change as BRAIN_CONFIG_UPDATED with before/after values
5. [Auditable]  GET /brain/audit-log shows the full history of every change
```

**The ML layer never:**
- Independently triggers an action
- Adjusts scores by more than ±15 points (cap in config)
- Deploys a new model silently
- Overwrites a human decision

---

## Folder Structure

```
ml-brain/
├── main.py                      # FastAPI app, all 9 endpoints
├── config/
│   └── rules.yaml               # ← All rules, weights, thresholds (edit live)
├── models/
│   ├── schemas.py               # Pydantic I/O schemas (API contract)
│   └── classifier.pkl           # (created after first retrain)
├── core/
│   ├── ingestion.py             # Event validation, storage, sliding window
│   ├── correlation_engine.py    # Rule evaluator (YAML-driven)
│   ├── scoring.py               # Additive risk scoring
│   ├── ml_refiner.py            # Optional ML layer (sklearn RandomForest)
│   └── feedback.py              # CISO feedback storage + retrain logic
├── db/
│   └── database.py              # SQLite schema, all CRUD helpers
├── tests/
│   ├── mock_events.py           # 5 demo scenarios, in-process or HTTP replay
│   └── test_correlation.py      # pytest test suite (9 test blocks)
├── requirements.txt
└── README.md                    # This file
```

---

## Demo Script (Live on Stage)

```powershell
# Terminal 1: Start the server
cd ml-brain
uvicorn main:app --port 8005 --reload

# Terminal 2: Run mock events (show correlation firing)
python tests/mock_events.py --replay --url http://localhost:8005

# Show active incidents
curl http://localhost:8005/correlations/active

# Show brain config (rules + weights)
curl http://localhost:8005/brain/status

# Submit CISO feedback
curl -X POST http://localhost:8005/brain/feedback \
  -H "Content-Type: application/json" \
  -d '{"incident_id":"INC-XXX","verdict":"FALSE_POSITIVE","reviewer":"ciso_demo","notes":"Test FP"}'

# Trigger retrain (show threshold change live)
curl -X POST http://localhost:8005/brain/retrain

# Check audit log (shows BRAIN_CONFIG_UPDATED)
curl http://localhost:8005/brain/audit-log
```

---

## Integration Notes for Teammates

- **Base URL**: `http://localhost:8005` (update if deploying remotely)
- **Audit endpoint**: Update `audit.endpoint` in `config/rules.yaml` to point to Person 6's service
- **Events**: Any of the 4 upstream modules can POST to `/events/ingest` at any time — events can arrive out of order
- **CORS**: Enabled for all origins — the dashboard can call this directly from the browser
- **Swagger**: `/docs` is always on — use it for integration testing and live demo

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| API Framework | FastAPI + uvicorn |
| Database | SQLite (WAL mode for concurrent access) |
| Config | YAML (pyyaml) — hot-reloadable |
| ML (optional) | scikit-learn RandomForestClassifier |
| Testing | pytest + FastAPI TestClient |
| Docs | FastAPI built-in Swagger (`/docs`) |
