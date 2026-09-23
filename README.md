# 🛰️ ORBITAL SHIELD

> **Autonomous Multi-Layer Cyber Defense & ML Correlation System for Satellite Ground Stations & TT&C Infrastructure**  
> *Smart India Hackathon 2026*

---

## 🌟 Executive Overview

**ORBITAL SHIELD** is a unified, multi-layered cyber defense architecture specifically engineered for space segment communications, ground-station Telemetry, Tracking & Command (TT&C) operations, and satellite supply chains.

The platform continuously analyzes flight telemetry, telecommands, firmware updates, and operator credentials in real time. It correlates cross-module threat indicators using a deterministic rule engine combined with a human-in-the-loop Machine Learning (ML) refiner, generates automated **CERT-In compliant compliance reports** within statutory 6-hour windows, and records all activities in an immutable SHA-256 hash-chained audit ledger.

---

## 🏗️ Architecture & Port Map

```
                          ┌───────────────────────────┐
                          │   Simulator / Gateway     │
                          │        (Port 8000)        │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼──────────────────────────┐
           │ Telemetry                  │ Commands                 │ Firmware & Access
           ▼                            ▼                          ▼
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│   Downlink Engine    │    │    Uplink Engine     │    │  Access Security &   │
│     (Port 8001)      │    │     (Port 8004)      │    │  Firmware Verifier   │
│  - Isolation Forest  │    │  - HMAC-SHA256 Sign  │    │ (Ports 8002 & 8003)  │
│  - Telemetry Integ.  │    │  - RBAC & Anti-Replay│    │ - Cosign Verification│
└──────────┬───────────┘    └──────────┬───────────┘    └──────────┬───────────┘
           │                           │                           │
           │ POST /events/ingest       │ POST /events/ingest       │ POST /events/ingest
           └───────────────────────────┼───────────────────────────┘
                                       ▼
                       ┌───────────────────────────────┐
                       │     ML Correlation Brain      │
                       │          (Port 8005)          │
                       │  - Cross-Module Correlation   │
                       │  - Model 1 Incident Dossier   │
                       │  - CERT-In 6-Hour Reporting   │
                       │  - CISO Feedback & Retraining │
                       │  - Live SSE Event Stream      │
                       └───────────────┬───────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            ▼ Forward Incidents                                   ▼ Live Updates
┌───────────────────────────────┐                     ┌───────────────────────────────┐
│         Audit Service         │                     │     Mission Control UI        │
│          (Port 8006)          │                     │          (Port 5173)          │
│  - Hash-Chained Audit Ledger  │                     │  - SOC Threat Map & Feeds     │
│  - Merkle / Chain Verifier    │                     │  - CISO Incident Dossiers     │
│  - PDF Regulatory Reports     │                     │  - Live Module Health Strip   │
└───────────────────────────────┘                     └───────────────────────────────┘
```

### Official Port Allocation

| Microservice | Port | Path / Directory | Role & Key Responsibilities |
|---|---|---|---|
| **Simulator Gateway** | `8000` | `simulator/` | Flight software replay, telemetry streams, command dispatch, access generation |
| **Downlink Engine** | `8001` | `downlink-engine/` | Telemetry packet integrity validation & Isolation Forest behavioral anomaly detection |
| **Access Security** | `8002` | `access-security/` | Ground operator login telemetry, brute-force & credential compromise detection |
| **Firmware Verifier** | `8003` | `firmware-verifier/` | Supply-chain Cosign cryptographic signature verification & binary tampering detection |
| **Uplink Engine** | `8004` | `uplink-engine/` | Command validation, RBAC, HMAC-SHA256 signing, anti-replay counter checks |
| **ML Correlation Brain** | `8005` | `ml-brain/` | Multi-vector attack correlation, Model 1 forensic dossier, CERT-In compliance report, SSE stream |
| **Audit Service** | `8006` | `audit-service/` | Immutable SHA-256 hash-chained audit storage, PDF report generator, cryptographic verifier |
| **Dashboard UI** | `5173` | `dashboard/` | Real-time React/Vite SOC console, telemetry charts, CISO feedback, module health |

---

## 📡 Official Event Contract

All upstream security modules (`DOWNLINK`, `UPLINK`, `FIRMWARE`, `ACCESS`) automatically POST standardized findings to:
`POST http://localhost:8005/events/ingest`

```json
{
  "event_id": "EVT-DL-0001",
  "timestamp": "2026-09-23T11:40:00Z",
  "source": "DOWNLINK",
  "satellite_id": "SAT-EO-01",
  "event_type": "TELEMETRY_ANOMALY",
  "severity": "HIGH",
  "confidence": 0.94,
  "description": "Thermal node spike (72.0 C) exceeds nominal threshold [18.0, 28.0] C",
  "action": "REVIEW",
  "evidence": {
    "temperature": 72.0,
    "anomaly_score": -0.72
  },
  "related_events": [],
  "operator_id": "OP-02",
  "session_id": "S123"
}
```

### Normalization Rules:
- **Severity**: `INFO` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
- **Source**: `DOWNLINK` | `UPLINK` | `FIRMWARE` | `ACCESS` | `ML_BRAIN`
- **Action**: `REVIEW` | `MONITOR` | `HUMAN_REVIEW` | `ALERT` | `LOG`

---

## 🚀 Quickstart & Startup

### Option 1: One-Command Startup (Recommended)

#### Linux / macOS:
```bash
chmod +x start_all.sh
./start_all.sh
```

#### Windows (PowerShell):
```powershell
.\start_all.ps1
```

#### Windows (Command Prompt):
```cmd
start_all.bat
```

### Option 2: Docker Compose
```bash
docker compose up --build
```

---

## 🔬 End-to-End Verification & Demo Workflows

### 1. View Service Health Status
Verify that all 8 microservices are active:
```bash
curl -s http://localhost:8000/health | jq .
curl -s http://localhost:8001/downlink/health | jq .
curl -s http://localhost:8002/health | jq .
curl -s http://localhost:8003/health | jq .
curl -s http://localhost:8004/health | jq .
curl -s http://localhost:8005/brain/status | jq .
curl -s http://localhost:8006/health | jq .
```

### 2. Stream Live Telemetry via WebSocket
```bash
cd simulator && python demo_stream.py
```

### 3. Replay Simulated Cyber Attacks & View Incident Correlations
```bash
cd ml-brain
python tests/mock_events.py --replay --url http://localhost:8005
```

Query open correlated incidents:
```bash
curl -s http://localhost:8005/correlations/active | jq .
```

### 4. Fetch Model 1 Forensic Dossier & CERT-In Compliance Report
```bash
# Markdown Forensic Dossier
curl -s http://localhost:8005/correlations/{INCIDENT_ID}/document | jq -r .incident_document_md

# CERT-In 6-Hour Regulatory JSON Report
curl -s http://localhost:8005/correlations/{INCIDENT_ID}/cert-in | jq .
```

### 5. Submit CISO Feedback & Retrain
```bash
# Submit CISO verdict (CONFIRMED_REAL, FALSE_POSITIVE, RECTIFIED)
curl -X POST http://localhost:8005/brain/feedback \
  -H "Content-Type: application/json" \
  -d '{"incident_id": "INC-001", "verdict": "CONFIRMED_REAL", "reviewer": "CISO-TEAM"}'

# Trigger Retraining Cycle
curl -X POST http://localhost:8005/brain/retrain | jq .
```

### 6. Verify Audit Ledger Cryptographic Integrity
```bash
curl -s http://localhost:8006/audit/verify | jq .
```

---

## 👥 Hackathon Presentation & Jury Guide

For the full jury script, step-by-step walkthrough, and test cases, refer to:  
👉 **[FINAL_EXECUTION_AND_VERIFICATION_GUIDE.md](FINAL_EXECUTION_AND_VERIFICATION_GUIDE.md)**
