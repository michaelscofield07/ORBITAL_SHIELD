# ORBITAL SHIELD — Access Security Module (Module 4)

Ground Station & Operator Access Security Anomaly Detection Engine for ORBITAL SHIELD.

This module monitors, analyzes, and flags suspicious ground station / operator access activities (logins, command executions, role changes, untrusted devices, and off-hour access).

---

## 🏗️ Architecture

The module uses a strictly decoupled 3-tier architecture:

```
[ Mock JSON / Person 1 Access API ]
               │
               ▼
      [ Input Adapter Layer ]
  (BaseInputAdapter / MockJSONInputAdapter / Person1APIAdapterPlaceholder)
               │
               ▼
    [ Access Security Engine ]
  (Rule-based explainable detection logic)
               │
               ▼
   [ Security Event Generator ]
  (Canonical SecurityEvent Schema Output)
               │
       ┌───────┴───────┐
       ▼               ▼
 [ Person 5 ]    [ Person 6 ]
  ML Brain        Audit / UI
(port 8005)
```

1. **Input Adapter Layer (`core/adapter.py`)**: Abstract layer mapping external payloads (Mock JSON or Person 1's live API) to normalized `AccessLogRecord` objects.
2. **Access Security Engine (`core/engine.py`)**: Explainable, rule-based detection engine evaluating access records against 6 security rules.
3. **Security Event Generation Layer (`core/event_generator.py`)**: Converts detection results into canonical `SecurityEvent` payloads matching Person 5's ML Brain (`IncomingEvent`) and Person 6's Audit layer.

---

## 🚨 Detectable Anomaly Scenarios

1. **Normal Successful Login (`AUTHENTICATION_SUCCESS / INFO`)**: Standard login from a trusted device during normal UTC operating hours.
2. **Repeated Failed Logins (`BRUTE_FORCE / HIGH or CRITICAL`)**: Detects multiple login failures for a user or IP address within a tracking window.
3. **Suspicious Login Time (`SUSPICIOUS_LOGIN_TIME / MEDIUM`)**: Detects logins originating outside configured standard UTC operating hours (e.g. 06:00 to 21:00 UTC).
4. **Unknown / Untrusted Device (`UNKNOWN_DEVICE / MEDIUM`)**: Flags access attempts from devices not present on the trusted ground station device whitelist.
5. **Privilege Escalation (`PRIVILEGE_ESCALATION / CRITICAL`)**: Detects unauthorized or sudden role transitions (e.g. `operator` -> `sysadmin`).
6. **Suspicious Access to Sensitive Commands/Resources (`UNAUTHORIZED_COMMAND / CRITICAL`)**: Flags execution of sensitive actions (e.g., `PAYLOAD_SHUTDOWN`, `PURGE_LOGS`, `ORBIT_DEVIATION`) or access to restricted satellite resources.

---

## ⚡ Quick Start

### 1. Installation

From the project root or module folder, install dependencies:

```bash
pip install -r access-security/requirements.txt
```

### 2. Run Demonstration Script

Run the standalone demo script showcasing all 6 scenarios:

```bash
python access-security/demo.py
```

### 3. Run Unit Tests

Execute the unit test suite:

```bash
pytest access-security/tests
```

### 4. Launch FastAPI Service

Start the Access Security microservice on port 8001:

```bash
python access-security/main.py
```

Interactive OpenAPI Swagger Docs available at: `http://localhost:8001/docs`

---

## 🔌 API Endpoints

- `GET /health`: Module status, engine config, and ML Brain connection status.
- `POST /access/analyze`: Analyze custom list of access records.
- `GET /access/events`: Retrieve cached/generated security events.
- `POST /access/mock/run`: Execute complete analysis on `mock_access_logs.json`.

---

## 🔁 Replacing Mock Data with Person 1's Live API

To connect Person 1's real simulated access API when available:

1. Open `access-security/core/adapter.py`.
2. Update `Person1APIAdapterPlaceholder.fetch_records()` with Person 1's API endpoint URL and authentication header.
3. In `main.py` or your integration pipeline, instantiate `Person1APIAdapterPlaceholder` instead of `MockJSONInputAdapter`.
4. **No changes are required in `engine.py` or `event_generator.py`.**

---

## 🧠 Integration Specifications

### Person 5 (ML Brain)
- **Endpoint**: `POST http://localhost:8005/events/ingest`
- **Contract**: Accepts `SecurityEvent` objects with `source="ACCESS"`.
- **Fault Tolerance**: If ML Brain is offline, Access Security logs `[WARNING] ML Brain unavailable — event generated locally.` and preserves event locally without crashing.

### Person 6 (Audit & Dashboard)
- **Contract**: Reads canonical `SecurityEvent` JSON array via `GET http://localhost:8001/access/events`.
