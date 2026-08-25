# ORBITAL SHIELD — Master Execution, Simulation & Verification Guide

This document provides the complete, authoritative guide to running, simulating, and verifying the integrated **ORBITAL SHIELD** spacecraft security ecosystem.

---

## 1. System Architecture & Port Mapping

| Service Name | Port | Description | Launch Command |
|---|---|---|---|
| **Simulator Gateway** | `8000` | Satellite Flight Software & Ground Gateway | `cd simulator && python main.py` |
| **Downlink Telemetry Engine** | `8001` | Telemetry Integrity & Anomaly Detector | `cd downlink-engine && python run.py` |
| **Access Security** | `8002` | Operator & Ground Station Access Control | `cd access-security && python main.py` |
| **Firmware Verifier** | `8003` | Supply Chain & Binary Signature Checks | `cd firmware-verifier && python main.py` |
| **Uplink Engine** | `8004` | Command RBAC, Replay Defense & Signing | `cd uplink-engine && python main.py` |
| **ML Correlation Brain** | `8005` | Cross-Module Correlation, SSE & Retraining | `cd ml-brain && python main.py` |
| **Audit Service** | `8006` | Hash-Chained Audit Log & Report Generator | `cd audit-service && python -m uvicorn app:app --port 8006` |
| **Dashboard UI** | `5173` | Modern Mission Control Operations UI | `cd dashboard && npm run dev` |

---

## 2. Integration Verification Summary

All 11 critical integration fixes are active:
- ✅ **B1–B4 (Port Alignment)**: All services default to global ports (8000–8006, 5173).
- ✅ **B5 & B8 (Schema Normalization)**:
  - Uplink `CommandAction` (`BLOCK/HOLD/ALLOW`) maps to ML Brain `ActionType` (`ALERT/HUMAN_REVIEW/LOG`).
  - Access Security `SeverityLevel` (`INFO`) maps to ML Brain `SeverityLevel` (`LOW`).
- ✅ **B6–B9 (Bindings & Endpoints)**: Simulator binds to `0.0.0.0`, Uplink includes executable `__main__` entry point.
- ✅ **B10–B11 (Audit Forwarding)**: Access Security and Firmware Verifier asynchronously forward all security events to the Audit Service.
- ✅ **SSE Health Broadcast**: ML Brain broadcasts live `/brain/stream` events to the UI's `ModuleHealthStrip`.
- ✅ **CISO Feedback & Retraining**: Dashboard CISO verdict buttons directly hit `/brain/feedback` and trigger `/brain/retrain`.

---

## 3. How to Run the Project

### Option A: Standalone Python & Node (Recommended — No Docker Required)

#### 1. One-Click Launcher
From the repository root (`ORBITAL_SHIELD`), run the launcher script:

* **PowerShell**:
  ```powershell
  .\start_all.ps1
  ```
* **Command Prompt**:
  ```cmd
  start_all.bat
  ```

This will automatically open 8 separate terminal windows, one for each microservice and the dashboard UI.

#### 2. Manual Terminal Launch (If running individually)
If you prefer running services manually, open 8 terminals in the root directory:

```bash
# Terminal 1: Simulator Gateway
cd simulator && python main.py

# Terminal 2: Downlink Telemetry Engine
cd downlink-engine && python run.py

# Terminal 3: Access Security
cd access-security && python main.py

# Terminal 4: Firmware Verifier
cd firmware-verifier && python main.py

# Terminal 5: Uplink Command Engine
cd uplink-engine && python main.py

# Terminal 6: ML Correlation Brain
cd ml-brain && python main.py

# Terminal 7: Audit Service
cd audit-service && python -m uvicorn app:app --port 8006

# Terminal 8: Mission Control Dashboard UI
cd dashboard && npm run dev
```

---

### Option B: Containerized Execution (Docker Compose)

> **Prerequisite**: Ensure **Docker Desktop** is open and running (Engine Status: Green / Running).

From the root of the repository:

```bash
# Build and start all 7 microservices + UI in Docker containers:
docker compose up --build
```

---

## 4. End-to-End Simulation & Verification Walkthrough

Follow these steps to demonstrate the complete threat detection, correlation, and retraining loop to evaluators or stakeholders:

### Step 1: Open Mission Control UI
Open your web browser and go to:
👉 **`http://localhost:5173`**

Observe the top **MODULE HEALTH** strip. The pills (`DOWNLINK`, `UPLINK`, `FIRMWARE`, `ACCESS`) connect via Server-Sent Events (SSE) to `/brain/stream`.

### Step 2: Trigger Threat Scenarios
1. Click the **SCENARIO CONTROL** tab in the top navigation.
2. Under **TRIGGER SCENARIO**, choose a scenario:
   * **`TELEMETRY_ANOMALY`**: Simulates thermal/power state spikes in spacecraft telemetry.
   * **`MESSAGE_REPLAY`**: Simulates a replay attack against satellite telecommand uplink.
   * **`MESSAGE_BURST`**: Simulates command flooding rate-limit violations.
3. Click **TRIGGER SCENARIO**.

### Step 3: Observe Live Correlation & Module Health
1. Switch back to the **SOC DASHBOARD** tab.
2. Watch the **MODULE HEALTH** strip at the top—matching module pills will glow green in real time as events hit the system.
3. Scroll down to **ACTIVE INCIDENTS**. The ML Brain will correlate the events and generate a unified incident card (e.g., *Multi-Vector Threat Detected* or *Telemetry Thermal Anomaly*).

### Step 4: Investigate & Download Audit PDF
1. Click **INVESTIGATE** on an active incident.
2. Review the correlated multi-source event timeline.
3. Click **DOWNLOAD REPORT** to pull the cryptographically signed, immutable PDF audit report from the Audit Service (`port 8006`).

### Step 5: CISO Review & Model Retraining
1. In the header top-right, click **ROLE: SOC_ANALYST** to toggle your role to **CISO**.
2. Open an incident modal and select your CISO verdict:
   * **CONFIRM REAL**: Validates the anomaly as a genuine security threat.
   * **FALSE POSITIVE**: Marks the event as harmless baseline noise.
3. Scroll down to the **CISO — ML BRAIN RETRAIN CYCLE** panel.
4. Click **RUN RETRAIN CYCLE**.
5. Verify the live feedback output:
   * **`ML RETRAINED`**: `TRUE ✓`
   * **`ML ACCURACY`**: Updated percentage (e.g., `94.2%`)
   * **`THRESHOLDS CHANGED`**: Real-time adjustment log showing how detection sensitivities were updated.

---

## 5. Troubleshooting & Health Verification

You can verify any microservice's health independently via HTTP GET:

| Service | Health Check Endpoint | Expected Status |
|---|---|---|
| Simulator | `http://localhost:8000/health` | `{"status": "HEALTHY", "module": "simulator"}` |
| Downlink Engine | `http://localhost:8001/downlink/health` | `{"status": "HEALTHY", "module": "downlink-engine"}` |
| Access Security | `http://localhost:8002/health` | `{"status": "HEALTHY", "module": "access_security"}` |
| Firmware Verifier | `http://localhost:8003/health` | `{"status": "HEALTHY", "module": "firmware_verification"}` |
| Uplink Engine | `http://localhost:8004/health` | `{"status": "HEALTHY", "module": "uplink_security_engine"}` |
| ML Brain | `http://localhost:8005/` | `{"status": "OK", "service": "ORBITAL SHIELD..."}` |
| Audit Service | `http://localhost:8006/health` | `{"status": "HEALTHY", "service": "audit"}` |
