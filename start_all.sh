#!/usr/bin/env bash
# ==============================================================================
# ORBITAL SHIELD — Master Microservices Launcher (Linux / macOS)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

LOGS_DIR="$ROOT_DIR/.logs"
mkdir -p "$LOGS_DIR"

echo "============================================================"
echo "  ORBITAL SHIELD — Starting All Microservices (No Docker)   "
echo "============================================================"

# Resolve Python runner
PYTHON_BIN="python3"
if [ -d "$ROOT_DIR/.venv" ]; then
    echo "Using virtual environment at $ROOT_DIR/.venv"
    source "$ROOT_DIR/.venv/bin/activate"
    PYTHON_BIN="python"
fi

PIDS=()

cleanup() {
    echo ""
    echo "Shutting down ORBITAL SHIELD microservices..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    echo "All services stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

echo "[1/8] Starting Simulator Gateway [Port 8000]..."
(cd "$ROOT_DIR/simulator" && $PYTHON_BIN main.py) > "$LOGS_DIR/simulator.log" 2>&1 &
PIDS+=($!)

echo "[2/8] Starting Downlink Engine [Port 8001]..."
(cd "$ROOT_DIR/downlink-engine" && $PYTHON_BIN run.py) > "$LOGS_DIR/downlink.log" 2>&1 &
PIDS+=($!)

echo "[3/8] Starting Access Security [Port 8002]..."
(cd "$ROOT_DIR/access-security" && $PYTHON_BIN main.py) > "$LOGS_DIR/access_security.log" 2>&1 &
PIDS+=($!)

echo "[4/8] Starting Firmware Verifier [Port 8003]..."
(cd "$ROOT_DIR/firmware-verifier" && $PYTHON_BIN main.py) > "$LOGS_DIR/firmware_verifier.log" 2>&1 &
PIDS+=($!)

echo "[5/8] Starting Uplink Engine [Port 8004]..."
(cd "$ROOT_DIR/uplink-engine" && $PYTHON_BIN main.py) > "$LOGS_DIR/uplink.log" 2>&1 &
PIDS+=($!)

echo "[6/8] Starting ML Correlation Brain [Port 8005]..."
(cd "$ROOT_DIR/ml-brain" && $PYTHON_BIN main.py) > "$LOGS_DIR/ml_brain.log" 2>&1 &
PIDS+=($!)

echo "[7/8] Starting Audit Service [Port 8006]..."
(cd "$ROOT_DIR/audit-service" && $PYTHON_BIN -m uvicorn app:app --port 8006 --host 0.0.0.0) > "$LOGS_DIR/audit_service.log" 2>&1 &
PIDS+=($!)

echo "[8/8] Starting Mission Control Dashboard [Port 5173]..."
(cd "$ROOT_DIR/dashboard" && npm run dev -- --host 0.0.0.0) > "$LOGS_DIR/dashboard.log" 2>&1 &
PIDS+=($!)

echo ""
echo "All 8 microservices initiated!"
echo "Logs are available in: $LOGS_DIR/"
echo ""
echo "Port Map:"
echo " - Simulator Gateway     : http://localhost:8000"
echo " - Downlink Engine       : http://localhost:8001"
echo " - Access Security       : http://localhost:8002"
echo " - Firmware Verifier     : http://localhost:8003"
echo " - Uplink Engine         : http://localhost:8004"
echo " - ML Correlation Brain  : http://localhost:8005"
echo " - Audit Service         : http://localhost:8006"
echo " - Dashboard UI          : http://localhost:5173"
echo ""
echo "Press Ctrl+C to terminate all services."

# Wait indefinitely for background children
wait
