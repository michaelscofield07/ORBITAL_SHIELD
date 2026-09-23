#!/usr/bin/env bash
# ==============================================================================
# ORBITAL SHIELD — Unified Test Suite Runner
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

echo "======================================================================"
echo "           ORBITAL SHIELD — COMPREHENSIVE TEST SUITE                 "
echo "======================================================================"

TOTAL_PASS=0
FAILURES=0

run_suite() {
    local name="$1"
    local dir="$2"
    echo -e "\n▶ Running tests for: $name ($dir)"
    if (cd "$dir" && PYTHONPATH=. pytest -q); then
        echo "  ✅ $name tests PASSED"
    else
        echo "  ❌ $name tests FAILED"
        FAILURES=$((FAILURES + 1))
    fi
}

run_suite "Simulator (Person 1)" "simulator"
run_suite "Downlink Security Engine (Person 2)" "downlink-engine"
run_suite "Access Security & RBAC (Person 3)" "access-security"
run_suite "Firmware Verifier (Person 4)" "firmware-verifier"
run_suite "Uplink Security Engine (Person 5)" "uplink-engine"
run_suite "ML Correlation Brain (Person 6 / Models 1, 2, 3)" "ml-brain"
run_suite "Audit & Compliance Service" "audit-service"

echo -e "\n▶ Verifying Dashboard UI build..."
if (cd dashboard && npm run build > /dev/null 2>&1); then
    echo "  ✅ Dashboard build PASSED"
else
    echo "  ❌ Dashboard build FAILED"
    FAILURES=$((FAILURES + 1))
fi

# If backend services are online, run the E2E verification suite
if curl -s http://localhost:8005/ > /dev/null 2>&1; then
    echo -e "\n▶ Running End-to-End Integration Suite..."
    if python scripts/test_e2e.py; then
        echo "  ✅ E2E Integration PASSED"
    else
        echo "  ❌ E2E Integration FAILED"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo -e "\nℹ️  Backend services not currently running on port 8005; skipping live E2E check."
    echo "   (Start services with ./start_all.sh to run full live E2E tests)"
fi

echo -e "\n======================================================================"
if [ $FAILURES -eq 0 ]; then
    echo "  🏆 ALL TESTS & BUILDS PASSED CLEANLY! Ready for SIH 2026 Demo."
    echo "======================================================================"
    exit 0
else
    echo "  💥 $FAILURES TEST SUITE(S) FAILED. Please inspect above logs."
    echo "======================================================================"
    exit 1
fi
