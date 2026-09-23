#!/usr/bin/env python3
"""
scripts/verify_stack.py
Launches all 7 backend services, waits for healthy status, runs scripts/test_e2e.py, and cleans up.
"""
import os
import sys
import time
import subprocess
import httpx
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = ROOT_DIR / ".logs"
LOGS_DIR.mkdir(exist_ok=True)

PYTHON_BIN = sys.executable

SERVICES = [
    {
        "name": "simulator",
        "port": 8000,
        "health": "http://127.0.0.1:8000/health",
        "cwd": ROOT_DIR / "simulator",
        "cmd": [PYTHON_BIN, "main.py"],
        "log": LOGS_DIR / "simulator.log"
    },
    {
        "name": "downlink-engine",
        "port": 8001,
        "health": "http://127.0.0.1:8001/downlink/health",
        "cwd": ROOT_DIR / "downlink-engine",
        "cmd": [PYTHON_BIN, "run.py"],
        "log": LOGS_DIR / "downlink.log"
    },
    {
        "name": "access-security",
        "port": 8002,
        "health": "http://127.0.0.1:8002/health",
        "cwd": ROOT_DIR / "access-security",
        "cmd": [PYTHON_BIN, "main.py"],
        "log": LOGS_DIR / "access_security.log"
    },
    {
        "name": "firmware-verifier",
        "port": 8003,
        "health": "http://127.0.0.1:8003/health",
        "cwd": ROOT_DIR / "firmware-verifier",
        "cmd": [PYTHON_BIN, "main.py"],
        "log": LOGS_DIR / "firmware_verifier.log"
    },
    {
        "name": "uplink-engine",
        "port": 8004,
        "health": "http://127.0.0.1:8004/health",
        "cwd": ROOT_DIR / "uplink-engine",
        "cmd": [PYTHON_BIN, "main.py"],
        "log": LOGS_DIR / "uplink.log"
    },
    {
        "name": "ml-brain",
        "port": 8005,
        "health": "http://127.0.0.1:8005/",
        "cwd": ROOT_DIR / "ml-brain",
        "cmd": [PYTHON_BIN, "main.py"],
        "log": LOGS_DIR / "ml_brain.log"
    },
    {
        "name": "audit-service",
        "port": 8006,
        "health": "http://127.0.0.1:8006/health",
        "cwd": ROOT_DIR / "audit-service",
        "cmd": [PYTHON_BIN, "-m", "uvicorn", "app:app", "--port", "8006", "--host", "0.0.0.0"],
        "log": LOGS_DIR / "audit_service.log"
    }
]

def main():
    procs = []
    print("=" * 70)
    print("ORBITAL SHIELD — Launching All 7 Backend Services for Integration Test")
    print("=" * 70)

    try:
        for svc in SERVICES:
            print(f"[*] Starting {svc['name']} on port {svc['port']}...")
            log_f = open(svc["log"], "w")
            p = subprocess.Popen(
                svc["cmd"],
                cwd=svc["cwd"],
                stdout=log_f,
                stderr=subprocess.STDOUT
            )
            procs.append((svc, p, log_f))

        # Wait for all services to be healthy
        client = httpx.Client(timeout=3.0)
        max_wait = 30
        start_time = time.time()
        print("\n[*] Waiting for all 7 services to become healthy...")

        all_healthy = False
        while time.time() - start_time < max_wait:
            unhealthy = []
            for svc in SERVICES:
                try:
                    r = client.get(svc["health"])
                    if r.status_code != 200:
                        unhealthy.append(f"{svc['name']} (status {r.status_code})")
                except Exception as e:
                    unhealthy.append(f"{svc['name']} ({type(e).__name__})")

            if not unhealthy:
                all_healthy = True
                break
            time.sleep(1)

        if not all_healthy:
            print(f"❌ Timed out waiting for services: {', '.join(unhealthy)}")
            sys.exit(1)

        print("✅ All 7 backend services are healthy and online!")

        # Run E2E test script
        print("\n" + "=" * 70)
        print("Executing scripts/test_e2e.py...")
        print("=" * 70 + "\n")
        e2e_res = subprocess.run([PYTHON_BIN, str(ROOT_DIR / "scripts" / "test_e2e.py")])
        if e2e_res.returncode != 0:
            print(f"❌ test_e2e.py failed with returncode {e2e_res.returncode}")
            sys.exit(e2e_res.returncode)

        print("\n✅ End-to-end integration verified successfully!")

    finally:
        print("\n[*] Shutting down services...")
        for svc, p, log_f in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                p.kill()
            try:
                log_f.close()
            except Exception:
                pass
        print("[*] All services terminated cleanly.")

if __name__ == "__main__":
    main()
