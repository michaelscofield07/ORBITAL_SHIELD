@echo off
echo ============================================================
echo ORBITAL SHIELD — Starting All Microservices (Standalone / No Docker)
echo ============================================================

echo Starting Simulator (Port 8000)...
start "Simulator [8000]" cmd /k "cd /d %~dp0simulator && python main.py"

echo Starting Downlink Engine (Port 8001)...
start "Downlink Engine [8001]" cmd /k "cd /d %~dp0downlink-engine && python run.py"

echo Starting Access Security (Port 8002)...
start "Access Security [8002]" cmd /k "cd /d %~dp0access-security && python main.py"

echo Starting Firmware Verifier (Port 8003)...
start "Firmware Verifier [8003]" cmd /k "cd /d %~dp0firmware-verifier && python main.py"

echo Starting Uplink Engine (Port 8004)...
start "Uplink Engine [8004]" cmd /k "cd /d %~dp0uplink-engine && python main.py"

echo Starting ML Brain (Port 8005)...
start "ML Brain [8005]" cmd /k "cd /d %~dp0ml-brain && python main.py"

echo Starting Audit Service (Port 8006)...
start "Audit Service [8006]" cmd /k "cd /d %~dp0audit-service && python -m uvicorn app:app --port 8006"

echo Starting Dashboard UI (Port 5173)...
start "Dashboard UI [5173]" cmd /k "cd /d %~dp0dashboard && npm run dev"

echo.
echo All services launched in separate windows!
echo Dashboard will be available at: http://localhost:5173
pause
