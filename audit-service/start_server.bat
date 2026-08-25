@echo off
echo Starting Orbital Shield Audit Service...
python -m uvicorn app:app --reload --port 8006
pause
