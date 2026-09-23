# ORBITAL SHIELD — PowerShell Start All Script (Standalone / No Docker)
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "ORBITAL SHIELD — Starting All Microservices (No Docker)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$rootDir = $PSScriptRoot

Write-Host "Starting Simulator (Port 8000)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\simulator'; python main.py"

Write-Host "Starting Downlink Engine (Port 8001)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\downlink-engine'; python run.py"

Write-Host "Starting Access Security (Port 8002)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\access-security'; python main.py"

Write-Host "Starting Firmware Verifier (Port 8003)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\firmware-verifier'; python main.py"

Write-Host "Starting Uplink Engine (Port 8004)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\uplink-engine'; python main.py"

Write-Host "Starting ML Brain (Port 8005)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\ml-brain'; python main.py"

Write-Host "Starting Audit Service (Port 8006)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\audit-service'; python -m uvicorn app:app --port 8006"

Write-Host "Starting Dashboard UI (Port 5173)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\dashboard'; npm run dev"

Write-Host ""
Write-Host "All 8 services launched in separate windows!" -ForegroundColor Yellow
Write-Host "Dashboard will be available at: http://localhost:5173" -ForegroundColor Yellow
