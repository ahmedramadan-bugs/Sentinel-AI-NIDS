# Sentinel-AI NIDS — Windows Launcher
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "..\.."))

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "[1/3] Creating virtual environment (.venv)..." -ForegroundColor Cyan
    python -m venv .venv
}

Write-Host "[2/3] Installing/verifying Python dependencies..." -ForegroundColor Cyan
.\.venv\Scripts\python.exe -m pip install -q -r requirements.txt

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "[3/3] Starting Sentinel-AI NIDS at http://127.0.0.1:8080 ..." -ForegroundColor Green
.\.venv\Scripts\python.exe run_nids.py
