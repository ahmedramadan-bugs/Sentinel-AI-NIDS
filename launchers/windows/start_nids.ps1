# Sentinel-AI NIDS — Windows Launcher
$ErrorActionPreference = "Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "..\.."))

$pyExe = $null
if (Test-Path ".venv\Scripts\python.exe") {
    $pyExe = ".\.venv\Scripts\python.exe"
} else {
    $hasGlobal = $false
    try {
        python -c "import xgboost, sklearn, numpy, netmiko" 2>$null
        if ($LASTEXITCODE -eq 0) { $hasGlobal = $true }
    } catch {}

    if ($hasGlobal) {
        Write-Host "[1/2] Using existing system Python environment..." -ForegroundColor Cyan
        $pyExe = "python"
    } else {
        Write-Host "[1/3] Creating virtual environment (.venv)..." -ForegroundColor Cyan
        python -m venv .venv
        Write-Host "[2/3] Installing Python dependencies..." -ForegroundColor Cyan
        .\.venv\Scripts\python.exe -m pip install -r requirements.txt
        $pyExe = ".\.venv\Scripts\python.exe"
    }
}

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
}

Write-Host "Starting Sentinel-AI NIDS at http://127.0.0.1:8080 ..." -ForegroundColor Green
& $pyExe run_nids.py
