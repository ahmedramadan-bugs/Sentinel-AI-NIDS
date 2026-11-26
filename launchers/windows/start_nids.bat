@echo off
title Sentinel-AI NIDS (Windows Support)
cd /d "%~dp0..\.."

set "PY_EXE="
if exist ".venv\Scripts\python.exe" (
    set "PY_EXE=.venv\Scripts\python.exe"
) else (
    python -c "import xgboost, sklearn, numpy, netmiko" >nul 2>&1
    if not errorlevel 1 (
        echo [1/2] Using existing system Python environment...
        set "PY_EXE=python"
    ) else (
        echo [1/3] Creating Python virtual environment...
        python -m venv .venv
        echo [2/3] Installing dependencies...
        .venv\Scripts\python.exe -m pip install -r requirements.txt
        set "PY_EXE=.venv\Scripts\python.exe"
    )
)

if not exist ".env" if exist ".env.example" (
    copy /Y ".env.example" ".env" >nul
)

echo Starting Sentinel-AI NIDS Dashboard on http://127.0.0.1:8080 ...
"%PY_EXE%" run_nids.py
pause
