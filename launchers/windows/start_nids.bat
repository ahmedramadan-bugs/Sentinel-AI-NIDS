@echo off
title Sentinel-AI NIDS (Windows Support)
cd /d "%~dp0..\.."

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating Python virtual environment...
    python -m venv .venv
)

echo [2/3] Checking dependencies...
.venv\Scripts\python.exe -m pip install -q -r requirements.txt

if not exist ".env" if exist ".env.example" (
    copy /Y ".env.example" ".env" >nul
)

echo [3/3] Starting Sentinel-AI NIDS Dashboard on http://127.0.0.1:8080 ...
.venv\Scripts\python.exe run_nids.py
pause
