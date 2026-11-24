# Sentinel-AI NIDS — Handoff & Implementation Plan

> **Purpose:** This document is the single source of truth for organizing, simplifying, upgrading, and maintaining `p2 - Copy` for GitHub and graduation committee presentation. If any session stops mid-work, the next developer or AI agent should read this file and continue from the next unchecked `[ ]` item.

---

## 1. Repository Structure (Target for GitHub)

```text
p2 - Copy/
├── README.md                  # Root guide explaining the project, team setup, & OS folders
├── HANDOFF_PLAN.md            # This handoff & architecture checklist
├── .gitignore                 # Ignores .venv, __pycache__, *.db, runtime logs, etc.
├── Linux_Support/             # Full NIDS project configured for Linux (Suricata + iptables/nftables)
│   ├── start_nids.sh
│   ├── start_nids_live_demo.sh
│   ├── stop_nids.sh
│   ├── NIDS.desktop
│   └── ... (AI/, collectors/, nids/, response_engine/, suricata/, tests/, web/, run_nids.py)
└── Windows_Support/           # Full NIDS project configured for Windows (dry-run/netsh + PowerShell/Batch)
    ├── start_nids.bat
    ├── start_nids.ps1
    └── ... (AI/, collectors/, nids/, response_engine/, suricata/, tests/, web/, run_nids.py)
```

---

## 2. Core Architecture (Student-Friendly)

- **Backend:** Pure Python `http.server.ThreadingHTTPServer` in `nids/dashboard.py` + `nids/pipeline.py` (no heavy FastAPI/SQLAlchemy boilerplate).
- **Detection:**
  - `nids/ml.py`: Loads `AI/models/xgboost_nids_model.pkl` + 12-feature alignment (`collectors/feature_alignment.py`).
  - `nids/rules.py`: Deterministic Suricata/signature fallback rules.
- **Storage:** SQLite (`nids/storage.py`).
- **Response:** `nids/response.py` + `response_engine/` (dry-run by default on Windows, iptables/Cisco support on Linux).
- **Frontend:** Plain HTML + CSS + modular JS (`web/index.html`, `web/css/styles.css`, `web/js/*.js`) with local Bootstrap, Bootstrap Icons, and Chart.js (`runtime/static/`).

---

## 3. New Features & API Contracts

### A. Kali Console Page (`Console`)
- **Backend endpoints in `nids/dashboard.py`:**
  - `POST /api/kali/connect` -> `{ host, port, username, password, mode }` (supports `ssh` via `paramiko`/`ssh` subprocess or `simulation` mode for offline demos).
  - `POST /api/kali/disconnect` -> disconnects active session.
  - `GET /api/kali/status` -> `{ connected, host, username, mode }`.
  - `GET /api/kali/playbooks` -> returns pre-built demo attack commands (Nmap SYN Scan, Hydra SSH Brute Force, HPing3 SYN Flood, SQLi Probe).
  - `POST /api/kali/exec` -> `{ command, target }` executes command (via SSH or local simulator that emits realistic output + optional EVE test event) and returns `{ stdout, stderr, exit_code, timestamp }`.
- **Frontend (`web/js/console.js`):**
  - Connection panel (IP, Port, Username, Password, Mode toggle: Live SSH / Demo Simulator).
  - Quick Playbook buttons that populate/run commands.
  - Interactive dark terminal output with command history and clear button.

### B. Live Network Topology Page (`Topology`)
- **Backend endpoint in `nids/dashboard.py`:**
  - `GET /api/topology` -> builds live `nodes` and `edges` from `pipeline.store.recent(...)` + `pipeline.responder`:
    - Each node: `{ id, ip, label, role ("gateway"|"nids"|"host"|"attacker"), status ("online"|"offline"|"attacking"|"blocked"), alert_count, last_attack, last_severity, last_seen }`.
    - Each edge: `{ source, target, attack_type, severity, active }`.
- **Frontend (`web/js/topology.js`):**
  - Interactive SVG Network Map (Gateway/Router -> NIDS Sensor -> Discovered Hosts) with smooth CSS/SVG animations (`better-motion`).
  - Clear **Online** (green) and **Offline** (muted) badges.
  - When an IP launches an attack: node turns **dark red** with pulsing ring, and an **animated dashed red attack beam** draws from the attacking IP toward its target, synced with Dashboard alerts!
  - Device inventory table below the map.

---

## 4. Progress Checklist

- [x] Phase 1: Clean junk/duplicate demo archives and create `HANDOFF_PLAN.md` + `.gitignore`
- [x] Phase 2: Add Console (Kali) & Topology APIs to `nids/dashboard.py` + `nids/storage.py`
- [x] Phase 3: Upgrade `web/` UI/UX, motion (`better-motion`), accessibility, and add `Console` + `Topology` pages
- [x] Phase 4: Package into `Linux_Support/` and `Windows_Support/` with OS-specific launchers & `README.md`
- [x] Phase 5: Run `pytest` on both folders and verify live server endpoints
