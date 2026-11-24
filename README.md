# Sentinel-AI NIDS (Student & Committee Edition)

An AI-powered **Network Intrusion Detection & Active Response System** built with clean, readable Python (`http.server` + SQLite + XGBoost + Suricata rules) and a modern **HTML / CSS / JavaScript** dashboard.

---

## Repository Structure

| Folder | Target OS | Description |
|---|---|---|
| [`Linux_Support/`](./Linux_Support) | **Linux (Ubuntu / Kali / Debian)** | Full NIDS with Suricata `eve.json` capture, `iptables`/Cisco response engine, and `.sh` / `.desktop` launchers. |
| [`Windows_Support/`](./Windows_Support) | **Windows 10 / 11** | Full NIDS with 1-click `.bat` & `.ps1` launchers, dry-run firewall mode, Demo Simulator Console, and live Topology map. |
| [`HANDOFF_PLAN.md`](./HANDOFF_PLAN.md) | **Team / Dev** | Architecture overview, API contracts, and development checklist. |

---

## Quick Start

### Windows (`Windows_Support/`)
1. Open `Windows_Support/` and double-click **`start_nids.bat`** (or run `.\start_nids.ps1` in PowerShell).
2. Open your browser at **`http://127.0.0.1:8080`**.

### Linux (`Linux_Support/`)
```bash
cd Linux_Support
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./start_nids.sh
```
Open **`http://127.0.0.1:8080`** in your browser.

---

## Key Features (Easy to Demo & Explain)

1. **Dashboard & Alerts (`web/js/script.js`):** Real-time traffic KPIs, correlated `ML + Suricata` detections, and alert inspection.
2. **Live Network Topology (`web/js/topology.js`, `nids/topology.py`):** Interactive SVG network map showing **Online / Offline** hosts, **Blocked** devices, and **dark-red pulsing attackers** with animated attack beams—synced live with Dashboard alerts.
3. **Kali Attack Console (`web/js/console.js`, `nids/kali_console.py`):** Connect to Kali Linux via **Live SSH** or use the built-in **Demo Simulator** with 1-click playbooks (Nmap SYN Scan, Hydra SSH Brute Force, HPing3 SYN Flood, SQLi Probe).
4. **AI Detection (`nids/ml.py`, `AI/train_model.py`):** 12-feature aligned `XGBClassifier` trained on deduplicated CICIDS2017 flows (`Normal`, `Suspicious Port`, `Brute Force`, `Denial of Service`, `Web Attack`, `Botnet`) with deterministic rule fallback.
5. **Active Response (`nids/response.py`, `response_engine/`):** Policy-driven blocking (`LOG`, `ALERT`, `TEMPORARY_BLOCK`, `BLOCK`) with whitelist protection.

---

## Running Tests

```bash
# Inside either Linux_Support/ or Windows_Support/
pytest tests
```
