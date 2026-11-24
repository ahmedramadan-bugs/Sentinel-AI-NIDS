# Sentinel-AI NIDS — System Architecture & API Reference

## 1. Repository Structure

```text
Sentinel-AI-NIDS/
├── README.md                  # Project overview, Quick Start, ML metrics, & env vars
├── ARCHITECTURE.md            # System architecture, modules, and REST API contracts
├── LICENSE                    # MIT License
├── docs/assets/               # Animated SVG diagrams & SOC dashboard preview
├── .github/workflows/tests.yml# CI running pytest on Linux_Support & Windows_Support
├── Linux_Support/             # Linux edition (Suricata + iptables/Cisco + .sh launchers)
└── Windows_Support/           # Windows edition (1-click .bat/.ps1 + dry-run/netsh)
```

---

## 2. Core Pipeline Architecture

1. **Telemetry Ingestion (`collectors/suricata_parser.py`):**
   - Tails Suricata `eve.json` (`flow` and `alert` events) in real time and parses each record into a `SuricataFlow` object.
2. **Feature Alignment (`collectors/feature_alignment.py`):**
   - Single source of truth for the **12 numeric flow features** (`FEATURE_COLUMNS`) shared between `AI/train_model.py` and `nids/ml.py` to prevent train/serving skew.
3. **Dual-Engine Detection (`nids/pipeline.py`):**
   - **ML Engine (`nids/ml.py`):** Loads `AI/models/xgboost_nids_model.pkl` and preprocessing artifacts (`imputer.pkl`, `scaler.pkl`, `label_encoder.pkl`).
   - **Deterministic Fallback (`nids/rules.py`):** Evaluates Suricata signatures and protocol heuristics so detection stays resilient even if ML artifacts are unavailable.
   - **Correlation:** Combines ML and rule verdicts, deduplicates by connection `correlation_key`, and stores events in SQLite (`nids/storage.py`).
4. **Active Response (`nids/response.py` & `response_engine/`):**
   - Applies policy (`BLOCK`, `TEMPORARY_BLOCK`, `ALERT`, `LOG`) based on severity, supporting `Dry-Run`, `HostFirewallBackend` (`iptables` / `netsh`), and `CiscoBackend` (SSH ACL).

---

## 3. REST API Contracts (`nids/dashboard.py`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Pipeline health, ML status, latency, and event counters |
| `GET` | `/api/events?limit=100` | Recent correlated security events |
| `GET` | `/api/events/{id}` | Detailed single event record |
| `GET` | `/api/stats/traffic?range=24h` | Time-series traffic & threat volume |
| `GET` | `/api/stats/distribution` | Attack-type breakdown |
| `GET` | `/api/stats/analytics` | Top attackers, protocol distribution, and 7×24 heatmap |
| `GET` | `/api/models/metrics` | Training metrics (`metrics.json`) and live XGBoost feature importances |
| `GET` | `/api/topology` | Discovered devices (`online`, `offline`, `attacking`, `blocked`) and edges |
| `GET` | `/api/kali/status` | Active Kali Console connection state and recent command history |
| `GET` | `/api/kali/playbooks` | Pre-configured demo attack playbooks |
| `POST` | `/api/kali/connect` | Connect in `simulation` (Demo Simulator) or `ssh` (Live Kali VM) mode |
| `POST` | `/api/kali/disconnect` | Close active Kali Console session |
| `POST` | `/api/kali/exec` | Execute a command or playbook and return `stdout`/`stderr` |
| `GET` | `/api/response/state` | Active blocks, whitelist, action history, and response stats |
| `POST` | `/api/response/block` | Block or temporarily block an IP |
| `POST` | `/api/response/unblock` | Unblock an IP |
| `POST` | `/api/response/whitelist/add` | Add an IP to the protected whitelist |
| `POST` | `/api/response/whitelist/remove` | Remove an IP from the whitelist |
| `GET` / `POST` | `/api/settings` | Read or update automated response policy and enforcement mode |
