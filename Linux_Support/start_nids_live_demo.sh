#!/usr/bin/env bash
# ==============================================================================
# start_nids_live_demo.sh
# ------------------------------------------------------------------------------
# OPT-IN LIVE DEMONSTRATION SCRIPT:
# Runs Sentinel-AI NIDS with real Cisco IOS ACL enforcement enabled (non-dry-run)
# and exposes dashboard to the local lab subnet for evaluation/demo.
# ==============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ -f "$PROJECT_DIR/.env" ]; then
    echo "Loading environment configuration from $PROJECT_DIR/.env ..."
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

echo "[1/4] Enabling sniffing interfaces in promiscuous mode..."
sudo ip link set ens33 up promisc on 2>/dev/null || true
sudo ip link set ens38 up promisc on 2>/dev/null || true

echo "[2/4] Restarting Suricata IDS engine..."
sudo systemctl restart suricata 2>/dev/null || true

echo "[3/4] Freeing port 8080 and setting log permissions..."
sudo fuser -k 8080/tcp 2>/dev/null || true
sudo chmod 644 /var/log/suricata/eve.json 2>/dev/null || true

echo "[4/4] Starting NIDS in LIVE ENFORCEMENT DEMO MODE..."
export NIDS_EVE_LOG="${NIDS_EVE_LOG:-/var/log/suricata/eve.json}"
export NIDS_RESPONSE_DRY_RUN=false
export NIDS_DASHBOARD_HOST="${NIDS_DASHBOARD_HOST:-0.0.0.0}"
export NIDS_DASHBOARD_PORT="${NIDS_DASHBOARD_PORT:-8080}"

(sleep 4 && xdg-open "http://localhost:${NIDS_DASHBOARD_PORT}" 2>/dev/null || true) &

exec "$PROJECT_DIR/.venv/bin/python3" "$PROJECT_DIR/run_nids.py"
