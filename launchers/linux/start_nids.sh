#!/usr/bin/env bash
set -e

echo "======================================================"
echo "   NIDS - Network Intrusion Detection & Response      "
echo "======================================================"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Capture interfaces — override via NIDS_CAPTURE_INTERFACES (space-separated)
# e.g.  export NIDS_CAPTURE_INTERFACES="eth0 eth1"
NIDS_CAPTURE_INTERFACES="${NIDS_CAPTURE_INTERFACES:-ens33 ens38}"

echo "[1/4] Enabling sniffing interfaces (${NIDS_CAPTURE_INTERFACES}) in promiscuous mode..."
for _iface in ${NIDS_CAPTURE_INTERFACES}; do
    sudo ip link set "${_iface}" up promisc on 2>/dev/null || true
done

echo "[2/4] Starting Suricata IDS engine..."
sudo systemctl restart suricata 2>/dev/null || true

echo "[3/4] Freeing port 8080 and setting log permissions..."
sudo fuser -k 8080/tcp 2>/dev/null || true
sudo chmod 644 /var/log/suricata/eve.json 2>/dev/null || true

echo "[4/4] Starting NIDS AI Engine & Dashboard..."
if [ -f "$PROJECT_DIR/.env" ]; then
    echo "Loading environment configuration from $PROJECT_DIR/.env ..."
    set -a
    # shellcheck source=/dev/null
    source "$PROJECT_DIR/.env"
    set +a
fi

export NIDS_EVE_LOG="${NIDS_EVE_LOG:-/var/log/suricata/eve.json}"
export NIDS_RESPONSE_DRY_RUN="${NIDS_RESPONSE_DRY_RUN:-true}"
export NIDS_DASHBOARD_HOST="${NIDS_DASHBOARD_HOST:-127.0.0.1}"
export NIDS_DASHBOARD_PORT="${NIDS_DASHBOARD_PORT:-8080}"

(sleep 4 && xdg-open "http://${NIDS_DASHBOARD_HOST}:${NIDS_DASHBOARD_PORT}" 2>/dev/null || true) &

exec "$PROJECT_DIR/.venv/bin/python3" "$PROJECT_DIR/run_nids.py"
