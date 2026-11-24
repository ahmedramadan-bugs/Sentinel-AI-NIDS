#!/usr/bin/env bash
echo "Stopping NIDS System..."
pkill -f "run_nids.py" 2>/dev/null || true
echo "NIDS process stopped."
