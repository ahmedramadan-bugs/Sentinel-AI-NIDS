"""
policy.py
---------------------------------------
Configurable Alert-Response Policy Engine with Out-of-the-Box Defaults.

Severity -> Action Mapping:
- Critical: BLOCK (Permanent block)
- High: TEMPORARY_BLOCK (Default: 300 seconds)
- Medium: ALERT (Alert on dashboard & log)
- Low / Info: LOG (Log only)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

DEFAULT_POLICY: Dict[str, Any] = {
    "Critical": "BLOCK",
    "High": "TEMPORARY_BLOCK",
    "Medium": "ALERT",
    "Low": "LOG",
    "Info": "LOG",
    "temp_block_seconds": 300,
    "enforcement_mode": "auto",  # 'auto', 'host', 'cisco', 'dry_run'
}

VALID_ACTIONS = {"BLOCK", "TEMPORARY_BLOCK", "ALERT", "LOG"}
VALID_MODES = {"auto", "host", "cisco", "dry_run"}


class PolicyEngine:
    def __init__(self, policy_path: Path):
        self.policy_path = Path(policy_path)
        self.policy: Dict[str, Any] = dict(DEFAULT_POLICY)
        self.load()

    def load(self) -> Dict[str, Any]:
        """Load policy from disk, or initialize with defaults if not present."""
        if self.policy_path.is_file():
            try:
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    # Merge with defaults so any missing key has a sensible default
                    for k, v in DEFAULT_POLICY.items():
                        if k not in loaded:
                            loaded[k] = v
                    self.policy = loaded
                    logger.info(f"Loaded response policy from {self.policy_path}")
                    return self.policy
            except Exception as e:
                logger.warning(f"Failed to read policy from {self.policy_path}, using defaults: {e}")

        self.policy = dict(DEFAULT_POLICY)
        self.save()
        return self.policy

    def save(self) -> bool:
        """Persist current policy to disk."""
        try:
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.policy_path, "w", encoding="utf-8") as f:
                json.dump(self.policy, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save policy to {self.policy_path}: {e}")
            return False

    def get_action(self, severity: str) -> str:
        """Get the configured action for a given severity level with default fallback."""
        sev_key = severity.capitalize() if severity else "Info"
        action = self.policy.get(sev_key, DEFAULT_POLICY.get(sev_key, "LOG"))
        return action if action in VALID_ACTIONS else "LOG"

    def get_temp_block_seconds(self) -> int:
        try:
            return int(self.policy.get("temp_block_seconds", 300))
        except (ValueError, TypeError):
            return 300

    def get_enforcement_mode(self) -> str:
        mode = self.policy.get("enforcement_mode", "auto").lower()
        return mode if mode in VALID_MODES else "auto"

    def update_policy(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update and persist policy settings."""
        for k, v in updates.items():
            if k in {"Critical", "High", "Medium", "Low", "Info"} and v in VALID_ACTIONS:
                self.policy[k] = v
            elif k == "temp_block_seconds":
                try:
                    self.policy[k] = max(10, min(86400, int(v)))
                except (ValueError, TypeError):
                    pass
            elif k == "enforcement_mode" and v in VALID_MODES:
                self.policy[k] = v

        self.save()
        return dict(self.policy)
