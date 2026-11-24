"""Response policy adapter.  The default is intentionally non-destructive."""

from __future__ import annotations

from typing import Any

from .config import Settings
from .types import Detection


class ResponseAdapter:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.engine = None
        self.error: str | None = None
        self._recent_attempts: dict[str, float] = {}
        from .policy import PolicyEngine
        policy_path = settings.root / "runtime" / "policy.json"
        self.policy_engine = PolicyEngine(policy_path)

    def start(self) -> bool:
        """Instantiate the existing response engine only when it is needed."""
        try:
            import os
            from response_engine.config import configure_runtime
            from response_engine.response_engine import ResponseEngine

            mode = self.policy_engine.get_enforcement_mode()
            is_dry = self.settings.response_dry_run

            resp_dir = self.settings.root / "runtime"
            resp_dir.mkdir(parents=True, exist_ok=True)

            backend = None
            if mode == "host":
                from response_engine.host_backend import HostFirewallBackend
                backend = HostFirewallBackend()
                configure_runtime(dry_run=False, data_dir=resp_dir)
            elif mode == "cisco":
                configure_runtime(dry_run=is_dry, data_dir=resp_dir)
            elif mode == "dry_run":
                configure_runtime(dry_run=True, data_dir=resp_dir)
            else:  # auto
                if os.getenv("NIDS_CISCO_HOST") and not is_dry:
                    configure_runtime(dry_run=False, data_dir=resp_dir)
                elif is_dry:
                    configure_runtime(dry_run=True, data_dir=resp_dir)
                else:
                    from response_engine.host_backend import HostFirewallBackend
                    backend = HostFirewallBackend()
                    configure_runtime(dry_run=False, data_dir=resp_dir)

            self.engine = ResponseEngine(backend=backend)
            return bool(self.engine.startup())
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return False

    def policy(self, detection: Detection | None) -> str:
        if detection is None:
            return "LOG"
        return self.policy_engine.get_action(detection.severity)

    @property
    def is_dry_run(self) -> bool:
        try:
            from response_engine.config import EngineConfig
            return bool(EngineConfig.DRY_RUN)
        except Exception:
            return self.settings.response_dry_run

    def respond(self, detection: Detection | None, source_ip: str) -> dict[str, Any]:
        action = self.policy(detection)
        dry = self.is_dry_run
        if action in {"LOG", "ALERT"}:
            return {"action": action, "status": "RECORDED", "dry_run": dry}
        if not source_ip or self.engine is None:
            return {"action": action, "status": "UNAVAILABLE", "dry_run": dry}

        # Fast burst deduplication: if we attempted to block this IP in the last 5 seconds, don't stall on SSH again
        import time
        now = time.time()
        last_attempt = self._recent_attempts.get(source_ip, 0)
        if now - last_attempt < 5.0 and source_ip in getattr(self.engine, "active_blocks", {}):
            return {"action": action, "status": "ACTIVE", "dry_run": dry}
        self._recent_attempts[source_ip] = now
        try:
            if action == "BLOCK":
                result = self.engine.block_ip(
                    source_ip, attack=detection.attack_type, severity=detection.severity, source="NIDS"
                )
            else:
                result = self.engine.temp_block_ip(
                    source_ip,
                    timeout=self.policy_engine.get_temp_block_seconds(),
                    attack=detection.attack_type,
                    severity=detection.severity,
                    source="NIDS",
                )
            if result.get("success"):
                status = "APPLIED"
            elif result.get("message") == "IP already blocked.":
                status = "ACTIVE"
            elif result.get("message") == "IP exists in whitelist.":
                status = "WHITELISTED"
            else:
                status = "FAILED"
            return {"action": action, "status": status, "result": result,
                    "dry_run": dry}
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            return {"action": action, "status": "ERROR", "error": self.error, "dry_run": dry}

    def health(self) -> dict[str, Any]:
        dry = self.is_dry_run
        if self.engine is None:
            return {"status": "UNAVAILABLE" if self.error else "NOT_STARTED", "dry_run": dry,
                    "error": self.error}
        return {"status": "HEALTHY", "dry_run": dry, "stats": self.engine.get_stats()}
