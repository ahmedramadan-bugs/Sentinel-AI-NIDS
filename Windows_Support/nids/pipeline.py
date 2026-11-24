"""One correlated flow: EVE JSON -> rules/ML -> response -> SQLite event."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from collectors.suricata_parser import SuricataFlow, SuricataParser

from .config import Settings
from .ml import ModelDetector
from .response import ResponseAdapter
from .rules import DeterministicRuleEngine
from .storage import EventStore
from .types import Detection, MLDecision, stronger_severity


logger = logging.getLogger(__name__)


class NIDSPipeline:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        model: Any | None = None,
        rules: DeterministicRuleEngine | None = None,
        responder: Any | None = None,
    ):
        self.settings = settings or Settings()
        self.settings.ensure_runtime_directories()
        self.store = EventStore(self.settings.database_path)
        self.model = model or ModelDetector(self.settings)
        self.rules = rules or DeterministicRuleEngine(self.settings.dedup_window_seconds)
        self.responder = responder or ResponseAdapter(self.settings)
        self.parser = SuricataParser(eve_log_path=str(self.settings.eve_log_path))
        self.running = False

    def start(self) -> None:
        self.model.load()
        self.responder.start()
        self.parser.register_flow_handler(self.process_flow)
        self.parser.register_alert_handler(self.process_flow)
        self.parser.start_watching(self.settings.poll_interval_seconds)
        self.running = True

    def stop(self) -> None:
        self.parser.stop_watching()
        if getattr(self.responder, "engine", None) is not None:
            self.responder.engine.shutdown()
        self.running = False

    def reload_model(self) -> bool:
        return bool(self.model.load())

    def _ml_detection(self, flow: SuricataFlow) -> Optional[Detection]:
        if flow.src_ip.startswith("fe80:") or flow.src_ip.startswith("ff02:") or flow.src_ip.startswith("::") or flow.src_ip == "0000:0000:0000:0000:0000:0000:0000:0000":
            return None
        decision: Optional[MLDecision] = self.model.classify(flow.to_features())
        if decision is None or decision.label.strip().lower() in {"normal", "benign"}:
            return None
        is_primary = decision.confidence >= self.settings.ml_confidence_threshold
        mode = "primary" if is_primary else "low_confidence"
        if is_primary:
            severity = "High" if decision.label.lower() in {"brute force", "data exfiltration"} else "Medium"
        else:
            severity = "Low"
        return Detection(
            attack_type=decision.label,
            severity=severity,
            confidence=decision.confidence,
            engine="ml",
            mode=mode,
            details={"latency_ms": round(decision.latency_ms, 3)},
        )

    def _correlate(self, rule: Optional[Detection], ml: Optional[Detection]) -> Optional[Detection]:
        if rule and ml:
            return Detection(
                attack_type=rule.attack_type,
                severity=stronger_severity(rule.severity, ml.severity),
                confidence=max(rule.confidence, ml.confidence),
                engine="ml+suricata" if rule.engine == "suricata" else "ml+deterministic",
                mode="validated" if ml.mode == "primary" else "low_confidence_validated",
                signature=rule.signature,
                rule_id=rule.rule_id,
                details={"ml_label": ml.attack_type, "ml_confidence": ml.confidence},
            )
        if rule:
            mode = "fallback" if not getattr(self.model, "available", False) else "rule"
            return Detection(rule.attack_type, rule.severity, rule.confidence, rule.engine, mode, rule.signature, rule.rule_id)
        return ml

    @staticmethod
    def _correlation_key(flow: SuricataFlow, detection: Optional[Detection]) -> str:
        raw = flow.raw_event or {}
        flow_id = raw.get("flow_id")
        if flow_id is not None:
            # Collapse alert and flow records for the same connection within a 60-second bucket
            time_bucket = int(flow.timestamp.timestamp() // 60)
            identity = {
                "flow_id": flow_id,
                "time_bucket": time_bucket,
                "src": flow.src_ip,
                "dst": flow.dest_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dest_port,
                "proto": flow.proto,
            }
        else:
            signature_id = (raw.get("alert") or {}).get("signature_id")
            identity = {
                "timestamp": flow.timestamp.isoformat(timespec="seconds"),
                "src": flow.src_ip,
                "dst": flow.dest_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dest_port,
                "proto": flow.proto,
                "signature_id": signature_id,
                "attack": detection.attack_type if detection else "Normal",
            }
        return hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()

    def process_flow(self, flow: SuricataFlow) -> dict[str, Any]:
        """Process one parser output.  No single detector may abort this method."""
        rule = self.rules.evaluate(flow)
        ml = self._ml_detection(flow)
        detection = self._correlate(rule, ml)
        planned_action = self.responder.policy(detection)
        event = {
            "correlation_key": self._correlation_key(flow, detection),
            "timestamp": flow.timestamp.astimezone(timezone.utc).isoformat(),
            "src_ip": flow.src_ip,
            "dest_ip": flow.dest_ip,
            "src_port": flow.src_port,
            "dest_port": flow.dest_port,
            "protocol": flow.proto,
            "attack_type": detection.attack_type if detection else "Normal",
            "detection_engine": detection.engine if detection else "none",
            "severity": detection.severity if detection else "Info",
            "confidence": detection.confidence if detection else 0.0,
            "detection_mode": detection.mode if detection else "normal",
            "signature": detection.signature if detection else None,
            "rule_id": detection.rule_id if detection else None,
            "response_action": planned_action,
            "response_status": "PENDING",
            "raw_event": {"eve": flow.raw_event or {}, "detection": detection.details if detection else {}},
        }
        inserted, event_id = self.store.record(event)
        if not inserted:
            # A flow alert and a correlated flow record must not trigger a second response.
            return {"stored": False, "duplicate": True, "event": event}
        response = self.responder.respond(detection, flow.src_ip)
        self.store.update_response(event_id, response)
        event["response_action"] = response["action"]
        event["response_status"] = response["status"]
        event["raw_event"]["response"] = response
        event["id"] = event_id
        return {"stored": True, "duplicate": False, "event": event}

    def ingest_eve_line(self, line: str) -> Optional[dict[str, Any]]:
        flow = self.parser.parse_eve_event(line)
        return self.process_flow(flow) if flow else None

    def process_existing_eve(self) -> int:
        count = 0
        for flow in self.parser.parse_eve_file(from_position=0):
            self.process_flow(flow)
            count += 1
        return count

    def status(self) -> dict[str, Any]:
        model_health = self.model.health()
        return {
            "suricata": {
                "status": "WATCHING" if self.running else ("READY" if self.settings.eve_log_path.exists() else "NOT_FOUND"),
                "eve_log": str(self.settings.eve_log_path),
            },
            "ml": model_health,
            "detection_mode": "ML_PRIMARY" if model_health.get("status") == "HEALTHY" else "DETERMINISTIC_FALLBACK",
            "database": self.store.health(),
            "response": self.responder.health(),
            "metrics": self.store.metrics(),
        }
