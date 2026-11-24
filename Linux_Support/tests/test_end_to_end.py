"""End-to-end tests using genuine EVE JSON input and safe test doubles."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from http import HTTPStatus
from http.client import HTTPConnection
import threading

from nids.config import Settings
from nids.dashboard import create_server
from nids.ml import ModelDetector
from nids.pipeline import NIDSPipeline
from nids.types import MLDecision


class FakeResponse:
    def __init__(self):
        self.calls = []

    def start(self):
        return True

    @staticmethod
    def policy(detection):
        if detection is None:
            return "LOG"
        if detection.severity == "Critical":
            return "BLOCK"
        if detection.severity == "High":
            return "TEMPORARY_BLOCK"
        if detection.severity == "Medium":
            return "ALERT"
        return "LOG"

    def respond(self, detection, source_ip):
        action = self.policy(detection)
        self.calls.append((action, source_ip, detection.attack_type if detection else "Normal"))
        return {"action": action, "status": "APPLIED", "dry_run": True}

    def health(self):
        return {"status": "HEALTHY", "dry_run": True}


class FakeModel:
    def __init__(self, label="Normal", confidence=0.99, available=True):
        self.label = label
        self.confidence = confidence
        self.available = available
        self.status = "HEALTHY" if available else "UNAVAILABLE"
        self.error_count = 0

    def load(self):
        return self.available

    def classify(self, _features):
        if not self.available:
            return None
        return MLDecision(self.label, self.confidence, 1.0)

    def health(self):
        return {"status": self.status, "error_count": self.error_count}


def eve_event(*, event_type="flow", signature=None, flow_id=101, timestamp="2026-08-21T00:00:00.000000+0000"):
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "flow_id": flow_id,
        "src_ip": "198.51.100.24",
        "src_port": 51234,
        "dest_ip": "203.0.113.8",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "start": "2026-08-21T00:00:00.000000+0000",
            "end": "2026-08-21T00:00:01.000000+0000",
            "bytes_toserver": 120,
            "bytes_toclient": 240,
            "pkts_toserver": 2,
            "pkts_toclient": 2,
        },
    }
    if signature:
        event["alert"] = {"signature": signature, "signature_id": 900001, "severity": 2}
    return json.dumps(event)


class NIDSEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.settings = Settings(
            root=root,
            eve_log_path=root / "eve.json",
            database_path=root / "events.db",
            model_path=root / "model.pkl",
            scaler_path=root / "scaler.pkl",
            label_encoder_path=root / "labels.pkl",
            feature_schema_path=root / "features.pkl",
            imputer_path=root / "imputer.pkl",
            dashboard_port=0,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normal_flow_is_stored_without_a_block(self):
        response = FakeResponse()
        pipeline = NIDSPipeline(self.settings, model=FakeModel(), responder=response)
        result = pipeline.ingest_eve_line(eve_event())
        self.assertTrue(result["stored"])
        self.assertEqual(result["event"]["attack_type"], "Normal")
        self.assertEqual(result["event"]["response_action"], "LOG")
        self.assertEqual(response.calls, [("LOG", "198.51.100.24", "Normal")])

    def test_suricata_alert_uses_fallback_and_is_deduplicated_before_response(self):
        response = FakeResponse()
        pipeline = NIDSPipeline(self.settings, model=FakeModel(available=False), responder=response)
        line = eve_event(event_type="alert", signature="ET SCAN Nmap TCP SYN scan", flow_id=202)
        first = pipeline.ingest_eve_line(line)
        second = pipeline.ingest_eve_line(line)
        self.assertTrue(first["stored"])
        self.assertEqual(first["event"]["detection_mode"], "fallback")
        self.assertEqual(first["event"]["attack_type"], "TCP SYN / Port Scan")
        self.assertTrue(second["duplicate"])
        self.assertEqual(len(response.calls), 1)
        self.assertEqual(pipeline.store.recent(1)[0]["response_status"], "APPLIED")

    def test_ml_failure_then_recovery_preserves_detections(self):
        response = FakeResponse()
        model = FakeModel(available=False)
        pipeline = NIDSPipeline(self.settings, model=model, responder=response)
        fallback = pipeline.ingest_eve_line(eve_event(event_type="alert", signature="ET SCAN Nmap TCP SYN scan", flow_id=301))
        self.assertEqual(fallback["event"]["detection_mode"], "fallback")
        model.available, model.status = True, "HEALTHY"
        model.label, model.confidence = "Brute Force", 0.91
        recovered = pipeline.ingest_eve_line(eve_event(flow_id=302))
        self.assertEqual(recovered["event"]["detection_engine"], "ml")
        self.assertEqual(recovered["event"]["detection_mode"], "primary")
        self.assertEqual(pipeline.status()["detection_mode"], "ML_PRIMARY")


    def test_suricata_deterministic_fallback_rules(self):
        rules_test_cases = [
            ("NIDS ICMP echo reconnaissance", "ICMP Reconnaissance", "Medium", "ALERT"),
            ("NIDS HTTP SQL injection attempt", "SQL Injection", "High", "TEMPORARY_BLOCK"),
            ("NIDS HTTP XSS attempt", "Cross-Site Scripting", "High", "TEMPORARY_BLOCK"),
            ("NIDS HTTP local file inclusion attempt", "Local File Inclusion", "High", "TEMPORARY_BLOCK"),
            ("NIDS SSH connection burst", "SSH Brute Force", "High", "TEMPORARY_BLOCK"),
            ("NIDS TCP SYN flood", "Denial of Service", "Critical", "BLOCK"),
        ]
        response = FakeResponse()
        pipeline = NIDSPipeline(self.settings, model=FakeModel(available=False), responder=response)
        for i, (sig, expected_attack, expected_sev, expected_action) in enumerate(rules_test_cases):
            line = eve_event(event_type="alert", signature=sig, flow_id=400 + i)
            res = pipeline.ingest_eve_line(line)
            self.assertTrue(res["stored"])
            self.assertEqual(res["event"]["attack_type"], expected_attack)
            self.assertEqual(res["event"]["severity"], expected_sev)
            self.assertEqual(res["event"]["response_action"], expected_action)

    def test_real_trained_xgboost_model_loading_and_inference(self):
        real_settings = Settings()
        if not real_settings.model_path.is_file():
            self.skipTest("Retrained XGBoost model not present")
        detector = ModelDetector(real_settings)
        loaded = detector.load()
        self.assertTrue(loaded)
        self.assertEqual(detector.status, "HEALTHY")
        self.assertTrue(detector.available)

        flow_features = {
            "Destination Port": 80,
            "Flow Duration": 50000,
            "Total Fwd Packets": 5,
            "Total Backward Packets": 5,
            "Total Length of Fwd Packets": 300,
            "Total Length of Bwd Packets": 1500,
            "Flow Bytes/s": 36000.0,
            "Flow Packets/s": 200.0,
            "Fwd Packets/s": 100.0,
            "Bwd Packets/s": 100.0,
            "Down/Up Ratio": 5.0,
            "Average Packet Size": 180.0,
        }
        decision = detector.classify(flow_features)
        self.assertIsNotNone(decision)
        self.assertIn(decision.label, ["Normal", "Suspicious Port", "Brute Force", "Denial of Service", "Web Attack", "Botnet", "Data Exfiltration"])
        self.assertTrue(0.0 <= decision.confidence <= 1.0)
        self.assertGreater(decision.latency_ms, 0)
        self.assertEqual(detector.health()["status"], "HEALTHY")

    def test_dashboard_http_server_endpoints(self):
        pipeline = NIDSPipeline(self.settings, model=FakeModel())
        pipeline.ingest_eve_line(eve_event())
        server = create_server(pipeline)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = HTTPConnection(self.settings.dashboard_host, server.server_port, timeout=2)
            
            # Root page
            conn.request("GET", "/")
            res = conn.getresponse()
            self.assertEqual(res.status, HTTPStatus.OK)
            self.assertIn("text/html", res.headers.get("Content-Type"))
            _ = res.read()

            # Status API
            conn.request("GET", "/api/status")
            res = conn.getresponse()
            self.assertEqual(res.status, HTTPStatus.OK)
            data = json.loads(res.read().decode("utf-8"))
            self.assertIn("ml", data)
            self.assertIn("database", data)
            self.assertIn("metrics", data)
            self.assertEqual(data["metrics"]["observed_events"], 1)

            # Events API
            conn.request("GET", "/api/events?limit=10")
            res = conn.getresponse()
            self.assertEqual(res.status, HTTPStatus.OK)
            data = json.loads(res.read().decode("utf-8"))
            self.assertEqual(len(data["events"]), 1)
            self.assertEqual(data["events"][0]["attack_type"], "Normal")

            # Path traversal regression checks
            for bad_path in [
                "/static/../../nids/config.py",
                "/css/../../nids/config.py",
                "/js/../../nids/config.py",
            ]:
                conn.request("GET", bad_path)
                bad_res = conn.getresponse()
                _ = bad_res.read()
                self.assertEqual(bad_res.status, HTTPStatus.NOT_FOUND, f"Path traversal succeeded on {bad_path}")

            conn.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_alert_and_flow_records_for_same_connection_collapse_to_single_event(self):
        response = FakeResponse()
        pipeline = NIDSPipeline(self.settings, model=FakeModel(available=False), responder=response)
        
        # 1. Alert event for connection (flow_id=777)
        alert_line = eve_event(
            event_type="alert",
            signature="NIDS TCP SYN Port Scan",
            flow_id=777,
            timestamp="2026-08-23T12:00:01.000000+0000"
        )
        # 2. Corresponding flow completion event for the same connection (flow_id=777)
        flow_line = eve_event(
            event_type="flow",
            flow_id=777,
            timestamp="2026-08-23T12:00:05.000000+0000"
        )
        
        res1 = pipeline.ingest_eve_line(alert_line)
        res2 = pipeline.ingest_eve_line(flow_line)
        
        self.assertTrue(res1["stored"])
        self.assertEqual(res1["event"]["attack_type"], "TCP SYN / Port Scan")
        self.assertTrue(res2["duplicate"], "Corresponding flow record was not deduplicated")
        self.assertEqual(len(response.calls), 1)
        self.assertEqual(len(pipeline.store.recent(10)), 1)

    def test_temporary_block_persistence_and_restart_reconciliation(self):
        from response_engine.config import configure_runtime
        from response_engine.response_engine import ResponseEngine

        # Use an isolated data dir within test temp dir
        data_dir = Path(self.temp_dir.name) / "resp_test"
        data_dir.mkdir(parents=True, exist_ok=True)
        configure_runtime(data_dir=data_dir, dry_run=True)

        engine1 = ResponseEngine()
        self.assertTrue(engine1.startup())
        
        # Create a temporary block for 100 seconds
        res = engine1.temp_block_ip("192.0.2.77", timeout=100, attack="Test Attack", severity="High")
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "temporary_block")
        self.assertIn("192.0.2.77", engine1.active_blocks)
        self.assertEqual(engine1.active_blocks["192.0.2.77"].block_type, "temporary")
        engine1.shutdown()

        # Instantiate a new engine on the same data dir to simulate restart
        engine2 = ResponseEngine()
        # Mock backend blocked IPs on switch
        engine2.backend.get_blocked_ips = lambda: ["192.0.2.77", "192.0.2.99"]
        self.assertTrue(engine2.startup())
        
        # 192.0.2.77 must remain temporary, while 192.0.2.99 must be classified as permanent
        self.assertIn("192.0.2.77", engine2.active_blocks)
        self.assertEqual(engine2.active_blocks["192.0.2.77"].block_type, "temporary")
        self.assertIn("192.0.2.99", engine2.active_blocks)
        self.assertEqual(engine2.active_blocks["192.0.2.99"].block_type, "permanent")
        engine2.shutdown()


if __name__ == "__main__":
    unittest.main()
