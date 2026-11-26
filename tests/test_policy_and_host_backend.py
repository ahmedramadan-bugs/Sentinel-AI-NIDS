"""Unit tests for the new PolicyEngine and HostFirewallBackend."""

import tempfile
import unittest
from pathlib import Path

from nids.policy import DEFAULT_POLICY, PolicyEngine
from response_engine.host_backend import HostFirewallBackend


class PolicyAndHostBackendTests(unittest.TestCase):
    def test_policy_defaults_and_customization(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_file = Path(tmp_dir) / "policy.json"
            engine = PolicyEngine(policy_file)

            # Test default actions out of the box
            self.assertEqual(engine.get_action("Critical"), "BLOCK")
            self.assertEqual(engine.get_action("High"), "TEMPORARY_BLOCK")
            self.assertEqual(engine.get_action("Medium"), "ALERT")
            self.assertEqual(engine.get_action("Low"), "LOG")
            self.assertEqual(engine.get_action("Info"), "LOG")
            self.assertEqual(engine.get_temp_block_seconds(), 300)

            # Test customization update and persistence
            engine.update_policy({
                "Critical": "TEMPORARY_BLOCK",
                "Medium": "LOG",
                "temp_block_seconds": 600,
                "enforcement_mode": "host",
            })
            self.assertEqual(engine.get_action("Critical"), "TEMPORARY_BLOCK")
            self.assertEqual(engine.get_action("Medium"), "LOG")
            self.assertEqual(engine.get_temp_block_seconds(), 600)
            self.assertEqual(engine.get_enforcement_mode(), "host")

            # Reload from disk to verify persistence
            reloaded = PolicyEngine(policy_file)
            self.assertEqual(reloaded.get_action("Critical"), "TEMPORARY_BLOCK")
            self.assertEqual(reloaded.get_temp_block_seconds(), 600)
            self.assertEqual(reloaded.get_enforcement_mode(), "host")

    def test_host_firewall_backend_lifecycle(self):
        backend = HostFirewallBackend()
        test_ip = "198.51.100.99"

        self.assertTrue(backend.is_connected())
        backend.ensure_acl()

        # Block
        backend.block(test_ip)
        self.assertTrue(backend.verify(test_ip))
        self.assertIn(test_ip, backend.get_blocked_ips())

        # Unblock
        backend.unblock(test_ip)
        self.assertTrue(backend.verify_removed(test_ip))
        self.assertNotIn(test_ip, backend.get_blocked_ips())

    def test_response_adapter_backend_selection_and_dry_run(self):
        from nids.config import Settings
        from nids.response import ResponseAdapter
        from nids.types import Detection

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_root = Path(tmp_dir)
            settings = Settings(root=tmp_root)
            adapter = ResponseAdapter(settings)

            # Test host mode selection
            adapter.policy_engine.update_policy({"enforcement_mode": "host"})
            ok = adapter.start()
            self.assertTrue(ok)
            self.assertIsNotNone(adapter.engine)
            self.assertEqual(type(adapter.engine.backend).__name__, "HostFirewallBackend")
            self.assertFalse(adapter.is_dry_run)

            # Test respond() in host mode correctly reports dry_run=False
            det = Detection(attack_type="DDoS", severity="Critical", engine="ML", confidence=0.99, mode="ml")
            resp = adapter.respond(det, "198.51.100.42")
            self.assertEqual(resp["action"], "BLOCK")
            self.assertEqual(resp["status"], "APPLIED")
            self.assertFalse(resp["dry_run"])


if __name__ == "__main__":
    unittest.main()
