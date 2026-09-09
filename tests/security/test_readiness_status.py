import importlib.util
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("readiness_status", ROOT / "scripts/readiness_status.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReadinessTests(unittest.TestCase):
    def test_uninitialized_stays_blocked_even_when_docker_says_healthy(self):
        result = module.readiness({"initialized": False, "sealed": True, "docker_health": "healthy"})
        self.assertFalse(result["ready"])
        self.assertTrue(result["bootstrap_required"])
        self.assertEqual(result["state"], "uninitialized")

    def test_sealed_and_unsealed(self):
        self.assertFalse(module.readiness({"initialized": True, "sealed": True})["ready"])
        result = module.readiness({"initialized": True, "sealed": False, "standby": True})
        self.assertTrue(result["ready"])
        self.assertFalse(result["policy_and_restore_verified"])

    def test_malformed_states_fail_closed_and_unknown_fields_are_dropped(self):
        for value in ({}, [], None, {"initialized": "true", "sealed": False},
                      {"initialized": False, "sealed": False}):
            self.assertFalse(module.readiness(value)["ready"])
        result = module.readiness({"initialized": True, "sealed": False, "credential": "hidden"})
        self.assertNotIn("hidden", json.dumps(result))

    def test_cli_reports_blocked_with_nonzero_exit_and_no_raw_input(self):
        result = subprocess.run(["python3", str(ROOT / "scripts/readiness_status.py")],
                                input='{"initialized":false,"sealed":true,"credential":"hidden"}',
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("hidden", result.stdout + result.stderr)

    def test_legacy_overlay_does_not_mask_uninitialized_or_sealed_codes(self):
        import yaml
        source = yaml.safe_load((ROOT / "deploy/compose/compose.legacy-readiness.yaml").read_text())
        check = source["services"]["openbao"]["healthcheck"]["test"][-1]
        self.assertNotIn("uninitcode", check)
        self.assertNotIn("sealedcode", check)
        self.assertEqual(set(source["services"]["openbao"]), {"healthcheck"})
