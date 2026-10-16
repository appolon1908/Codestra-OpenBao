"""No secret values, no write capability and no ungoverned activation."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MissionControlStagingReaderTests(unittest.TestCase):
    def test_policy_is_exact_read_only_staging(self):
        item = json.loads((ROOT / "config/staging/mission-control-reader.v1.json").read_text())
        policy = (ROOT / item["policy_file"]).read_text()
        self.assertEqual(item["environment"], "staging")
        self.assertIs(item["runtime_apply_authorized"], False)
        self.assertIs(item["production_go"], False)
        self.assertIs(item["external_effects_enabled"], False)
        self.assertLessEqual(item["identity"]["token_max_ttl_seconds"], 900)
        self.assertIs(item["database_access"]["read_only_transaction"], True)
        self.assertEqual(item["database_access"]["permissions"], ["CONNECT", "SELECT"])
        self.assertIs(item["activation"]["staging_go"], False)
        self.assertIs(item["activation"]["requires_approval"], True)
        self.assertEqual(policy.count('path "'), 1)
        self.assertIn(item["secret_path"], policy)
        self.assertIn('capabilities = ["read"]', policy)
        self.assertNotIn('capabilities = ["create"', policy)
        self.assertNotIn('capabilities = ["update"', policy)
        self.assertNotIn('"token":', json.dumps(item))
        self.assertNotIn('"password":', json.dumps(item))


if __name__ == "__main__":
    unittest.main()
