from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/generate_workload_policies.py"
SPEC = importlib.util.spec_from_file_location("generate_workload_policies", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GeneratedPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = json.loads(MODULE.AUTHORITY.read_text(encoding="utf-8"))

    def test_committed_policies_match_generator(self) -> None:
        rendered, expected_index = MODULE.build(self.authority)
        actual_index = json.loads(MODULE.INDEX.read_text(encoding="utf-8"))
        self.assertEqual(actual_index, expected_index)
        for relative, source in rendered.items():
            self.assertEqual((MODULE.OUTPUT / relative).read_text(encoding="utf-8"), source)

    def test_every_policy_denies_other_environments_and_system_admin(self) -> None:
        rendered, _ = MODULE.build(self.authority)
        for role in self.authority["roles"]:
            relative = Path(role["environment"]) / f"{role['serviceIdentity']}.hcl"
            source = rendered[relative]
            for environment in MODULE.ENVIRONMENTS:
                expected = f'path "codestra/data/{environment}/*"'
                if environment == role["environment"]:
                    self.assertNotIn(expected, source)
                else:
                    self.assertIn(expected, source)
            self.assertIn('path "sys/*"', source)
            self.assertIn('path "auth/token/create*"', source)
            self.assertNotIn('capabilities = ["sudo"]', source)

    def test_n8n_has_only_middleware_client_secret_access(self) -> None:
        rendered, _ = MODULE.build(self.authority)
        for environment in MODULE.ENVIRONMENTS:
            source = rendered[Path(environment) / "n8n-automation.hcl"]
            self.assertIn(f"codestra/data/{environment}/n8n/middleware-client/*", source)
            for forbidden in ("email", "sms", "telephony", "advertising", "beyvra"):
                self.assertNotIn(f"/{forbidden}/", source)

    def test_only_prometheus_has_exact_metrics_read(self) -> None:
        rendered, _ = MODULE.build(self.authority)
        for role in self.authority["roles"]:
            relative = Path(role["environment"]) / f"{role['serviceIdentity']}.hcl"
            source = rendered[relative]
            if role["serviceIdentity"] == "prometheus-openbao":
                self.assertIn('path "sys/metrics" {\n  capabilities = ["read"]', source)
            else:
                self.assertNotIn('path "sys/metrics"', source)
            self.assertIn('path "sys/*" {\n  capabilities = ["deny"]', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
