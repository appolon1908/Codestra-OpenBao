from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/generate_jwt_roles.py"
SPEC = importlib.util.spec_from_file_location("generate_jwt_roles", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class JwtRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = json.loads(MODULE.AUTHORITY.read_text(encoding="utf-8"))
        cls.auth = json.loads(MODULE.AUTH_CONFIG.read_text(encoding="utf-8"))
        cls.generated = json.loads(MODULE.OUTPUT.read_text(encoding="utf-8"))

    def test_committed_roles_match_generator(self) -> None:
        self.assertEqual(self.generated, MODULE.build(self.authority, self.auth))

    def test_every_role_requires_exact_claims_and_lifetime(self) -> None:
        required_fragments = [
            "'iss' in claims", "'sub' in claims", "'aud' in claims",
            "'azp' in claims", "'iat' in claims", "'exp' in claims",
            "'jti' in claims", "'codestra_environment' in claims",
            "int(claims.exp) - int(claims.iat) <= 300",
            "TTL: 300000000000",
            "issue_time: now",
            "MaxTTL: 300000000000",
            "explicit_max_ttl: 300000000000",
            "no_default_policy: true",
        ]
        for role in self.generated["roles"]:
            expression = role["payload"]["cel_program"]["expression"]
            for fragment in required_fragments:
                self.assertIn(fragment, expression)
            self.assertNotIn("*", expression)
            self.assertEqual(role["payload"]["bound_audiences"], ["openbao"])
            self.assertFalse(role["runtimeApplyAuthorized"])

    def test_replay_gate_is_implemented_but_runtime_remains_fail_closed(self) -> None:
        self.assertTrue(self.generated["jtiReplayCacheRequired"])
        self.assertTrue(self.generated["jtiReplayCacheImplemented"])
        self.assertEqual(
            self.generated["authPlugin"],
            "plugins/codestra-jwt-replay/plugin.v1.json",
        )
        self.assertFalse(self.generated["runtimeApplyAuthorized"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
