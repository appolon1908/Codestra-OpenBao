from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_applied_plan.py"
SPEC = importlib.util.spec_from_file_location("verify_applied_plan", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyContractTests(unittest.TestCase):
    def test_image_readback_checks_repo_digest_not_config_object_id(self) -> None:
        source = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
        self.assertIn("docker image inspect", source)
        self.assertIn(".[0].RepoDigests | index($expected) != null", source)
        self.assertNotIn('[[ "$actual_image" == "$expected_image"', source)

    def test_final_readback_enforces_the_desired_voter_topology(self) -> None:
        source = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
        self.assertIn("select(.voter == true)", source)
        self.assertIn(".desiredVotingNodes", source)
        self.assertIn("(( peer_count < desired_peers ))", source)
        self.assertLess(source.index("(( peer_count < desired_peers ))"), source.index("RAFT_HEALTH=PASS"))
        for environment, voters in (("staging", 3), ("production", 3)):
            document = json.loads((ROOT / f"config/environments/{environment}/environment.json").read_text())
            self.assertEqual(document["desiredVotingNodes"], voters)

    def test_kv_v2_security_configuration_is_read_back(self) -> None:
        operation = {
            "kind": "secret_engine_config",
            "name": "codestra/config",
            "payload": {
                "max_versions": 10,
                "cas_required": True,
                "delete_version_after": "2160h",
            },
        }
        with mock.patch.object(
            MODULE,
            "json_command",
            return_value={"data": operation["payload"]},
        ):
            MODULE.verify(operation)

        drifted = {"data": {**operation["payload"], "cas_required": False}}
        with mock.patch.object(MODULE, "json_command", return_value=drifted):
            with self.assertRaisesRegex(ValueError, "secret_engine_config_readback_mismatch"):
                MODULE.verify(operation)

    def test_normalized_durations_read_back_equal_but_other_values_do_not(self) -> None:
        operation = {
            "kind": "secret_engine_config",
            "name": "codestra/config",
            "payload": {"max_versions": 10, "cas_required": True, "delete_version_after": "2160h"},
        }
        # Observed on OpenBao 2.6.2: the stored value reads back normalized.
        normalized = {"data": {**operation["payload"], "delete_version_after": "2160h0m0s"}}
        with mock.patch.object(MODULE, "json_command", return_value=normalized):
            MODULE.verify(operation)
        for value in ("0s", "2159h0m0s", "", "2160"):
            shorter = {"data": {**operation["payload"], "delete_version_after": value}}
            with self.subTest(value=value), mock.patch.object(MODULE, "json_command", return_value=shorter):
                with self.assertRaisesRegex(ValueError, "secret_engine_config_readback_mismatch"):
                    MODULE.verify(operation)
        self.assertNotEqual(MODULE.semantic("v1.1.0"), MODULE.semantic("v1.1.0s"))
        self.assertEqual(MODULE.semantic("4d1dd974"), "4d1dd974")


if __name__ == "__main__":
    unittest.main(verbosity=2)
