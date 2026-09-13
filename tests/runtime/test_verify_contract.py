from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
