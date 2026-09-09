from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/build_release.py"
SPEC = importlib.util.spec_from_file_location("build_release", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseGuardTests(unittest.TestCase):
    def test_current_source_cannot_be_released_before_runtime_gates(self) -> None:
        with self.assertRaisesRegex(ValueError, "runtime_authority_not_earned"):
            MODULE.validate_runtime_authority()
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("runtime_blocked_by_vex", source)
        self.assertIn("codestra_openbao_runtime_disabled", source)

    def test_release_manifest_covers_every_runtime_authority_file(self) -> None:
        manifest = MODULE.authority_manifest()
        for required in (
            "CODESTRA_UPSTREAM.json",
            ".github/workflows/runtime-deploy.yml",
            ".github/workflows/runtime-rollback.yml",
            "config/workload-secret-authority.v1.json",
            "deploy/compose/compose.yaml",
            "monitoring/alerts/openbao-alerts.yml",
            "openbao/openbao.hcl",
            "plugins/codestra-jwt-replay/backend.go",
            "plugins/codestra-jwt-replay/plugin.v1.json",
            "scripts/apply.sh",
        ):
            self.assertIn(required, manifest)
        self.assertRegex(MODULE.authority_checksum(manifest), r"^[0-9a-f]{64}$")

    def test_release_workflow_publishes_only_with_immutable_protection(self) -> None:
        source = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for required in (
            "openbao-release", "verify_environment_approval.sh",
            "immutable-releases", "gh release create", "--target", "--draft",
            "gh release upload", "--method PATCH", "-F draft=false",
            '.draft == true', 'all(startswith(\"sha256:\"))',
            "cosign sign-blob", "cosign verify-blob", "refs/heads/production",
            ".immutable == true", "OPENBAO_IMMUTABLE_GITHUB_RELEASE=PASS",
        ):
            self.assertIn(required, source)
        self.assertIn("contents: write", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
