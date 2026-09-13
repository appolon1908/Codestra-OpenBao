from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RotationRevocationGuardTests(unittest.TestCase):
    def test_rotation_requires_cas_agent_mode_revocation_and_health(self) -> None:
        source = (ROOT / "scripts/rotate-test.sh").read_text(encoding="utf-8")
        for required in (
            '[[ "$environment" =~ ^(development|test|staging)$ ]]',
            "OPENBAO_PROVIDER_EFFECTS_DISABLED_ACKNOWLEDGED",
            'bao kv put -cas="$expected_version"',
            'stat -c %a "$rendered_file"',
            '"$old_revoke"',
            'if "$old_verifier"',
            '"$health_verifier"',
            "OLD_CREDENTIAL_ACCESS=DENIED",
        ):
            self.assertIn(required, source)
        self.assertNotIn("CODESTRA_ENVIRONMENT=production", source)

    def test_revocation_proves_target_cross_env_and_audit_denials(self) -> None:
        source = (ROOT / "scripts/revoke-test.sh").read_text(encoding="utf-8")
        for required in (
            '[[ "$environment" =~ ^(development|test|staging)$ ]]',
            '"$revoke_driver"',
            'if "$target_deny_verifier"',
            '"$unrelated_verifier"',
            'if "$cross_environment_verifier"',
            '"$audit_verifier"',
            "CROSS_ENVIRONMENT_ACCESS=DENIED",
            "PROVIDER_BUSINESS_EFFECTS_ENABLED=NO",
        ):
            self.assertIn(required, source)

    def test_certification_workflow_is_protected_and_non_production(self) -> None:
        workflow = (ROOT / ".github/workflows/runtime-certification.yml").read_text()
        self.assertIn("options: [development, test, staging]", workflow)
        self.assertIn("openbao-${{ inputs.environment }}-certify", workflow)
        self.assertIn("scripts/verify_environment_approval.sh", workflow)
        self.assertIn("scripts/rotate-test.sh", workflow)
        self.assertIn("scripts/revoke-test.sh", workflow)
        self.assertNotIn("options: [development, test, staging, production]", workflow)


if __name__ == "__main__":
    unittest.main()
