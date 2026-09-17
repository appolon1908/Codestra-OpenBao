"""The rotation certification matrix must map onto the real scripts, hooks and evidence fields."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "config" / "rotation-certification.v1.json"


class RotationCertificationContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.rotate = (ROOT / "scripts" / "rotate-test.sh").read_text(encoding="utf-8")
        self.revoke = (ROOT / "scripts" / "revoke-test.sh").read_text(encoding="utf-8")
        self.certifier = (ROOT / "scripts" / "certify_staging_identity.py").read_text(encoding="utf-8")

    def test_eight_ordered_steps_for_staging_only(self):
        steps = self.contract["steps"]
        self.assertEqual([s["step"] for s in steps], list(range(1, 9)))
        self.assertEqual(self.contract["environments"], ["staging"])
        self.assertFalse(self.contract["productionRotationAuthorized"])
        self.assertEqual(self.contract["destructiveProductionRotation"], "forbidden")
        self.assertRegex(self.rotate, r'\[\[ "\$environment" =~ \^\(development\|test\|staging\)\$ \]\]')

    def test_every_executor_and_input_exists(self):
        for step in self.contract["steps"]:
            executor = ROOT / step["executor"]
            self.assertTrue(executor.is_file(), step["executor"])
            source = executor.read_text(encoding="utf-8")
            for name in step.get("inputs", []):
                self.assertIn(name, source, f"step {step['step']} input {name} is not consumed by {step['executor']}")
            for check in step.get("checks", []):
                self.assertIn(f'"{check}"', self.certifier, f"step {step['step']} check {check} is not a certifier check")
        for name in self.contract["revocationMatrix"]["inputs"]:
            self.assertIn(name, self.revoke)

    def test_evidence_fields_match_rotate_script_output(self):
        fields = self.contract["steps"][-1]["evidenceFields"]
        for field in fields:
            self.assertRegex(self.rotate, rf"\b{re.escape(field)}:", field)
        self.assertIn("secretValuesIncluded:false", self.rotate)
        self.assertIn("providerBusinessEffectsEnabled:false", self.rotate)
        self.assertIn('chmod 0400 "$evidence"', self.rotate)

    def test_old_credential_must_be_denied_or_the_run_aborts(self):
        self.assertIn('if "$old_verifier" >/dev/null 2>&1; then', self.rotate)
        self.assertIn("exit 2", self.rotate)


if __name__ == "__main__":
    unittest.main()
