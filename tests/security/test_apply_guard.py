from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ApplyGuardTests(unittest.TestCase):
    def test_apply_requires_exact_plan_approval_and_all_runtime_gates(self) -> None:
        source = (ROOT / "scripts/apply.sh").read_text(encoding="utf-8")
        for required in (
            "sha256sum -c", ".planSourceSha", ".counts.destroy", ".runtimeApplyAuthorized",
            "jtiReplayCacheImplemented", "verify_environment_approval.sh",
            "APPLY_EXACT_OPENBAO_PLAN_", "verify_applied_plan.py",
            "OPENBAO_PLUGIN_BINARY", "bao plugin register", "-plugin-name=",
        ):
            self.assertIn(required, source)
        self.assertNotIn("operator init", source)
        self.assertNotIn("audit disable", source)
        self.assertNotIn("secrets disable", source)

    def test_required_approver_is_kazan555(self) -> None:
        source = (ROOT / "scripts/verify_environment_approval.sh").read_text(encoding="utf-8")
        self.assertIn("kazan555", source)
        self.assertIn("/approvals", source)
        for suffix in ("runtime", "certify", "initialize", "backup", "restore"):
            self.assertIn(f'openbao-${{environment}}-{suffix}', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
