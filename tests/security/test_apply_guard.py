from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ApplyGuardTests(unittest.TestCase):
    def test_apply_requires_exact_plan_approval_and_all_runtime_gates(self) -> None:
        source = (ROOT / "scripts/apply.sh").read_text(encoding="utf-8")
        for required in (
            "verify_artifact_checksum.sh", ".planSourceSha", ".counts.destroy", ".runtimeApplyAuthorized",
            "jtiReplayCacheImplemented", "verify_environment_approval.sh",
            "APPLY_EXACT_OPENBAO_PLAN_", "verify_applied_plan.py", "OPENBAO_PLUGIN_BINARY",
            "scripts/require_mutation_lease.sh", "scripts/collect_live_state.sh",
            "python3 -m codestra.change_kernel.cli", " submit ", " approve ", " apply ",
            "--expected-plan-sha256", "--approver kazan555",
        ):
            self.assertIn(required, source)
        for forbidden in ("operator init", "audit disable", "secrets disable", "bao write",
                          "bao policy write", "bao plugin register", "bao secrets enable", "bao auth enable"):
            self.assertNotIn(forbidden, source)

    def test_single_actuator_owns_every_plan_mutation_command(self) -> None:
        source = (ROOT / "codestra/change_kernel/actuator.py").read_text(encoding="utf-8")
        for required in ('"plugin", "register"', '"secrets", "enable"', '"auth", "enable"',
                         "-plugin-name=", '"policy", "write"', '"bao", "write"',
                         "kernel.intend(", "UNSUPPORTED_OR_DESTRUCTIVE_OPERATION"):
            self.assertIn(required, source)
        for forbidden in ('"delete"', '"disable"', '"destroy"', "operator"):
            self.assertNotIn(forbidden, source)

    def test_required_approver_is_kazan555(self) -> None:
        source = (ROOT / "scripts/verify_environment_approval.sh").read_text(encoding="utf-8")
        self.assertIn("kazan555", source)
        self.assertIn("/approvals", source)
        for suffix in ("runtime", "certify", "initialize", "backup", "restore"):
            self.assertIn(f'openbao-${{environment}}-{suffix}', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
