from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PlanRuntimeContractTests(unittest.TestCase):
    def test_plan_reads_the_real_singular_cel_role_list_endpoint(self) -> None:
        source = (ROOT / "scripts/collect_live_state.sh").read_text(encoding="utf-8")
        self.assertIn('"auth/${mount}/cel/role"', source)
        self.assertNotIn('"auth/${mount}/cel/roles"', source)
        for forbidden in ("bao write", "bao delete", "bao policy write", "bao secrets enable"):
            self.assertNotIn(forbidden, source)

    def test_plan_binds_the_live_state_it_was_built_from(self) -> None:
        source = (ROOT / "scripts/plan.sh").read_text(encoding="utf-8")
        self.assertIn('scripts/collect_live_state.sh "$environment" "$live_dir"', source)
        self.assertIn("live-fingerprint", source)
        self.assertIn('--live-state-sha256 "$live_state_sha"', source)

    def test_isolated_integration_proves_role_compile_list_and_readback(self) -> None:
        source = (ROOT / "scripts/integration_test.sh").read_text(encoding="utf-8")
        for required in (
            "server -dev",
            'bao_exec write "auth/${mount}/cel/role/${role}"',
            'bao_exec list -format=json "auth/${mount}/cel/role"',
            'bao_exec read -format=json "auth/${mount}/cel/role/${role}"',
            "POLICY_WRITE_READBACK=PASS",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
