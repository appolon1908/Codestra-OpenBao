from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DriftContractTests(unittest.TestCase):
    def test_drift_is_read_only_and_never_reconciles(self) -> None:
        source = (ROOT / "scripts/drift.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/plan.sh", source)
        self.assertIn("codestra_openbao_drift_detected", source)
        for forbidden in ("scripts/apply.sh", "bao write", "bao delete", "docker compose up"):
            self.assertNotIn(forbidden, source)

    def test_runtime_verification_never_reads_secret_values(self) -> None:
        source = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
        self.assertNotIn("bao kv get", source)
        self.assertNotIn("codestra/data/", source)
        self.assertIn("NATIVE_PUBLIC_PORTS=0", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
