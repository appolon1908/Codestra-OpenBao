from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/validate_openbao_image_upgrade_candidate.py"
SPEC = importlib.util.spec_from_file_location("validate_upgrade_candidate", SOURCE)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class UpgradeCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = json.loads(
            (ROOT / "artifacts/security/openbao-image-upgrade-candidate-20261008.json").read_text()
        )
        cls.raw = (ROOT / cls.summary["report_path"]).read_bytes()
        cls.report = json.loads(cls.raw)

    def evaluate(self, summary=None, report=None, raw=None, now=None):
        return GATE.validate(
            summary if summary is not None else copy.deepcopy(self.summary),
            report if report is not None else copy.deepcopy(self.report),
            raw if raw is not None else self.raw,
            now=now,
        )

    def test_real_immutable_candidate_is_not_misrepresented_as_releasable(self) -> None:
        status = self.evaluate()
        self.assertEqual(status["status"], "BLOCKED")
        self.assertEqual(status["blockers"], ["GO-2026-5932:golang.org/x/crypto:UNKNOWN"])
        self.assertEqual(status["high_count"], 0)
        self.assertEqual(status["critical_count"], 0)

    def test_sha256_cannot_be_changed_or_reused(self) -> None:
        summary = copy.deepcopy(self.summary)
        summary["report_sha256"] = "0" * 64
        with self.assertRaisesRegex(GATE.CandidateError, "integrity"):
            self.evaluate(summary=summary)
        summary = copy.deepcopy(self.summary)
        summary["image_reference"] = summary["image_reference"].replace("sha256:", "tag:")
        with self.assertRaisesRegex(GATE.CandidateError, "mutable"):
            self.evaluate(summary=summary)

    def test_unknown_findings_cannot_be_downgraded(self) -> None:
        summary = copy.deepcopy(self.summary)
        summary["unknown_count"] = 0
        with self.assertRaisesRegex(GATE.CandidateError, "unknown_count"):
            self.evaluate(summary=summary)
        summary = copy.deepcopy(self.summary)
        summary["unknown_findings"] = []
        with self.assertRaisesRegex(GATE.CandidateError, "unscored"):
            self.evaluate(summary=summary)

    def test_authorizations_and_stale_scans_are_rejected(self) -> None:
        for field in ("production_go", "promotion_authorized"):
            summary = copy.deepcopy(self.summary)
            summary[field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(GATE.CandidateError, "authorize"):
                    self.evaluate(summary=summary)
        with self.assertRaisesRegex(GATE.CandidateError, "freshness"):
            self.evaluate(now=dt.datetime(2026, 12, 1, tzinfo=dt.timezone.utc))

    def test_unscored_severity_cannot_be_hidden(self) -> None:
        report = copy.deepcopy(self.report)
        target = next(
            v for result in report["Results"] for v in result.get("Vulnerabilities") or []
            if v["VulnerabilityID"] == "GO-2026-5932"
        )
        target["Severity"] = None
        raw = json.dumps(report).encode()
        summary = copy.deepcopy(self.summary)
        summary["report_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(GATE.CandidateError, "missing severity"):
            self.evaluate(summary=summary, report=report, raw=raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
