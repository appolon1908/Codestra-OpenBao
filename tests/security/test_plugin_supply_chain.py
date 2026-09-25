from __future__ import annotations

import datetime as dt
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_plugin_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("verify_plugin_supply_chain", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
# Fixed evaluation instant so the tests do not depend on the wall clock.
NOW = dt.datetime(2026, 9, 24, 12, 0, tzinfo=dt.timezone.utc)


def committed_report() -> dict:
    return json.loads(MODULE.REPORT.read_text(encoding="utf-8"))


class PluginSupplyChainTests(unittest.TestCase):
    def validate_report(self, report: dict, now: dt.datetime = NOW) -> tuple[int, int]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            return MODULE.validate(MODULE.SBOM, path, now=now)

    def test_committed_plugin_has_zero_high_critical(self) -> None:
        report = committed_report()
        for result in report["Results"]:
            result["Vulnerabilities"] = [
                finding
                for finding in result.get("Vulnerabilities") or []
                if finding["Severity"] != "UNKNOWN"
            ]
        components, observations = self.validate_report(report)
        self.assertGreaterEqual(components, 50)
        self.assertEqual(observations, 0)

    def test_committed_plugin_exposes_the_unscored_finding(self) -> None:
        """Blocker record: GO-2026-5932 (x/crypto/openpgp, UNKNOWN) was skipped before hardening."""
        with self.assertRaisesRegex(
            ValueError, r"plugin_unresolved_high_critical:1:GO-2026-5932:golang.org/x/crypto:UNKNOWN$"
        ):
            MODULE.validate(MODULE.SBOM, MODULE.REPORT, now=NOW)

    def test_high_finding_fails_closed(self) -> None:
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            report = committed_report()
            report["Results"][0].setdefault("Vulnerabilities", []).append(
                {"VulnerabilityID": "CVE-TEST", "PkgName": "test", "Severity": severity}
            )
            with self.subTest(severity=severity):
                with self.assertRaisesRegex(ValueError, f"CVE-TEST:test:{severity}"):
                    self.validate_report(report)

    def test_missing_or_unrecognised_severity_fails_closed(self) -> None:
        for severity in (None, "", "high", "NEGLIGIBLE"):
            report = committed_report()
            item = {"VulnerabilityID": "CVE-TEST", "PkgName": "test"}
            if severity is not None:
                item["Severity"] = severity
            report["Results"][0].setdefault("Vulnerabilities", []).insert(0, item)
            with self.subTest(severity=severity):
                with self.assertRaisesRegex(ValueError, "plugin_unrecognized_severity:CVE-TEST:test"):
                    self.validate_report(report)

    def test_malformed_report_fails_closed(self) -> None:
        report = committed_report()
        report["Results"] = None
        with self.assertRaisesRegex(ValueError, "plugin_report_results_missing"):
            self.validate_report(report)

    def test_report_must_inventory_the_plugin_binary(self) -> None:
        cases = {
            "empty": lambda report: report.update(Results=[]),
            "other_binary": lambda report: report["Results"][0].update(Target="usr/bin/other"),
            "not_gobinary": lambda report: report["Results"][0].update(Type="gomod"),
        }
        for name, mutate in cases.items():
            report = committed_report()
            mutate(report)
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, "plugin_report_binary_not_scanned"):
                    self.validate_report(report)

    def test_rootfs_target_path_is_accepted(self) -> None:
        report = committed_report()
        report["Results"][0]["Target"] = "tmp/plugin-vulnerability/codestra-jwt-replay"
        with self.assertRaisesRegex(ValueError, "GO-2026-5932"):
            self.validate_report(report)

    def test_report_schema_is_pinned(self) -> None:
        report = committed_report()
        report["SchemaVersion"] = 3
        with self.assertRaisesRegex(ValueError, "plugin_report_schema_drift"):
            self.validate_report(report)

    def test_scan_freshness_comes_from_created_at(self) -> None:
        report = committed_report()
        created = dt.datetime.fromisoformat(report["CreatedAt"])
        with self.assertRaisesRegex(ValueError, "plugin_scan_stale"):
            self.validate_report(report, now=created + dt.timedelta(days=31))
        with self.assertRaisesRegex(ValueError, "plugin_scan_created_in_future"):
            self.validate_report(report, now=created - dt.timedelta(hours=1))
        del report["CreatedAt"]
        with self.assertRaisesRegex(ValueError, "plugin_scan_created_at_missing"):
            self.validate_report(report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
