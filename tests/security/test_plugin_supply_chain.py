from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def passing_report() -> dict:
    report = committed_report()
    for result in report["Results"]:
        result["Vulnerabilities"] = [
            finding
            for finding in result.get("Vulnerabilities") or []
            if finding["Severity"] != "UNKNOWN"
        ]
    return report


class PluginSupplyChainTests(unittest.TestCase):
    def validate_report(
        self,
        report: dict,
        now: dt.datetime = NOW,
        *,
        plugin_path: Path | None = None,
    ) -> tuple[int, int]:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            return MODULE.validate(MODULE.SBOM, path, now=now, plugin_path=plugin_path)

    def test_committed_plugin_has_zero_high_critical(self) -> None:
        components, observations = self.validate_report(passing_report())
        self.assertGreaterEqual(components, 50)
        self.assertEqual(observations, 0)

    def test_fresh_empty_or_unrelated_report_cannot_certify_plugin(self) -> None:
        report = passing_report()
        report["Results"] = []
        with self.assertRaisesRegex(ValueError, "plugin_report_target_missing"):
            self.validate_report(report)

        report = passing_report()
        report["Results"][0]["Target"] = "unrelated-binary"
        with self.assertRaisesRegex(ValueError, "plugin_report_target_drift"):
            self.validate_report(report)

    def test_report_schema_and_scanner_identity_fail_closed(self) -> None:
        cases = (
            ("SchemaVersion", 1, "plugin_report_schema_drift"),
            ("ArtifactType", "container_image", "plugin_report_artifact_type_drift"),
            ("Trivy", {}, "plugin_report_scanner_identity_drift"),
            ("Trivy", {"Version": "0.75.0"}, "plugin_report_scanner_identity_drift"),
        )
        for field, value, expected in cases:
            report = passing_report()
            report[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, expected):
                    self.validate_report(report)

    def test_report_package_inventory_is_bound_to_sbom(self) -> None:
        report = passing_report()
        report["Results"][0]["Packages"].pop()
        with self.assertRaisesRegex(ValueError, "plugin_report_inventory_drift"):
            self.validate_report(report)

    def test_rebuilt_plugin_digest_and_scan_root_are_bound(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            plugin = root / "codestra-jwt-replay"
            plugin.write_bytes(b"exact rebuilt plugin fixture")
            digest = hashlib.sha256(plugin.read_bytes()).hexdigest()

            manifest = json.loads(MODULE.MANIFEST.read_text(encoding="utf-8"))
            manifest["binarySha256"] = digest
            manifest_path = root / "plugin.v1.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            sbom = json.loads(MODULE.SBOM.read_text(encoding="utf-8"))
            sbom["metadata"]["component"]["version"] = f"sha256:{digest}"
            sbom_path = root / "plugin.cdx.json"
            sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

            report = passing_report()
            report["ArtifactName"] = str(root)
            report_path = root / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            with mock.patch.object(MODULE, "MANIFEST", manifest_path):
                MODULE.validate(sbom_path, report_path, now=NOW, plugin_path=plugin)
                report["ArtifactName"] = str(root / "unrelated-root")
                report_path.write_text(json.dumps(report), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "plugin_report_artifact_root_drift"):
                    MODULE.validate(sbom_path, report_path, now=NOW, plugin_path=plugin)

                report["ArtifactName"] = str(root)
                report_path.write_text(json.dumps(report), encoding="utf-8")
                plugin.write_bytes(b"different artifact")
                with self.assertRaisesRegex(ValueError, "plugin_artifact_digest_drift"):
                    MODULE.validate(sbom_path, report_path, now=NOW, plugin_path=plugin)

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

    def test_missing_finding_identity_fields_fail_closed(self) -> None:
        cases = (
            ({"PkgName": "test", "Severity": "LOW"}, "plugin_finding_vulnerability_id_missing"),
            ({"VulnerabilityID": "CVE-TEST", "Severity": "MEDIUM"}, "plugin_finding_package_missing:CVE-TEST"),
            ({"VulnerabilityID": "", "PkgName": "test", "Severity": "LOW"}, "plugin_finding_vulnerability_id_missing"),
            ({"VulnerabilityID": "CVE-TEST", "PkgName": "", "Severity": "LOW"}, "plugin_finding_package_missing:CVE-TEST"),
        )
        for finding, expected in cases:
            report = committed_report()
            report["Results"][0].setdefault("Vulnerabilities", []).insert(0, finding)
            with self.subTest(finding=finding):
                with self.assertRaisesRegex(ValueError, expected):
                    self.validate_report(report)

    def test_malformed_report_fails_closed(self) -> None:
        report = committed_report()
        report["Results"] = None
        with self.assertRaisesRegex(ValueError, "plugin_report_results_missing"):
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
