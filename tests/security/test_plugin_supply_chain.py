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
NOW = dt.datetime(2026, 9, 24, 12, 0, tzinfo=dt.timezone.utc)


def committed_report() -> dict:
    return json.loads(MODULE.REPORT.read_text(encoding="utf-8"))


def report_without_unknown() -> dict:
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
        scan_root: str | Path | None = None,
    ) -> tuple[int, int]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            return MODULE.validate(
                MODULE.SBOM,
                path,
                now=now,
                plugin_path=plugin_path,
                scan_root=scan_root,
            )

    def test_committed_plugin_has_zero_high_critical_after_known_unknown_is_removed(self) -> None:
        components, observations = self.validate_report(report_without_unknown())
        self.assertGreaterEqual(components, 50)
        self.assertEqual(observations, 0)

    def test_committed_plugin_accepts_reviewed_module_only_advisory(self) -> None:
        components, observations = MODULE.validate(MODULE.SBOM, MODULE.REPORT, now=NOW)
        self.assertGreaterEqual(components, 50)
        self.assertEqual(observations, 0)
        manifest = MODULE.load(MODULE.MANIFEST)
        controls = manifest.get("moduleOnlyAdvisoryControls", [])
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["vulnerabilityId"], "GO-2026-5932")
        self.assertEqual(controls[0]["module"], "golang.org/x/crypto")
        self.assertEqual(
            controls[0]["prohibitedPackagePrefix"],
            "golang.org/x/crypto/openpgp",
        )

    def test_high_critical_and_unknown_findings_fail_closed(self) -> None:
        for severity in ("HIGH", "CRITICAL", "UNKNOWN"):
            report = report_without_unknown()
            report["Results"][0].setdefault("Vulnerabilities", []).append(
                {"VulnerabilityID": "CVE-TEST", "PkgName": "test", "Severity": severity}
            )
            with self.subTest(severity=severity):
                with self.assertRaisesRegex(ValueError, f"CVE-TEST:test:{severity}"):
                    self.validate_report(report)

    def test_missing_or_unrecognised_severity_fails_closed(self) -> None:
        for severity in (None, "", "high", "NEGLIGIBLE"):
            report = report_without_unknown()
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
            (
                {"VulnerabilityID": "CVE-TEST", "Severity": "MEDIUM"},
                "plugin_finding_package_missing:CVE-TEST",
            ),
            (
                {"VulnerabilityID": "", "PkgName": "test", "Severity": "LOW"},
                "plugin_finding_vulnerability_id_missing",
            ),
            (
                {"VulnerabilityID": "CVE-TEST", "PkgName": "", "Severity": "LOW"},
                "plugin_finding_package_missing:CVE-TEST",
            ),
        )
        for finding, expected in cases:
            report = report_without_unknown()
            report["Results"][0].setdefault("Vulnerabilities", []).insert(0, finding)
            with self.subTest(finding=finding):
                with self.assertRaisesRegex(ValueError, expected):
                    self.validate_report(report)

    def test_malformed_report_fails_closed(self) -> None:
        report = report_without_unknown()
        report["Results"] = None
        with self.assertRaisesRegex(ValueError, "plugin_report_results_missing"):
            self.validate_report(report)

    def test_report_schema_and_artifact_type_are_pinned(self) -> None:
        report = report_without_unknown()
        report["SchemaVersion"] = 3
        with self.assertRaisesRegex(ValueError, "plugin_report_schema_drift"):
            self.validate_report(report)
        report = report_without_unknown()
        report["ArtifactType"] = "repository"
        with self.assertRaisesRegex(ValueError, "plugin_report_artifact_type_drift"):
            self.validate_report(report)

    def test_report_must_inventory_the_plugin_binary(self) -> None:
        cases = {
            "empty": lambda report: report.update(Results=[]),
            "other_binary": lambda report: report["Results"][0].update(Target="usr/bin/other"),
            "not_gobinary": lambda report: report["Results"][0].update(Type="gomod"),
        }
        for name, mutate in cases.items():
            report = report_without_unknown()
            mutate(report)
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, "plugin_report_binary_not_scanned"):
                    self.validate_report(report)

    def test_scan_root_binding_is_exact(self) -> None:
        manifest = MODULE.load(MODULE.MANIFEST)
        report = report_without_unknown()
        report["ArtifactName"] = "/runner/_temp/plugin-vulnerability"
        report["Results"][0]["Target"] = "codestra-jwt-replay"
        MODULE.require_report_scan_binding(
            report,
            manifest,
            "/runner/_temp/plugin-vulnerability",
        )
        with self.assertRaisesRegex(ValueError, "plugin_report_scan_root_drift"):
            MODULE.require_report_scan_binding(report, manifest, "/runner/_temp/other")

    def test_windows_scan_paths_normalize_consistently(self) -> None:
        self.assertEqual(
            MODULE.normalize_scan_path(r"C:\Runner\_temp\plugin-vulnerability"),
            "c:/Runner/_temp/plugin-vulnerability",
        )
        manifest = MODULE.load(MODULE.MANIFEST)
        report = report_without_unknown()
        report["ArtifactName"] = r"C:\Runner\_temp\plugin-vulnerability"
        report["Results"][0]["Target"] = r"bin\codestra-jwt-replay"
        MODULE.require_report_scan_binding(
            report,
            manifest,
            "c:/Runner/_temp/plugin-vulnerability",
        )

    def test_absolute_binary_target_cannot_escape_scan_root(self) -> None:
        manifest = MODULE.load(MODULE.MANIFEST)
        report = report_without_unknown()
        report["ArtifactName"] = r"C:\Runner\_temp\plugin-vulnerability"
        report["Results"][0]["Target"] = r"C:\other\codestra-jwt-replay"
        with self.assertRaisesRegex(ValueError, "plugin_report_binary_outside_scan_root"):
            MODULE.require_report_scan_binding(
                report,
                manifest,
                r"C:\Runner\_temp\plugin-vulnerability",
            )

    def test_exact_rebuilt_plugin_digest_is_required(self) -> None:
        manifest = MODULE.load(MODULE.MANIFEST)
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / manifest["command"]
            plugin.write_bytes(b"synthetic-rebuilt-plugin")
            synthetic_manifest = dict(manifest)
            synthetic_manifest["binarySha256"] = MODULE.sha256_file(plugin)
            MODULE.require_plugin_binary(plugin, synthetic_manifest)
            plugin.write_bytes(b"tampered-plugin")
            with self.assertRaisesRegex(ValueError, "plugin_binary_digest_drift"):
                MODULE.require_plugin_binary(plugin, synthetic_manifest)

    def test_validate_accepts_plugin_path_and_rejects_wrong_binary(self) -> None:
        manifest = MODULE.load(MODULE.MANIFEST)
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / manifest["command"]
            plugin.write_bytes(b"not-the-reviewed-plugin")
            with self.assertRaisesRegex(ValueError, "plugin_binary_digest_drift"):
                self.validate_report(report_without_unknown(), plugin_path=plugin)

    def test_scan_freshness_comes_from_created_at(self) -> None:
        report = report_without_unknown()
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
