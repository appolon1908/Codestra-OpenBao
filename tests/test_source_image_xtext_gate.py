#!/usr/bin/env python3
"""Regression contract for the patched OpenBao source-image dependency."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/openbao-source-image-authority.yml"
OVERLAY = ROOT / "scripts/prepare_openbao_source_build.py"


class SourceImageXTextGateTests(unittest.TestCase):
    def test_source_build_requires_exact_patched_go_module_in_both_paths(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        module_pattern = r"golang.org/x/text[[:space:]]+v0\\.43\\.0"
        self.assertEqual(workflow.count(module_pattern), 2)
        self.assertEqual(workflow.count("python3 tests/test_source_image_xtext_gate.py"), 2)
        self.assertIn('"golang.org/x/text": "v0.43.0"', OVERLAY.read_text())

    @staticmethod
    def _scan_script() -> str:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        marker = 'python3 - "$""{RUNNER_TEMP}/trivy.json" <<\'PY\'\n'.replace('$""', '$')
        assert workflow.count(marker) == 1
        part = workflow.split(marker, 1)[1].split("\n          PY", 1)[0]
        return textwrap.dedent(part)

    def test_unknown_cve_remains_blocked_even_if_other_findings_clean(self) -> None:
        source = self._scan_script()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "trivy.json"
            def run(vulnerabilities: list[dict]) -> subprocess.CompletedProcess[str]:
                report.write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": "codestra-openbao:source-validation", "Results": [{"Target": "usr/bin/bao", "Type": "gobinary", "Vulnerabilities": vulnerabilities}]}))
                return subprocess.run(
                    [sys.executable, "-c", source, str(report)],
                    capture_output=True, text=True, check=False, cwd=ROOT,
                    env={**os.environ, "LOCAL_IMAGE": "codestra-openbao:source-validation"},
                )
            self.assertEqual(run([]).returncode, 0)
            self.assertNotEqual(
                run([{"VulnerabilityID": "CVE-2026-56851", "Severity": "UNKNOWN", "PkgName": "golang.org/x/text"}]).returncode, 0
            )
            self.assertNotEqual(
                run([{"VulnerabilityID": "CVE-2026-56851", "Severity": "LOW", "PkgName": "golang.org/x/text"}]).returncode, 0
            )
            self.assertNotEqual(
                run([{"VulnerabilityID": "CVE-2026-84445", "Severity": "LOW", "PkgName": "google.golang.org/grpc"}]).returncode, 0
            )
            self.assertNotEqual(
                run([{"VulnerabilityID": "new-unknown-vulnerability", "Severity": "UNKNOWN", "PkgName": "third-party"}]).returncode, 0
            )


    def test_all_scans_include_unfixed_findings(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertNotIn("--ignore-unfixed", workflow)
        self.assertEqual(workflow.count("trivy image --scanners vuln"), 2)

    def test_local_scan_rejects_malformed_or_wrong_image_evidence(self) -> None:
        source = self._scan_script()
        valid = {"SchemaVersion": 2, "ArtifactType": "container_image",
                 "ArtifactName": "codestra-openbao:source-validation",
                 "Results": [{"Target": "usr/bin/bao", "Type": "gobinary", "Vulnerabilities": []}]}
        documents = [{}, {**valid, "Results": None}, {**valid, "Results": []},
                     {**valid, "ArtifactName": "other:image"},
                     {**valid, "Results": [{"Target": "usr/bin/bao", "Type": "gobinary", "Vulnerabilities": [None]}]},
                     {**valid, "Results": [{"Target": "usr/bin/bao", "Type": "gobinary",
                       "Vulnerabilities": [{"VulnerabilityID": "unscored", "PkgName": "package", "Severity": None}]}]}]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "trivy.json"
            for document in documents:
                report.write_text(json.dumps(document))
                result = subprocess.run([sys.executable, "-B", "-c", source, str(report)],
                                        cwd=ROOT, capture_output=True, text=True,
                                        env={**os.environ, "LOCAL_IMAGE": "codestra-openbao:source-validation"})
                with self.subTest(document=document):
                    self.assertNotEqual(result.returncode, 0)

    def test_both_binaries_require_fixed_jose(self) -> None:
        self.assertEqual(WORKFLOW.read_text().count(r"github.com/go-jose/go-jose/v4[[:space:]]+v4\\.1\\.6"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
