#!/usr/bin/env python3
"""Regression contract for the patched OpenBao source-image dependency."""
from __future__ import annotations

import json
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
        module_pattern = r"golang.org/x/text[[:space:]]+v0\\.42\\.0"
        self.assertEqual(workflow.count(module_pattern), 2)
        self.assertEqual(workflow.count("python3 tests/test_source_image_xtext_gate.py"), 2)
        self.assertIn('"golang.org/x/text": "v0.42.0"', OVERLAY.read_text())

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
                report.write_text(json.dumps({"Results": [{"Vulnerabilities": vulnerabilities}]}))
                return subprocess.run(
                    [sys.executable, "-c", source, str(report)],
                    capture_output=True, text=True, check=False,
                )
            self.assertEqual(run([]).returncode, 0)
            self.assertNotEqual(
                run([{"VulnerabilityID": "CVE-2026-56851", "Severity": "UNKNOWN", "PkgName": "golang.org/x/text"}]).returncode, 0
            )
            self.assertNotEqual(
                run([{"VulnerabilityID": "CVE-2026-56851", "Severity": "LOW", "PkgName": "golang.org/x/text"}]).returncode, 0
            )
            self.assertNotEqual(
                run([{"VulnerabilityID": "new-unknown-vulnerability", "Severity": "UNKNOWN", "PkgName": "third-party"}]).returncode, 0
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
