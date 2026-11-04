#!/usr/bin/env python3
"""Regression contract for the patched OpenBao source-image dependency."""
from __future__ import annotations

import hashlib
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

    def test_failed_scan_retains_hash_bound_diagnostics_without_accepting_findings(self) -> None:
        workflow = WORKFLOW.read_text()
        script = textwrap.dedent(workflow.split("python3 - <<'SOURCE_IMAGE_DIAGNOSTICS'\n", 1)[1].split(
            "\n          SOURCE_IMAGE_DIAGNOSTICS", 1)[0])
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"SchemaVersion": 2, "ArtifactType": "container_image",
                      "ArtifactName": "codestra-openbao:source-validation",
                      "Results": [{"Target": "usr/bin/bao", "Type": "gobinary", "Vulnerabilities": [{
                          "VulnerabilityID": "GO-2026-5932", "PkgName": "golang.org/x/crypto",
                          "InstalledVersion": "synthetic", "FixedVersion": "synthetic-fixed", "Severity": "HIGH"}]}]}
            for name in ("dependency-overlay.json", "bao-go-version.txt", "openbao.spdx.json", "trivy-version.json"):
                (root / name).write_text("synthetic public evidence\n")
            (root / "trivy.json").write_text(json.dumps(report))
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            env = {**os.environ, "RUNNER_TEMP": str(root), "EXPECTED_SHA": head, "SOURCE_TREE": tree,
                   "GITHUB_REPOSITORY": "appolon1908/Codestra-OpenBao", "GITHUB_RUN_ID": "123",
                   "GITHUB_RUN_ATTEMPT": "2", "LOCAL_IMAGE": report["ArtifactName"]}
            result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            diagnostic = json.loads((root / "source-image-diagnostics.json").read_text())
            self.assertEqual(diagnostic["source_sha"], head)
            self.assertEqual(diagnostic["source_tree"], tree)
            self.assertEqual(diagnostic["run_attempt"], 2)
            self.assertTrue(diagnostic["diagnostic_only"])
            self.assertFalse(diagnostic["runtime_authorized"])
            self.assertEqual(diagnostic["files_sha256"], {n: hashlib.sha256(b).hexdigest() for n, b in before.items()})
            self.assertEqual(before, {n: (root / n).read_bytes() for n in before})
            gate = subprocess.run([sys.executable, "-c", self._scan_script(), str(root / "trivy.json")],
                                  cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertNotEqual(gate.returncode, 0)
            self.assertIn("GO-2026-5932", gate.stderr)
            for changed in ({"EXPECTED_SHA": "0" * 40}, {"SOURCE_TREE": "0" * 40}):
                with self.subTest(changed=changed):
                    (root / "source-image-diagnostics.json").unlink(missing_ok=True)
                    denied = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env={**env, **changed},
                                            capture_output=True, text=True)
                    self.assertNotEqual(denied.returncode, 0)
                    self.assertFalse((root / "source-image-diagnostics.json").exists())
        upload = workflow.split("- name: Upload bounded source-image validation evidence", 1)[1].split(
            "\n  protected-image-release:", 1)[0]
        self.assertIn("if: ${{ always() }}", upload)
        self.assertNotIn("continue-on-error", workflow.split("\n  protected-image-release:", 1)[0])
        self.assertIn("${{ env.EXPECTED_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}", upload)
        self.assertIn("${{ runner.temp }}/trivy.json", upload)
        self.assertIn("${{ runner.temp }}/source-image-diagnostics.json", upload)

    def test_both_binaries_require_fixed_jose(self) -> None:
        self.assertEqual(WORKFLOW.read_text().count(r"github.com/go-jose/go-jose/v4[[:space:]]+v4\\.1\\.6"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
