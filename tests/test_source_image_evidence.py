from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/write_openbao_source_image_evidence.py"
DIGEST = "sha256:" + "3" * 64
REPOSITORY = "ghcr.io/ingtrader21-spec/codestra-openbao"


def report(findings=None):
    return {"SchemaVersion": 2, "Trivy": {"Version": "0.74.0"}, "CreatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "ArtifactName": REPOSITORY + "@" + DIGEST, "ArtifactType": "container_image",
            "Metadata": {"RepoDigests": [REPOSITORY + "@" + DIGEST]},
            "Results": [{"Target": "bin/bao", "Type": "gobinary", "Vulnerabilities": findings}]}


def finding(severity="UNKNOWN", identifier="GO-2026-5932"):
    return {"VulnerabilityID": identifier, "PkgName": "golang.org/x/crypto", "Severity": severity}


class SourceImageEvidenceTests(unittest.TestCase):
    def run_writer(self, directory, document):
        scan = directory / "trivy.json"
        scan.write_text(json.dumps(document))
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"status": "PASS", "module": "github.com/moby/go-archive", "new_version": "0.3.2"}))
        for name in ("sbom", "signature", "provenance"):
            (directory / name).write_text("{}")
        output = directory / "evidence.json"
        result = subprocess.run([
            sys.executable, "-B", str(SCRIPT), "--source-sha", "1" * 40,
            "--source-tree", "2" * 40, "--image-digest", DIGEST,
            "--grpc-version", "1.83.2", "--archive-version", "0.3.2",
            "--dependency-overlay", str(overlay), "--sbom", str(directory / "sbom"),
            "--scan", str(scan), "--signature-verification", str(directory / "signature"),
            "--provenance-verification", str(directory / "provenance"),
            "--run-id", "123", "--run-attempt", "1", "--output", str(output)
        ], capture_output=True, text=True, timeout=30)
        return result, json.loads(output.read_text()) if output.exists() else None

    def test_unknown_unfixed_advisory_produces_failed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result, evidence = self.run_writer(Path(directory), report([finding()]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence["status"], "FAIL")
        self.assertEqual(evidence["vulnerability_scan"]["unknown_count"], 1)
        self.assertFalse(evidence["runtime_authorized"])

    def test_clean_and_medium_reports_remain_valid(self):
        for findings in (None, [], [finding("MEDIUM")]):
            with self.subTest(findings=findings), tempfile.TemporaryDirectory() as directory:
                result, evidence = self.run_writer(Path(directory), report(findings))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(evidence["status"], "PASS")
                self.assertEqual(evidence["vulnerability_scan"]["unknown_count"], 0)

    def test_known_grpc_advisory_remains_blocked_at_any_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            result, evidence = self.run_writer(Path(directory), report([finding("LOW", "CVE-2026-84304")]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(evidence["status"], "FAIL")

    def test_malformed_reports_never_produce_pass_evidence(self):
        documents = [None, {}, {"SchemaVersion": 2}, {"SchemaVersion": 2, "Results": None},
                     {"SchemaVersion": 2, "Results": [None]},
                     report([None]), report([{}]), report([finding(None)]),
                     report([finding("high")]), report([finding("UNASSIGNED")])]
        bad_package = report([finding()])
        bad_package["Results"][0]["Vulnerabilities"][0]["PkgName"] = ""
        documents.append(bad_package)
        wrong_schema = report()
        wrong_schema["SchemaVersion"] = 1
        documents.append(wrong_schema)
        for document in documents:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as directory:
                result, evidence = self.run_writer(Path(directory), document)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(evidence)

    def test_wrong_or_stale_image_observation_is_refused(self):
        for field, value in (("CreatedAt", "2020-01-01T00:00:00Z"),
                             ("CreatedAt", "2099-01-01T00:00:00Z"),
                             ("CreatedAt", "2026-10-28T00:00:00"),
                             ("ArtifactType", "filesystem")):
            document = report()
            document[field] = value
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                result, evidence = self.run_writer(Path(directory), document)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(evidence)
        for results in ([], [{"Target": "other", "Type": "gobinary", "Vulnerabilities": None}]):
            document = report()
            document["Results"] = results
            with self.subTest(results=results), tempfile.TemporaryDirectory() as directory:
                result, evidence = self.run_writer(Path(directory), document)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(evidence)
        document = report()
        document["Trivy"]["Version"] = "0.75.0"
        with tempfile.TemporaryDirectory() as directory:
            result, evidence = self.run_writer(Path(directory), document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(evidence)
        document = report()
        document["Metadata"]["RepoDigests"] = [REPOSITORY + "@sha256:" + "9" * 64]
        with tempfile.TemporaryDirectory() as directory:
            result, evidence = self.run_writer(Path(directory), document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
