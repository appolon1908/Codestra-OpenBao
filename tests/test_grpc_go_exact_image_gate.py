#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_grpc_go_exact_image_gate.py"
SPEC = importlib.util.spec_from_file_location("grpc_image_gate", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SOURCE_SHA = "1" * 40
SOURCE_TREE = "2" * 40
IMAGE_DIGEST = "sha256:" + "3" * 64
ARTIFACT_SHA = "4" * 64
IDENTITY = (
    "https://github.com/appolon1908-hue/Codestra-OpenBao/"
    ".github/workflows/openbao-source-image-authority.yml@refs/heads/production"
)


def valid_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "PASS",
        "source_sha": SOURCE_SHA,
        "source_tree": SOURCE_TREE,
        "source_dependency_version": "1.83.2",
        "archive_module": "github.com/moby/go-archive",
        "archive_module_version": "0.3.2",
        "dependency_overlay_sha256": ARTIFACT_SHA,
        "runtime_target": "distroless",
        "image_repository": "ghcr.io/appolon1908-hue/codestra-openbao",
        "image_reference": (
            "ghcr.io/appolon1908-hue/codestra-openbao@" + IMAGE_DIGEST
        ),
        "image_digest": IMAGE_DIGEST,
        "image_dependency_version": "1.83.2",
        "platform": "linux/amd64",
        "sbom": {
            "reference": "artifact://openbao-image/sbom.spdx.json",
            "sha256": ARTIFACT_SHA,
            "format": "spdx-json",
        },
        "vulnerability_scan": {
            "reference": "artifact://openbao-image/trivy.json",
            "sha256": ARTIFACT_SHA,
            "cve_present": False,
            "critical_count": 0,
            "high_count": 0,
        },
        "signature": {
            "reference": "sigstore://openbao-image/signature.bundle.json",
            "sha256": ARTIFACT_SHA,
            "verified": True,
            "certificate_identity": IDENTITY,
        },
        "provenance": {
            "reference": "attestation://openbao-image/provenance",
            "sha256": ARTIFACT_SHA,
            "verified": True,
            "subject_digest": IMAGE_DIGEST,
            "source_sha": SOURCE_SHA,
            "builder_identity": IDENTITY,
        },
        "workflow": {
            "repository": "appolon1908-hue/Codestra-OpenBao",
            "path": ".github/workflows/openbao-source-image-authority.yml",
            "ref": "refs/heads/production",
            "run_id": 12345,
            "run_attempt": 1,
        },
        "runtime_authorized": False,
    }


class ExactImageGateTests(unittest.TestCase):
    def test_source_gate_matches_remediated_inputs(self) -> None:
        gate = MODULE.load_json(MODULE.GATE_PATH)
        minimum, source_version = MODULE.validate_gate(gate)
        self.assertEqual(minimum, "1.83.1")
        self.assertEqual(source_version, "1.83.2")
        self.assertEqual(gate["source_build"]["archive_module_version"], "0.3.2")
        self.assertEqual(gate["source_build"]["docker_target"], "distroless")
        self.assertEqual(gate["exact_image_gate"], "BLOCKED_PENDING_PROTECTED_BUILD")
        self.assertTrue(all(value is False for value in gate["activation"].values()))

    def test_version_ordering(self) -> None:
        self.assertLess(MODULE.version_tuple("1.82.1"), MODULE.version_tuple("1.83.1"))
        self.assertGreater(MODULE.version_tuple("1.83.2"), MODULE.version_tuple("1.83.1"))

    def test_parse_source_version_requires_exactly_one_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "go.mod"
            path.write_text(
                "module example.test/openbao\n\nrequire google.golang.org/grpc v1.83.2\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.parse_source_version(path), "1.83.2")
            path.write_text(
                "require (\n google.golang.org/grpc v1.83.2\n google.golang.org/grpc v1.83.1\n)\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                MODULE.parse_source_version(path)

    def test_valid_protected_image_evidence_passes(self) -> None:
        MODULE.validate_image_evidence(
            valid_evidence(),
            "1.83.1",
            "1.83.2",
            expected_source_sha=SOURCE_SHA,
            expected_source_tree=SOURCE_TREE,
        )

    def test_old_grpc_dependency_is_rejected(self) -> None:
        evidence = valid_evidence()
        evidence["image_dependency_version"] = "1.82.1"
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_old_archive_dependency_is_rejected(self) -> None:
        evidence = valid_evidence()
        evidence["archive_module_version"] = "0.2.0"
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_non_distroless_runtime_is_rejected(self) -> None:
        evidence = valid_evidence()
        evidence["runtime_target"] = "default"
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_digest_mismatch_is_rejected(self) -> None:
        evidence = valid_evidence()
        evidence["image_reference"] = (
            "ghcr.io/appolon1908-hue/codestra-openbao@sha256:" + "9" * 64
        )
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_unresolved_high_vulnerability_is_rejected(self) -> None:
        evidence = valid_evidence()
        scan = copy.deepcopy(evidence["vulnerability_scan"])
        assert isinstance(scan, dict)
        scan["high_count"] = 1
        evidence["vulnerability_scan"] = scan
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_wrong_workflow_identity_is_rejected(self) -> None:
        evidence = valid_evidence()
        signature = copy.deepcopy(evidence["signature"])
        assert isinstance(signature, dict)
        signature["certificate_identity"] = "https://example.invalid/untrusted"
        evidence["signature"] = signature
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_runtime_self_authorization_is_rejected(self) -> None:
        evidence = valid_evidence()
        evidence["runtime_authorized"] = True
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")

    def test_placeholder_artifact_reference_is_rejected(self) -> None:
        evidence = valid_evidence()
        sbom = copy.deepcopy(evidence["sbom"])
        assert isinstance(sbom, dict)
        sbom["reference"] = "REPLACE_WITH_SBOM"
        evidence["sbom"] = sbom
        with self.assertRaises(ValueError):
            MODULE.validate_image_evidence(evidence, "1.83.1", "1.83.2")


if __name__ == "__main__":
    unittest.main()
