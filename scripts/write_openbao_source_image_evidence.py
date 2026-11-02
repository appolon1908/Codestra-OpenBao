#!/usr/bin/env python3
"""Create secret-free evidence for one protected OpenBao source-built OCI image."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ARCHIVE_MODULE = "github.com/moby/go-archive"
BLOCKED_GRPC_CVES = {"CVE-2026-84304", "CVE-2026-84445"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


KNOWN_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
MAX_SCAN_AGE = dt.timedelta(days=30)
MAX_CLOCK_SKEW = dt.timedelta(minutes=10)


def vulnerability_counts(document: Any) -> tuple[int, int, int, bool]:
    if not isinstance(document, dict) or type(document.get("SchemaVersion")) is not int or document["SchemaVersion"] != 2:
        raise ValueError("Trivy report must be a schema 2 object")
    results = document.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be a list")
    counts = {"CRITICAL": 0, "HIGH": 0, "UNKNOWN": 0}
    cve_present = False
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy result must be an object")
        if not isinstance(result.get("Target"), str) or not result["Target"].strip():
            raise ValueError("Trivy result target is missing")
        if not isinstance(result.get("Type"), str) or not result["Type"].strip():
            raise ValueError("Trivy result type is missing")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy Vulnerabilities must be a list or null")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Trivy finding must be an object")
            vulnerability_id = vulnerability.get("VulnerabilityID")
            package = vulnerability.get("PkgName")
            severity = vulnerability.get("Severity")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                raise ValueError("Trivy vulnerability identifier is missing")
            if not isinstance(package, str) or not package.strip():
                raise ValueError("Trivy vulnerability package is missing")
            if not isinstance(severity, str) or severity not in KNOWN_SEVERITIES:
                raise ValueError("Trivy vulnerability severity is missing or invalid")
            cve_present = cve_present or vulnerability_id in BLOCKED_GRPC_CVES
            if severity in counts:
                counts[severity] += 1
    return counts["CRITICAL"], counts["HIGH"], counts["UNKNOWN"], cve_present


def require_current_image_report(document: dict, image_reference: str) -> None:
    if document.get("ArtifactType") != "container_image":
        raise ValueError("Trivy report must describe a container image")
    metadata = document.get("Metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("RepoDigests"), list):
        raise ValueError("Trivy image digest metadata is missing")
    if image_reference not in metadata["RepoDigests"]:
        raise ValueError("Trivy report does not bind the exact image digest")
    scanner = document.get("Trivy")
    if not isinstance(scanner, dict) or scanner.get("Version") != "0.74.0":
        raise ValueError("Trivy report must use the reviewed scanner 0.74.0")
    created_at = document.get("CreatedAt")
    if not isinstance(created_at, str):
        raise ValueError("Trivy scan creation time is missing")
    created = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    if created.tzinfo is None:
        raise ValueError("Trivy scan creation time must be timezone aware")
    now = dt.datetime.now(dt.timezone.utc)
    if created > now + MAX_CLOCK_SKEW or now - created > MAX_SCAN_AGE:
        raise ValueError("Trivy scan is stale or dated in the future")
    if not any(result["Type"] == "gobinary" and Path(result["Target"]).name == "bao"
               for result in document["Results"]):
        raise ValueError("Trivy report did not scan the OpenBao binary")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--grpc-version", required=True)
    parser.add_argument("--archive-version", required=True)
    parser.add_argument("--dependency-overlay", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--signature-verification", type=Path, required=True)
    parser.add_argument("--provenance-verification", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not SHA_RE.fullmatch(args.source_sha) or not SHA_RE.fullmatch(args.source_tree):
        raise SystemExit("source SHA/tree must be full lowercase Git object IDs")
    if not DIGEST_RE.fullmatch(args.image_digest):
        raise SystemExit("image digest must be sha256:<64 lowercase hex>")
    for label, version in (("grpc-go", args.grpc_version), ("archive", args.archive_version)):
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise SystemExit(f"{label} version must be a semantic version without v")
    if args.archive_version != "0.3.2":
        raise SystemExit("archive module version must equal reviewed v0.3.2")
    if args.run_id <= 0 or args.run_attempt <= 0:
        raise SystemExit("workflow run identity must be positive")
    overlay = load_json(args.dependency_overlay)
    if not isinstance(overlay, dict) or overlay.get("status") != "PASS":
        raise SystemExit("dependency overlay evidence is missing or invalid")
    if overlay.get("module") != ARCHIVE_MODULE or overlay.get("new_version") != "0.3.2":
        raise SystemExit("dependency overlay does not bind reviewed archive module")

    report = load_json(args.scan)
    critical, high, unknown, cve_present = vulnerability_counts(report)
    image_repository = "ghcr.io/ingtrader21-spec/codestra-openbao"
    require_current_image_report(report, f"{image_repository}@{args.image_digest}")
    identity = (
        "https://github.com/ingtrader21-spec/Codestra-OpenBao/"
        ".github/workflows/openbao-source-image-authority.yml@refs/heads/production"
    )
    evidence = {
        "schema_version": 1,
        "status": "PASS" if not cve_present and critical == high == unknown == 0 else "FAIL",
        "source_sha": args.source_sha,
        "source_tree": args.source_tree,
        "source_dependency_version": args.grpc_version,
        "archive_module": ARCHIVE_MODULE,
        "archive_module_version": args.archive_version,
        "dependency_overlay_sha256": sha256(args.dependency_overlay),
        "runtime_target": "distroless",
        "image_repository": image_repository,
        "image_reference": f"{image_repository}@{args.image_digest}",
        "image_digest": args.image_digest,
        "image_dependency_version": args.grpc_version,
        "platform": "linux/amd64",
        "sbom": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/openbao.spdx.json",
            "sha256": sha256(args.sbom),
            "format": "spdx-json",
        },
        "vulnerability_scan": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/trivy.json",
            "sha256": sha256(args.scan),
            "cve_present": cve_present,
            "critical_count": critical,
            "high_count": high,
            "unknown_count": unknown,
            "scanned_at": report["CreatedAt"],
            "scanner_version": report["Trivy"]["Version"],
            "image_digest": args.image_digest,
        },
        "signature": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/signature-verification.json",
            "sha256": sha256(args.signature_verification),
            "verified": True,
            "certificate_identity": identity,
        },
        "provenance": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/provenance-verification.json",
            "sha256": sha256(args.provenance_verification),
            "verified": True,
            "subject_digest": args.image_digest,
            "source_sha": args.source_sha,
            "builder_identity": identity,
        },
        "workflow": {
            "repository": "ingtrader21-spec/Codestra-OpenBao",
            "path": ".github/workflows/openbao-source-image-authority.yml",
            "ref": "refs/heads/production",
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
        },
        "runtime_authorized": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"OPENBAO_IMAGE_EVIDENCE_STATUS={evidence['status']}")
    print(f"OPENBAO_IMAGE_CRITICAL_COUNT={critical}")
    print(f"OPENBAO_IMAGE_HIGH_COUNT={high}")
    print(f"OPENBAO_IMAGE_UNKNOWN_COUNT={unknown}")
    print(f"OPENBAO_IMAGE_BLOCKED_GRPC_CVE_PRESENT={'YES' if cve_present else 'NO'}")
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
