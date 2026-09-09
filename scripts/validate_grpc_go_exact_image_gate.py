#!/usr/bin/env python3
"""Fail-closed source and exact-image evidence gate for CVE-2026-84304."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "codestra" / "vulnerability-gates" / "grpc-go-cve-2026-84304.v1.json"
VERSION_RE = re.compile(
    r"(?m)^\s*(?:require\s+)?google\.golang\.org/grpc\s+v(\d+\.\d+\.\d+)(?:\s|$)"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_REPOSITORY = "ghcr.io/appolon1908-hue/codestra-openbao"
WORKFLOW_PATH = ".github/workflows/openbao-source-image-authority.yml"
WORKFLOW_REF = "refs/heads/production"
WORKFLOW_IDENTITY = (
    "https://github.com/appolon1908-hue/Codestra-OpenBao/"
    ".github/workflows/openbao-source-image-authority.yml@refs/heads/production"
)
DISTROLESS_BASE = (
    "gcr.io/distroless/static:nonroot@sha256:"
    "f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6"
)
ARCHIVE_MODULE = "github.com/moby/go-archive"
ARCHIVE_VERSION = "0.3.2"
OVERLAY_SCRIPT = "scripts/prepare_openbao_source_build.py"


def fail(message: str) -> None:
    print(f"OPENBAO_GRPC_GO_GATE_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def version_tuple(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise ValueError(f"invalid semantic version: {value}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def parse_source_version(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    matches = VERSION_RE.findall(content)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one grpc-go module declaration, found {len(matches)}"
        )
    return matches[0]


def nonempty_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    upper = value.upper()
    return not any(token in upper for token in ("REPLACE", "UNKNOWN", "PENDING", "TODO"))


def require_false_map(value: Any, label: str) -> None:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{label} must be a non-empty object")
    enabled = sorted(name for name, state in value.items() if state is not False)
    if enabled:
        raise ValueError(f"{label} must remain false: {enabled}")


def validate_gate(gate: dict[str, Any]) -> tuple[str, str]:
    if gate.get("schema_version") != 1 or gate.get("cve") != "CVE-2026-84304":
        raise ValueError("gate identity mismatch")
    if gate.get("module") != "google.golang.org/grpc":
        raise ValueError("module authority mismatch")

    minimum = str(gate.get("minimum_remediated_version", ""))
    source_version = parse_source_version(
        ROOT / str(gate.get("source_module_file", ""))
    )
    if version_tuple(source_version) < version_tuple(minimum):
        raise ValueError("source grpc-go dependency is below the remediated version")
    if gate.get("source_dependency_version") != source_version:
        raise ValueError("recorded source dependency version differs from go.mod")
    if gate.get("source_dependency_gate") != "PASS":
        raise ValueError("remediated source dependency gate must be PASS")

    expected_build = {
        "build_script": "upstream/scripts/build.sh",
        "dependency_overlay_script": OVERLAY_SCRIPT,
        "archive_module": ARCHIVE_MODULE,
        "archive_module_version": ARCHIVE_VERSION,
        "dockerfile": "upstream/Dockerfile",
        "docker_target": "distroless",
        "runtime_base": DISTROLESS_BASE,
        "go_version_file": "upstream/.go-version",
        "image_repository": IMAGE_REPOSITORY,
        "validation_workflow": WORKFLOW_PATH,
        "protected_release_branch": "production",
        "protected_environment": "openbao-release",
        "certificate_identity": WORKFLOW_IDENTITY,
    }
    if gate.get("source_build") != expected_build:
        raise ValueError("source image build authority mismatch")
    for relative in (
        expected_build["build_script"],
        expected_build["dependency_overlay_script"],
        expected_build["dockerfile"],
        expected_build["go_version_file"],
        expected_build["validation_workflow"],
    ):
        if not (ROOT / relative).is_file():
            raise ValueError(f"source image authority file is missing: {relative}")
    dockerfile = (ROOT / expected_build["dockerfile"]).read_text(encoding="utf-8")
    if f"FROM {DISTROLESS_BASE} AS distroless" not in dockerfile:
        raise ValueError("digest-pinned distroless runtime target is missing")

    vex = gate.get("vex")
    if not isinstance(vex, dict):
        raise ValueError("VEX boundary is missing")
    if vex.get("temporary_source_only_disposition_allowed") is not False:
        raise ValueError("temporary source-only VEX cannot authorize the image gate")
    if vex.get("runtime_authority_allowed") is not False:
        raise ValueError("VEX cannot authorize runtime activation")
    expiry_text = str(vex.get("expires_at", ""))
    try:
        expiry = dt.datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid VEX expiry: {exc}") from exc
    if expiry.tzinfo is None:
        raise ValueError("VEX expiry must be timezone-aware")

    require_false_map(gate.get("activation"), "activation")
    artifact_fields = (
        "image_sbom_reference",
        "image_provenance_reference",
        "image_signature_reference",
        "image_scan_reference",
    )
    digest = gate.get("exact_image_digest")
    image_version = gate.get("image_dependency_version")
    committed_complete = (
        bool(DIGEST_RE.fullmatch(str(digest or "")))
        and isinstance(image_version, str)
        and version_tuple(image_version) >= version_tuple(minimum)
        and all(nonempty_reference(gate.get(name)) for name in artifact_fields)
    )
    status = gate.get("exact_image_gate")
    if status == "PASS":
        if not committed_complete:
            raise ValueError("exact image gate claims PASS without complete committed evidence")
    elif status == "BLOCKED_PENDING_PROTECTED_BUILD":
        if any(
            gate.get(name) is not None
            for name in ("exact_image_digest", "image_dependency_version", *artifact_fields)
        ):
            raise ValueError("blocked image gate must not carry partial artifact authority")
    else:
        raise ValueError("unsupported exact image gate state")
    if gate.get("evidence_commit_required") is not True:
        raise ValueError("protected build evidence must require a reviewed evidence commit")
    return minimum, source_version


def require_artifact(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} evidence must be an object")
    if not nonempty_reference(value.get("reference")):
        raise ValueError(f"{label} reference is missing or placeholder")
    if not HEX_RE.fullmatch(str(value.get("sha256", ""))):
        raise ValueError(f"{label} SHA-256 is malformed")
    return value


def validate_image_evidence(
    evidence: dict[str, Any],
    minimum: str,
    source_version: str,
    expected_source_sha: str | None = None,
    expected_source_tree: str | None = None,
) -> None:
    if evidence.get("schema_version") != 1 or evidence.get("status") != "PASS":
        raise ValueError("image evidence identity/status mismatch")
    source_sha = str(evidence.get("source_sha", ""))
    source_tree = str(evidence.get("source_tree", ""))
    if not SHA_RE.fullmatch(source_sha) or not SHA_RE.fullmatch(source_tree):
        raise ValueError("image evidence source SHA/tree is malformed")
    if expected_source_sha and source_sha != expected_source_sha:
        raise ValueError("image evidence source SHA differs from protected source")
    if expected_source_tree and source_tree != expected_source_tree:
        raise ValueError("image evidence source tree differs from protected source")
    if evidence.get("source_dependency_version") != source_version:
        raise ValueError("image evidence grpc-go version differs from protected source")
    if evidence.get("archive_module") != ARCHIVE_MODULE:
        raise ValueError("image evidence archive-module authority mismatch")
    if evidence.get("archive_module_version") != ARCHIVE_VERSION:
        raise ValueError("image evidence archive module is not security-fixed")
    if evidence.get("runtime_target") != "distroless":
        raise ValueError("image evidence runtime target is not distroless")

    digest = str(evidence.get("image_digest", ""))
    if not DIGEST_RE.fullmatch(digest):
        raise ValueError("image digest is malformed")
    if evidence.get("image_repository") != IMAGE_REPOSITORY:
        raise ValueError("image repository authority mismatch")
    if evidence.get("image_reference") != f"{IMAGE_REPOSITORY}@{digest}":
        raise ValueError("image reference is not bound to the exact digest")
    if evidence.get("platform") != "linux/amd64":
        raise ValueError("only the reviewed linux/amd64 image is admissible")
    image_grpc = str(evidence.get("image_dependency_version", ""))
    if version_tuple(image_grpc) < version_tuple(minimum):
        raise ValueError("image contains a vulnerable grpc-go version")
    if image_grpc != source_version:
        raise ValueError("image grpc-go version differs from protected source")

    sbom = require_artifact(evidence.get("sbom"), "SBOM")
    scan = require_artifact(evidence.get("vulnerability_scan"), "vulnerability scan")
    signature = require_artifact(evidence.get("signature"), "signature")
    provenance = require_artifact(evidence.get("provenance"), "provenance")
    if sbom.get("format") not in {"spdx-json", "cyclonedx-json"}:
        raise ValueError("unsupported SBOM format")
    if scan.get("cve_present") is not False:
        raise ValueError("CVE-2026-84304 remains present in the image scan")
    if scan.get("critical_count") != 0 or scan.get("high_count") != 0:
        raise ValueError("critical/high image vulnerabilities remain unresolved")
    if (
        signature.get("verified") is not True
        or signature.get("certificate_identity") != WORKFLOW_IDENTITY
    ):
        raise ValueError("image signature identity is unverified or unauthorized")
    if provenance.get("verified") is not True:
        raise ValueError("image provenance is not verified")
    if (
        provenance.get("subject_digest") != digest
        or provenance.get("source_sha") != source_sha
    ):
        raise ValueError("image provenance is not bound to source and digest")
    if provenance.get("builder_identity") != WORKFLOW_IDENTITY:
        raise ValueError("image provenance builder identity is unauthorized")

    workflow = evidence.get("workflow")
    if not isinstance(workflow, dict):
        raise ValueError("workflow evidence is missing")
    if workflow.get("repository") != "appolon1908-hue/Codestra-OpenBao":
        raise ValueError("workflow repository mismatch")
    if workflow.get("path") != WORKFLOW_PATH or workflow.get("ref") != WORKFLOW_REF:
        raise ValueError("image evidence must originate from the protected production workflow")
    if not isinstance(workflow.get("run_id"), int) or workflow["run_id"] <= 0:
        raise ValueError("workflow run ID is invalid")
    if not isinstance(workflow.get("run_attempt"), int) or workflow["run_attempt"] <= 0:
        raise ValueError("workflow run attempt is invalid")
    if evidence.get("runtime_authorized") is not False:
        raise ValueError("image evidence cannot self-authorize runtime deployment")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--expected-source-tree")
    parser.add_argument("--require-remediated-image", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        gate = load_json(GATE_PATH)
        minimum, source_version = validate_gate(gate)
        evidence_valid = False
        if args.evidence:
            evidence = load_json(args.evidence)
            validate_image_evidence(
                evidence,
                minimum,
                source_version,
                expected_source_sha=args.expected_source_sha,
                expected_source_tree=args.expected_source_tree,
            )
            evidence_valid = True
        if args.require_remediated_image and not evidence_valid:
            raise ValueError("a valid protected exact-image evidence document is required")
    except ValueError as exc:
        fail(str(exc))

    report = {
        "schema_version": 1,
        "cve": "CVE-2026-84304",
        "minimum_remediated_version": minimum,
        "source_dependency_version": source_version,
        "archive_module_version": ARCHIVE_VERSION,
        "runtime_target": "distroless",
        "source_dependency_remediated": True,
        "protected_exact_image_evidence_valid": evidence_valid,
        "repository_exact_image_gate": gate["exact_image_gate"],
        "runtime_activation_authorized": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(f"OPENBAO_GRPC_GO_SOURCE_VERSION={source_version}")
    print(f"OPENBAO_ARCHIVE_MODULE_VERSION={ARCHIVE_VERSION}")
    print("OPENBAO_RUNTIME_TARGET=DISTROLESS")
    print("OPENBAO_GRPC_GO_SOURCE_REMEDIATED=PASS")
    print(
        "OPENBAO_GRPC_GO_PROTECTED_IMAGE_EVIDENCE="
        f"{'PASS' if evidence_valid else 'BLOCKED'}"
    )
    print("OPENBAO_RUNTIME_ACTIVATION=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
