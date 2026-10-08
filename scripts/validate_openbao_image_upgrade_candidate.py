#!/usr/bin/env python3
"""Fail-closed, exact-digest assessment of a prospective OpenBao image.

This reviews immutable scan evidence; it never mutates image authority,
approves a vulnerability disposition, or enables a runtime.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = ROOT / "artifacts/security/openbao-image-upgrade-candidate-20261008.json"
GATED = {"HIGH", "CRITICAL", "UNKNOWN"}


class CandidateError(ValueError):
    pass


def validate(summary: dict, report: dict, raw_report: bytes, now: dt.datetime | None = None) -> dict:
    if summary.get("schema_version") != 1 or report.get("SchemaVersion") != 2:
        raise CandidateError("schema mismatch")
    reference = summary.get("image_reference", "")
    if not isinstance(reference, str) or not re.fullmatch(
        r"ghcr\.io/openbao/openbao@sha256:[0-9a-f]{64}", reference
    ):
        raise CandidateError("mutable, malformed, or unexpected image reference")
    if report.get("ArtifactName") != reference or report.get("ArtifactType") != "container_image":
        raise CandidateError("report does not match the immutable image")
    if summary.get("image_platform") != "linux/amd64":
        raise CandidateError("unreviewed image platform")
    manifest = summary.get("image_manifest_digest", "")
    index = summary.get("image_index_digest", "")
    if not isinstance(manifest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest):
        raise CandidateError("image manifest digest missing or malformed")
    if reference != "ghcr.io/openbao/openbao@" + manifest:
        raise CandidateError("scan reference is not bound to the image manifest digest")
    if not isinstance(index, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", index):
        raise CandidateError("OCI index digest missing or malformed")
    if index == manifest:
        raise CandidateError("image manifest and OCI index identities were conflated")
    if report.get("ArtifactID") != summary.get("image_config_digest"):
        raise CandidateError("image config digest mismatch")
    if hashlib.sha256(raw_report).hexdigest() != summary.get("report_sha256"):
        raise CandidateError("vulnerability report integrity mismatch")
    try:
        scan_at = dt.datetime.fromisoformat(report["CreatedAt"].replace("Z", "+00:00"))
        manifest_at = dt.datetime.fromisoformat(summary["scan_timestamp"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as e:
        raise CandidateError("scan timestamp invalid") from e
    if scan_at.tzinfo is None or manifest_at != scan_at:
        raise CandidateError("scan timestamp provenance mismatch")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise CandidateError("clock must carry a timezone")
    if scan_at > now + dt.timedelta(minutes=10) or now - scan_at > dt.timedelta(days=30):
        raise CandidateError("scan missing freshness or has future timestamp")
    results = report.get("Results")
    if not isinstance(results, list):
        raise CandidateError("vulnerability results missing")
    findings = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Vulnerabilities", []), (list, type(None))):
            raise CandidateError("malformed scan results")
        findings.extend(result.get("Vulnerabilities") or [])
    if any(not isinstance(f, dict) or f.get("Severity") not in {"LOW", "MEDIUM", *GATED}
           or not f.get("VulnerabilityID") or not f.get("PkgName") for f in findings):
        raise CandidateError("unknown vulnerability data or missing severity")
    counts = {
        "high_count": sum(f["Severity"] == "HIGH" for f in findings),
        "critical_count": sum(f["Severity"] == "CRITICAL" for f in findings),
        "unknown_count": sum(f["Severity"] == "UNKNOWN" for f in findings),
    }
    for key, observed in counts.items():
        if summary.get(key) != observed:
            raise CandidateError(f"{key} differs from scanned result")
    old_cve = any(f["VulnerabilityID"] == "CVE-2026-56851" for f in findings)
    if summary.get("cve_2026_56851_detected") is not old_cve:
        raise CandidateError("old-CVE observation drift")
    unknown = [
        {"vulnerability_id": f["VulnerabilityID"],
         "package_name": f["PkgName"],
         "installed_version": f.get("InstalledVersion")}
        for f in findings if f["Severity"] == "UNKNOWN"
    ]
    if summary.get("unknown_findings") != unknown:
        raise CandidateError("unscored findings changed")
    if summary.get("production_go") is not False or summary.get("promotion_authorized") is not False:
        raise CandidateError("candidate evidence cannot authorize production or promotion")
    blockers = [f"{f['VulnerabilityID']}:{f['PkgName']}:{f['Severity']}"
                for f in findings if f["Severity"] in GATED]
    if old_cve:
        blockers.append("CVE-2026-56851 remains in candidate")
    return {"status": "BLOCKED" if blockers else "SCANNED_CANDIDATE_ONLY",
            "blockers": sorted(set(blockers)), "image_reference": reference, **counts}


def load_report_path(summary: dict) -> Path:
    """Resolve only the reviewed immutable report, refusing symlink/path traversal."""
    if not isinstance(summary, dict):
        raise CandidateError("summary must be an object")
    report_name = summary.get("report_path")
    if report_name != "artifacts/security/openbao-v2.7.1-linux-amd64.trivy.json":
        raise CandidateError("report path outside reviewed security artifact")
    report_path = ROOT / report_name
    if report_path.is_symlink() or not report_path.resolve().is_relative_to(ROOT.resolve()):
        raise CandidateError("report symlink or path escaped repository")
    if not report_path.is_file() or report_path.stat().st_size > 10_000_000:
        raise CandidateError("report missing or oversized")
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    report_path = load_report_path(summary)
    raw = report_path.read_bytes()
    result = validate(summary, json.loads(raw), raw)
    print(json.dumps(result, sort_keys=True))
    # Exit successfully only for independent *integrity* assessment; a blocked
    # candidate is never an authorization signal to release orchestration.
    return 1 if result["status"] == "BLOCKED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
