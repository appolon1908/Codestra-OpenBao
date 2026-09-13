#!/usr/bin/env python3
"""Build a secret-free immutable release manifest after runtime certification."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_ROOTS = (".github", "config", "deploy", "monitoring", "openbao", "plugins", "scripts")
CERTIFICATION_FILES = {
    "development": "development-certification.json",
    "test": "test-certification.json",
    "staging": "staging-certification.json",
    "restore": "restore-certification.json",
}


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def authority_files() -> list[Path]:
    paths = [ROOT / "CODESTRA_UPSTREAM.json"]
    for directory in AUTHORITY_ROOTS:
        paths.extend(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    return sorted(set(paths))


def authority_manifest() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): file_sha(path) for path in authority_files()}


def authority_checksum(manifest: dict[str, str]) -> str:
    value = "".join(f"{path}\0{digest}\n" for path, digest in sorted(manifest.items()))
    return hashlib.sha256(value.encode()).hexdigest()


def load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"not_an_object:{path.name}")
    return value


def require_certifications(evidence_dir: Path, checksum: str) -> dict[str, dict]:
    evidence = {
        name: load_object(evidence_dir / filename)
        for name, filename in CERTIFICATION_FILES.items()
    }
    for name, document in evidence.items():
        if document.get("schemaVersion") != 1:
            raise ValueError(f"invalid_certification_schema:{name}")
        if document.get("authorityChecksum") != checksum:
            raise ValueError(f"certification_authority_drift:{name}")
        if document.get("secretValuesIncluded") is not False:
            raise ValueError(f"certification_may_contain_secrets:{name}")

    development = evidence["development"]
    for gate in ("config", "auth", "policy", "rotation", "revocation", "backup", "restore"):
        if development.get(gate) != "PASS":
            raise ValueError(f"development_gate_not_pass:{gate}")
    test = evidence["test"]
    if test.get("certified") != "YES":
        raise ValueError("test_not_certified")
    staging = evidence["staging"]
    expected_staging = {
        "certified": "YES",
        "rotation": "PASS",
        "revocation": "PASS",
        "crossEnvironmentAccess": "DENIED",
        "soak": "PASS",
        "backup": "PASS",
        "restore": "PASS",
    }
    for gate, expected in expected_staging.items():
        if staging.get(gate) != expected:
            raise ValueError(f"staging_gate_not_pass:{gate}")
    restore = evidence["restore"]
    for gate in ("restore", "offHostBackup", "rpo", "rto"):
        if restore.get(gate) != "PASS":
            raise ValueError(f"recovery_gate_not_pass:{gate}")
    return evidence


def validate_runtime_authority() -> None:
    paths = (
        ROOT / "config/workload-secret-authority.v1.json",
        ROOT / "config/auth/keycloak-jwt.v1.json",
        ROOT / "openbao/auth/jwt-roles.v1.json",
        ROOT / "config/audit/audit.v1.json",
        ROOT / "config/secrets/engines.v1.json",
        ROOT / "config/recovery/backup.v1.json",
        ROOT / "config/environments/production/environment.json",
    )
    for path in paths:
        if load_object(path).get("runtimeApplyAuthorized") is not True:
            raise ValueError(f"runtime_authority_not_earned:{path.relative_to(ROOT)}")
    vex = load_object(ROOT / "artifacts/supply-chain/openbao-2.6.2-linux-amd64.vex.json")
    blockers = sorted(
        vulnerability
        for statement in vex.get("statements", [])
        if statement.get("condition") == "codestra_openbao_runtime_disabled"
        for vulnerability in statement.get("vulnerabilityIds", [])
    )
    if blockers:
        raise ValueError("runtime_blocked_by_vex:" + ",".join(blockers))
    auth = load_object(ROOT / "config/auth/keycloak-jwt.v1.json")
    roles = load_object(ROOT / "openbao/auth/jwt-roles.v1.json")
    if auth.get("jtiReplayCacheImplemented") is not True or roles.get("jtiReplayCacheImplemented") is not True:
        raise ValueError("jti_replay_protection_not_implemented")
    workload = load_object(ROOT / "config/workload-secret-authority.v1.json")
    for role in workload.get("roles", []):
        if role.get("environment") == "production" and role.get("runtimeBindingAuthorized") is not True:
            raise ValueError(f"production_workload_not_certified:{role.get('serviceIdentity')}")
        if role.get("providerBusinessEffectsEnabled") is not False:
            raise ValueError(f"provider_business_effect_enabled:{role.get('serviceIdentity')}")


def build(expected_source_sha: str, evidence_dir: Path) -> dict:
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if actual != expected_source_sha or len(actual) != 40:
        raise ValueError("release_source_sha_mismatch")
    validate_runtime_authority()
    files = authority_manifest()
    checksum = authority_checksum(files)
    evidence = require_certifications(evidence_dir, checksum)
    upstream = load_object(ROOT / "CODESTRA_UPSTREAM.json")
    plugin = load_object(ROOT / "plugins/codestra-jwt-replay/plugin.v1.json")
    supply = ROOT / "artifacts/supply-chain"
    return {
        "schemaVersion": 1,
        "sourceSha": actual,
        "authorityChecksum": checksum,
        "authorityFiles": files,
        "openbaoVersion": upstream["upstream_version"],
        "upstreamSha": upstream["upstream_ref"],
        "imageReference": upstream["image_reference"],
        "imageDigest": upstream["image_digest"],
        "imageArchitecture": upstream["image_architecture"],
        "authPlugin": {
            "name": plugin["name"],
            "version": plugin["version"],
            "sha256": plugin["binarySha256"],
            "upstreamSha": plugin["upstreamSha"],
            "goVersion": plugin["goVersion"],
        },
        "sbomSha256": file_sha(supply / "openbao-2.6.2-linux-amd64.cdx.json"),
        "vulnerabilityReportSha256": file_sha(supply / "openbao-2.6.2-linux-amd64.trivy.json"),
        "vexSha256": file_sha(supply / "openbao-2.6.2-linux-amd64.vex.json"),
        "authPluginSbomSha256": file_sha(
            supply / "codestra-jwt-replay-v1.1.0-linux-amd64.cdx.json"
        ),
        "authPluginVulnerabilityReportSha256": file_sha(
            supply / "codestra-jwt-replay-v1.1.0-linux-amd64.trivy.json"
        ),
        "certificationEvidenceSha256": {
            name: file_sha(evidence_dir / CERTIFICATION_FILES[name]) for name in evidence
        },
        "rollbackPackageIncluded": True,
        "runtimeApplyAuthorized": True,
        "providerBusinessEffectsEnabled": False,
        "secretValuesIncluded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--evidence-dir", type=Path, default=ROOT / "evidence/certification")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = build(args.expected_source_sha, args.evidence_dir)
        args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"OPENBAO_RELEASE=FAIL ERROR={exc}") from exc
    print("OPENBAO_RELEASE=PASS")
    print(f"RELEASE_SOURCE_SHA={manifest['sourceSha']}")
    print(f"RELEASE_AUTHORITY_CHECKSUM={manifest['authorityChecksum']}")


if __name__ == "__main__":
    main()
