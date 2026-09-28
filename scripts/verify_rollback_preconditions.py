#!/usr/bin/env python3
"""Validate that a runtime rollback is bound to one fresh protected approval and backup."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
MAX_AGE = dt.timedelta(minutes=15)
MAX_FUTURE_SKEW = dt.timedelta(minutes=2)


def fail(message: str) -> None:
    raise ValueError(message)


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"not_an_object:{path.name}")
    return value


def instant(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        fail(f"{label}_missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        fail(f"{label}_not_timezone_aware")
    return parsed.astimezone(dt.timezone.utc)


def fresh(value: object, label: str, now: dt.datetime) -> dt.datetime:
    parsed = instant(value, label)
    if parsed > now + MAX_FUTURE_SKEW:
        fail(f"{label}_in_future")
    if now - parsed > MAX_AGE:
        fail(f"{label}_stale")
    return parsed


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_env(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "")
    if not value:
        fail(f"environment_missing:{name}")
    return value


def validate(
    authorization_path: Path,
    backup_path: Path,
    *,
    env: dict[str, str] | None = None,
    now: dt.datetime | None = None,
) -> tuple[dict, dict]:
    env = dict(os.environ if env is None else env)
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)

    repository = required_env("GITHUB_REPOSITORY", env)
    run_id = required_env("GITHUB_RUN_ID", env)
    workflow = required_env("GITHUB_WORKFLOW", env)
    environment = required_env("CODESTRA_ENVIRONMENT", env)
    approval_environment = required_env("OPENBAO_APPROVAL_ENVIRONMENT", env)
    reviewer = env.get("OPENBAO_REQUIRED_REVIEWER", "kazan555")
    current_source = required_env("CODESTRA_SOURCE_SHA", env)
    rollback_source = required_env("OPENBAO_ROLLBACK_SOURCE_SHA", env)
    rollback_digest = required_env("OPENBAO_ROLLBACK_IMAGE_DIGEST", env)
    rollback_container = required_env("OPENBAO_ROLLBACK_CONTAINER", env)
    confirmation = required_env("OPENBAO_ROLLBACK_CONFIRMATION", env)

    if repository != "ingtrader21-spec/Codestra-OpenBao":
        fail("repository_mismatch")
    if environment not in {"development", "test", "staging", "production"}:
        fail("environment_invalid")
    if approval_environment != f"openbao-{environment}-runtime":
        fail("approval_environment_mismatch")
    if reviewer != "kazan555":
        fail("reviewer_mismatch")
    if not SHA.fullmatch(current_source):
        fail("current_source_invalid")
    if not SHA.fullmatch(rollback_source):
        fail("rollback_source_invalid")
    if not DIGEST.fullmatch(rollback_digest):
        fail("rollback_digest_invalid")
    if confirmation != f"ROLLBACK_OPENBAO_RUNTIME_TO_{rollback_source}":
        fail("confirmation_mismatch")

    authorization = load(authorization_path)
    expected = {
        "schemaVersion": 1,
        "repository": repository,
        "workflow": workflow,
        "runId": run_id,
        "environment": environment,
        "approvalEnvironment": approval_environment,
        "approvedBy": reviewer,
        "currentSourceSha": current_source,
        "rollbackSourceSha": rollback_source,
        "rollbackImageDigest": rollback_digest,
        "rollbackContainer": rollback_container,
        "confirmation": confirmation,
        "authorization": "PASS",
        "secretValuesIncluded": False,
    }
    for key, value in expected.items():
        if authorization.get(key) != value:
            fail(f"authorization_binding_mismatch:{key}")
    fresh(authorization.get("createdAt"), "authorization_created_at", now)

    backup = load(backup_path)
    backup_expected = {
        "schemaVersion": 1,
        "environment": environment,
        "backup": "PASS",
        "offHostBackup": "PASS",
        "checksumVerified": True,
        "immutabilityVerified": True,
        "secretValuesIncluded": False,
    }
    for key, value in backup_expected.items():
        if backup.get(key) != value:
            fail(f"backup_binding_mismatch:{key}")
    fresh(backup.get("completedAt"), "backup_completed_at", now)
    if not isinstance(backup.get("artifact"), str) or not backup["artifact"]:
        fail("backup_artifact_missing")
    if not isinstance(backup.get("sizeBytes"), int) or backup["sizeBytes"] <= 0:
        fail("backup_size_invalid")
    if not isinstance(backup.get("sha256"), str) or not HASH.fullmatch(backup["sha256"]):
        fail("backup_sha256_invalid")

    expected_evidence_hash = authorization.get("backupEvidenceSha256")
    if not isinstance(expected_evidence_hash, str) or not HASH.fullmatch(expected_evidence_hash):
        fail("backup_evidence_hash_invalid")
    if file_sha256(backup_path) != expected_evidence_hash:
        fail("backup_evidence_hash_mismatch")
    if authorization.get("backupArtifactSha256") != backup["sha256"]:
        fail("backup_artifact_hash_mismatch")

    return authorization, backup


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: verify_rollback_preconditions.py ROLLBACK_AUTHORIZATION.json PRECHANGE_BACKUP.json"
        )
    try:
        authorization, backup = validate(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"OPENBAO_ROLLBACK_PRECONDITIONS=FAIL ERROR={exc}") from exc
    print("OPENBAO_ROLLBACK_PRECONDITIONS=PASS")
    print(f"ROLLBACK_AUTHORIZATION_RUN_ID={authorization['runId']}")
    print(f"PRECHANGE_BACKUP_SHA256={backup['sha256']}")


if __name__ == "__main__":
    main()
