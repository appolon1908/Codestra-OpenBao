from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_rollback_preconditions.py"
SPEC = importlib.util.spec_from_file_location("verify_rollback_preconditions", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

NOW = dt.datetime(2026, 9, 26, 10, 30, tzinfo=dt.timezone.utc)
CURRENT = "1" * 40
ROLLBACK = "2" * 40
DIGEST = "sha256:" + "3" * 64
ARTIFACT_SHA = "4" * 64

BASE_ENV = {
    "GITHUB_REPOSITORY": "ingtrader21-spec/Codestra-OpenBao",
    "GITHUB_RUN_ID": "123456789",
    "GITHUB_WORKFLOW": "OpenBao protected runtime rollback",
    "CODESTRA_ENVIRONMENT": "staging",
    "OPENBAO_APPROVAL_ENVIRONMENT": "openbao-staging-runtime",
    "OPENBAO_REQUIRED_REVIEWER": "kazan555",
    "CODESTRA_SOURCE_SHA": CURRENT,
    "OPENBAO_ROLLBACK_SOURCE_SHA": ROLLBACK,
    "OPENBAO_ROLLBACK_IMAGE_DIGEST": DIGEST,
    "OPENBAO_ROLLBACK_CONTAINER": "codestra-openbao-rollback-20260926T100000Z",
    "OPENBAO_ROLLBACK_CONFIRMATION": f"ROLLBACK_OPENBAO_RUNTIME_TO_{ROLLBACK}",
}


def timestamp(minutes_ago: int = 1) -> str:
    return (NOW - dt.timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")


def backup(environment: str = "staging") -> dict:
    return {
        "schemaVersion": 1,
        "environment": environment,
        "artifact": f"openbao-{environment}-20260926T102900Z.raft.snap.age",
        "sha256": ARTIFACT_SHA,
        "sizeBytes": 4096,
        "completedAt": timestamp(),
        "backup": "PASS",
        "offHostBackup": "PASS",
        "checksumVerified": True,
        "immutabilityVerified": True,
        "secretValuesIncluded": False,
    }


def authorization(env: dict[str, str], backup_bytes: bytes) -> dict:
    return {
        "schemaVersion": 1,
        "repository": env["GITHUB_REPOSITORY"],
        "workflow": env["GITHUB_WORKFLOW"],
        "runId": env["GITHUB_RUN_ID"],
        "environment": env["CODESTRA_ENVIRONMENT"],
        "approvalEnvironment": env["OPENBAO_APPROVAL_ENVIRONMENT"],
        "approvedBy": env["OPENBAO_REQUIRED_REVIEWER"],
        "currentSourceSha": env["CODESTRA_SOURCE_SHA"],
        "rollbackSourceSha": env["OPENBAO_ROLLBACK_SOURCE_SHA"],
        "rollbackImageDigest": env["OPENBAO_ROLLBACK_IMAGE_DIGEST"],
        "rollbackContainer": env["OPENBAO_ROLLBACK_CONTAINER"],
        "confirmation": env["OPENBAO_ROLLBACK_CONFIRMATION"],
        "backupEvidenceSha256": hashlib.sha256(backup_bytes).hexdigest(),
        "backupArtifactSha256": ARTIFACT_SHA,
        "createdAt": timestamp(),
        "authorization": "PASS",
        "secretValuesIncluded": False,
    }


class RollbackPreconditionTests(unittest.TestCase):
    def run_validate(
        self,
        *,
        env: dict[str, str] | None = None,
        backup_value: dict | None = None,
        auth_edit=None,
        backup_edit=None,
    ):
        current_env = copy.deepcopy(BASE_ENV if env is None else env)
        current_backup = copy.deepcopy(backup_value or backup(current_env["CODESTRA_ENVIRONMENT"]))
        if backup_edit:
            backup_edit(current_backup)
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            backup_path = directory_path / "backup.json"
            backup_bytes = json.dumps(current_backup, sort_keys=True).encode()
            backup_path.write_bytes(backup_bytes)
            current_auth = authorization(current_env, backup_bytes)
            if auth_edit:
                auth_edit(current_auth)
            auth_path = directory_path / "authorization.json"
            auth_path.write_text(json.dumps(current_auth, sort_keys=True), encoding="utf-8")
            return MODULE.validate(auth_path, backup_path, env=current_env, now=NOW)

    def test_exact_fresh_binding_passes(self) -> None:
        authorization_value, backup_value = self.run_validate()
        self.assertEqual(authorization_value["rollbackSourceSha"], ROLLBACK)
        self.assertEqual(backup_value["sha256"], ARTIFACT_SHA)

    def test_target_or_approval_drift_fails_closed(self) -> None:
        cases = {
            "currentSourceSha": "9" * 40,
            "rollbackSourceSha": "8" * 40,
            "rollbackImageDigest": "sha256:" + "7" * 64,
            "rollbackContainer": "other-container",
            "approvedBy": "other-reviewer",
            "approvalEnvironment": "openbao-production-runtime",
            "runId": "999",
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, f"authorization_binding_mismatch:{key}"):
                    self.run_validate(auth_edit=lambda auth, key=key, value=value: auth.__setitem__(key, value))

    def test_authorization_and_backup_must_be_fresh(self) -> None:
        with self.assertRaisesRegex(ValueError, "authorization_created_at_stale"):
            self.run_validate(
                auth_edit=lambda auth: auth.__setitem__(
                    "createdAt", (NOW - dt.timedelta(minutes=16)).isoformat()
                )
            )
        with self.assertRaisesRegex(ValueError, "backup_completed_at_stale"):
            self.run_validate(
                backup_edit=lambda item: item.__setitem__(
                    "completedAt", (NOW - dt.timedelta(minutes=16)).isoformat()
                )
            )

    def test_backup_evidence_is_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            backup_path = directory_path / "backup.json"
            original = backup()
            original_bytes = json.dumps(original, sort_keys=True).encode()
            backup_path.write_bytes(original_bytes)
            auth = authorization(BASE_ENV, original_bytes)
            auth_path = directory_path / "authorization.json"
            auth_path.write_text(json.dumps(auth, sort_keys=True), encoding="utf-8")
            changed = copy.deepcopy(original)
            changed["sizeBytes"] += 1
            backup_path.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "backup_evidence_hash_mismatch"):
                MODULE.validate(auth_path, backup_path, env=BASE_ENV, now=NOW)

    def test_backup_must_be_immutable_off_host_and_secret_free(self) -> None:
        cases = {
            "backup": "FAIL",
            "offHostBackup": "FAIL",
            "checksumVerified": False,
            "immutabilityVerified": False,
            "secretValuesIncluded": True,
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, f"backup_binding_mismatch:{key}"):
                    self.run_validate(
                        backup_edit=lambda item, key=key, value=value: item.__setitem__(key, value)
                    )

    def test_production_binding_uses_production_runtime_environment(self) -> None:
        env = copy.deepcopy(BASE_ENV)
        env["CODESTRA_ENVIRONMENT"] = "production"
        env["OPENBAO_APPROVAL_ENVIRONMENT"] = "openbao-production-runtime"
        self.run_validate(env=env, backup_value=backup("production"))


class RollbackExecutionContractTests(unittest.TestCase):
    def test_mutation_waits_for_exact_authorization_and_backup_binding(self) -> None:
        rollback = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
        approval = rollback.index("scripts/verify_environment_approval.sh")
        preconditions = rollback.index("scripts/verify_rollback_preconditions.py")
        mutation = rollback.index('docker stop --time 90 "$current"')
        self.assertLess(approval, preconditions)
        self.assertLess(preconditions, mutation)
        self.assertIn("OPENBAO_ROLLBACK_AUTHORIZATION_EVIDENCE", rollback)
        self.assertIn("OPENBAO_PRECHANGE_BACKUP_EVIDENCE", rollback)

    def test_automatic_recovery_stays_armed_until_live_readback_passes(self) -> None:
        rollback = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
        trap_on = rollback.index("trap recover_current ERR")
        start = rollback.index('docker start "$current" >/dev/null', trap_on)
        status = rollback.index("bao status -format=json", start)
        leader = rollback.index("bao read -format=json sys/leader", status)
        peers = rollback.index("bao operator raft list-peers -format=json", leader)
        audit = rollback.index("bao audit list -format=json", peers)
        trap_off = rollback.index("trap - ERR", audit)
        self.assertLess(trap_on, start)
        self.assertLess(start, status)
        self.assertLess(status, leader)
        self.assertLess(leader, peers)
        self.assertLess(peers, audit)
        self.assertLess(audit, trap_off)
        self.assertIn("min_voters=3", rollback)
        self.assertIn(".sealed", rollback)
        self.assertIn("status_json", rollback)

    def test_sanitized_evidence_records_readback_without_secret_values(self) -> None:
        rollback = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
        for field in (
            "rollbackAuthorizationVerified:true",
            "prechangeBackupVerified:true",
            'runtimeReadback:"PASS"',
            "leaderReadback:true",
            "raftVoterCount:$raftVoterCount",
            "auditReadback:true",
            "secretValuesIncluded:false",
        ):
            self.assertIn(field, rollback)
        self.assertNotIn("BAO_TOKEN:$", rollback)

    def test_workflow_binds_backup_then_authorization_before_rollback(self) -> None:
        workflow = (ROOT / ".github/workflows/runtime-rollback.yml").read_text(encoding="utf-8")
        approval = workflow.index("scripts/verify_environment_approval.sh")
        backup_call = workflow.index("scripts/backup.sh", approval)
        evidence_hash = workflow.index('backup_evidence_sha="$(sha256sum', backup_call)
        authorization = workflow.index("rollback-authorization.json")
        verify = workflow.rindex("scripts/verify_rollback_preconditions.py")
        rollback = workflow.index("run: scripts/rollback.sh")
        self.assertLess(approval, backup_call)
        self.assertLess(backup_call, evidence_hash)
        self.assertLess(evidence_hash, verify)
        self.assertLess(verify, rollback)
        self.assertIn("backupEvidenceSha256", workflow)
        self.assertIn("backupArtifactSha256", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
