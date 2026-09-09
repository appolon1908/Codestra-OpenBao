import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RecoveryContractTests(unittest.TestCase):
    def test_backup_is_encrypted_verified_immutable_and_off_host(self) -> None:
        backup = (ROOT / "scripts/backup.sh").read_text()
        for control in (
            "bao operator raft snapshot save",
            "age --encrypt --recipients-file",
            "age --decrypt --identity",
            "bao operator raft snapshot inspect",
            "rclone copyto --immutable",
            "rclone cat",
            '"$remote_checksum" == "$(cat "$checksum")"',
        ):
            self.assertIn(control, backup)

        policy = json.loads((ROOT / "config/recovery/backup.v1.json").read_text())
        self.assertTrue(policy["localProtectedCopyRequired"])
        self.assertTrue(policy["offHostCopyRequired"])
        self.assertTrue(policy["offHostImmutabilityRequired"])
        self.assertTrue(policy["isolatedRestoreRequired"])

    def test_restore_is_isolated_and_never_targets_production(self) -> None:
        restore = (ROOT / "scripts/restore-test.sh").read_text()
        self.assertIn('[[ "$environment" != production ]]', restore)
        self.assertIn('"$target_cluster_id" != "$production_cluster_id"', restore)
        self.assertIn("OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED", restore)
        self.assertIn("bao operator raft snapshot restore -force", restore)
        self.assertIn("verify_secret_hash.py", restore)

        workflow = (ROOT / ".github/workflows/backup-restore-test.yml").read_text()
        self.assertIn("codestra-openbao-restore", workflow)
        self.assertNotIn("options: [development, test, staging, production]", workflow)
        self.assertIn("Upload only sanitized restore certification evidence", workflow)
        self.assertGreaterEqual(workflow.count("scripts/verify_environment_approval.sh"), 2)
        self.assertIn("OPENBAO_APPROVAL_ENVIRONMENT: openbao-${{ inputs.environment }}-backup", workflow)
        self.assertIn("OPENBAO_APPROVAL_ENVIRONMENT: openbao-${{ inputs.environment }}-restore", workflow)
        self.assertIn("git/ref/heads/${CODESTRA_ENVIRONMENT}", workflow)

    def test_post_restore_probe_uses_a_distinct_bounded_token(self) -> None:
        restore = (ROOT / "scripts/restore-test.sh").read_text()
        for control in (
            "OPENBAO_RESTORED_PROBE_TOKEN_FILE",
            "OPENBAO_RESTORED_PROBE_EXPECTED_POLICY",
            "pre_restore_token_sha",
            "restored_probe_token_sha",
            '[[ "$restored_probe_token_sha" != "$pre_restore_token_sha" ]]',
            "unset BAO_TOKEN",
            "bao token lookup -format=json",
            "verify_restored_probe_token.py",
            '--expected-policy "$restored_probe_policy"',
            "bao token revoke -self",
            "restoredProbeCredentialDistinct:true",
            "restoredProbeTokenRevoked:true",
        ):
            self.assertIn(control, restore)

        verifier = (ROOT / "scripts/verify_restored_probe_token.py").read_text()
        for control in (
            "token_policies",
            "identity_policies",
            "external_namespace_policies",
            "inherited identity policies are prohibited",
            "inherited external-namespace policies are prohibited",
            "probe token must be explicitly non-renewable",
            "probe token must have a positive integer TTL",
        ):
            self.assertIn(control, verifier)

        restore_position = restore.index("bao operator raft snapshot restore -force")
        discard_position = restore.index("unset BAO_TOKEN", restore_position)
        probe_read_position = restore.index("restored_probe_token=", discard_position)
        policy_position = restore.index("verify_restored_probe_token.py", probe_read_position)
        verify_position = restore.index("verify_secret_hash.py", policy_position)
        revoke_position = restore.index("bao token revoke -self", verify_position)
        self.assertLess(restore_position, discard_position)
        self.assertLess(discard_position, probe_read_position)
        self.assertLess(probe_read_position, policy_position)
        self.assertLess(policy_position, verify_position)
        self.assertLess(verify_position, revoke_position)

        workflow = (ROOT / ".github/workflows/backup-restore-test.yml").read_text()
        self.assertIn(
            "OPENBAO_RESTORED_PROBE_TOKEN_FILE: ${{ vars.OPENBAO_RESTORED_PROBE_TOKEN_FILE }}",
            workflow,
        )
        self.assertIn(
            "OPENBAO_RESTORED_PROBE_EXPECTED_POLICY: ${{ vars.OPENBAO_RESTORED_PROBE_EXPECTED_POLICY }}",
            workflow,
        )

    def test_environment_approval_parser_reads_the_response_array(self) -> None:
        approval = (ROOT / "scripts/verify_environment_approval.sh").read_text()
        self.assertIn('type == "array"', approval)
        self.assertIn("any(.[];", approval)
        self.assertNotIn("any(.;", approval)
        self.assertIn('(.user.login // .reviewer.login // "") == $reviewer', approval)

    def test_production_backup_is_scheduled_and_never_artifacts_snapshot_data(self) -> None:
        workflow = (ROOT / ".github/workflows/scheduled-backup.yml").read_text()
        self.assertIn("cron: '17 2 * * *'", workflow)
        self.assertIn("ref: production", workflow)
        self.assertIn("scripts/backup.sh", workflow)
        self.assertIn("Upload sanitized evidence but never snapshot data", workflow)
        self.assertNotIn("path: ${{ vars.OPENBAO_BACKUP_ROOT }}", workflow)

        policy = json.loads((ROOT / "config/recovery/backup.v1.json").read_text())
        self.assertEqual(policy["schedule"], "17 2 * * *")


if __name__ == "__main__":
    unittest.main()
