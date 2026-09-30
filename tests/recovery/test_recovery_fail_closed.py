"""Behavioural fail-closed tests for checksum binding, backup, restore, unseal and apply guards.

Every external command that could touch a real OpenBao, age identity or remote is
replaced by a stub that only records that it was reached.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/verify_artifact_checksum.sh"
SPEC = importlib.util.spec_from_file_location("unseal_from_files", ROOT / "scripts/unseal_from_files.py")
assert SPEC and SPEC.loader
UNSEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UNSEAL)


def write_stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.marks = self.tmp / "marks"
        self.marks.mkdir()

    def stub(self, name: str, body: str = "") -> None:
        write_stub(self.bin, name, f'touch "{self.marks}/{name}"\n{body}')

    def env(self, **values: str) -> dict[str, str]:
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.tmp)}
        env.update(values)
        return env

    def reached(self, name: str) -> bool:
        return (self.marks / name).exists()


class ArtifactChecksumTests(Workspace):
    def setUp(self) -> None:
        super().setUp()
        self.artifact = self.tmp / "plan.json"
        self.artifact.write_text('{"plan": 1}\n', encoding="utf-8")
        self.decoy = self.tmp / "good.json"
        self.decoy.write_text('{"plan": 0}\n', encoding="utf-8")
        self.checksum = self.tmp / "plan.json.sha256"

    def run_helper(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(HELPER), str(self.artifact), str(self.checksum), *extra],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_exact_artifact_passes_and_prints_digest(self) -> None:
        self.checksum.write_text(f"{sha(self.artifact)}  plan.json\n", encoding="utf-8")
        result = self.run_helper(sha(self.artifact))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), sha(self.artifact))

    def test_checksum_naming_a_decoy_file_fails(self) -> None:
        # `sha256sum -c` alone would pass here while plan.json is the file used.
        self.checksum.write_text(f"{sha(self.decoy)}  good.json\n", encoding="utf-8")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum_names_other_file", result.stderr)

    def test_digest_mismatch_extra_lines_and_reviewed_mismatch_fail(self) -> None:
        cases = {
            "artifact_digest_mismatch": (f"{sha(self.decoy)}  plan.json\n", ()),
            "checksum_line_count:2": (
                f"{sha(self.artifact)}  plan.json\n{sha(self.decoy)}  good.json\n",
                (),
            ),
            "checksum_format": ("not-a-digest  plan.json\n", ()),
            "reviewed_digest_mismatch": (f"{sha(self.artifact)}  plan.json\n", ("0" * 64,)),
        }
        for error, (content, extra) in cases.items():
            self.checksum.write_text(content, encoding="utf-8")
            with self.subTest(error=error):
                result = self.run_helper(*extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)

    def test_callers_use_the_binding_helper(self) -> None:
        for script in ("restore-test.sh", "apply.sh", "apply_saved_plan.sh"):
            source = (ROOT / "scripts" / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIn("verify_artifact_checksum.sh", source)
                self.assertNotIn("sha256sum -c", source)


class BackupAttestationTests(Workspace):
    def run_backup(self, attestation: dict) -> subprocess.CompletedProcess[str]:
        for name in ("age", "rclone"):
            self.stub(name, "exit 1")
        self.stub("bao", "exit 1")
        files = {}
        for name in ("recipient", "identity"):
            files[name] = self.tmp / name
            files[name].write_text("placeholder\n", encoding="utf-8")
        attestation_path = self.tmp / "attestation.json"
        attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
        return subprocess.run(
            [str(ROOT / "scripts/backup.sh")],
            env=self.env(
                CODESTRA_ENVIRONMENT="staging",
                OPENBAO_BACKUP_ROOT=str(self.tmp / "backups"),
                OPENBAO_AGE_RECIPIENT_FILE=str(files["recipient"]),
                OPENBAO_AGE_IDENTITY_FILE=str(files["identity"]),
                OPENBAO_OFFHOST_REMOTE="remote:bucket",
                OPENBAO_OFFHOST_IMMUTABILITY_ATTESTATION=str(attestation_path),
            ),
            capture_output=True,
            text=True,
            check=False,
        )

    @staticmethod
    def attestation(**overrides: object) -> dict:
        value = {
            "schemaVersion": 1,
            "remote": "remote:bucket",
            "objectLockEnabled": True,
            "retentionDays": 30,
            "owner": "security",
            "verifiedAt": "2026-09-25T00:00:00Z",
        }
        value.update(overrides)
        return value

    def test_valid_attestation_reaches_the_status_probe(self) -> None:
        self.run_backup(self.attestation())
        self.assertTrue(self.reached("bao"))

    def test_non_numeric_retention_or_schema_fails_before_bao(self) -> None:
        for field, value in (
            ("retentionDays", "1"),
            ("retentionDays", {}),
            ("retentionDays", 7),
            ("schemaVersion", "1"),
        ):
            with self.subTest(field=field, value=value):
                (self.marks / "bao").unlink(missing_ok=True)
                result = self.run_backup(self.attestation(**{field: value}))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.reached("bao"))


class RestoreTargetTests(Workspace):
    def run_restore(self, address: str, started: str | None = None) -> subprocess.CompletedProcess[str]:
        self.stub("bao", """if [[ "$1" == status ]]; then echo '{"cluster_id":"isolated"}'; exit 2; fi; exit 1""")
        self.stub("age", "exit 1")
        artifact = self.tmp / "snapshot.age"
        artifact.write_bytes(b"ciphertext")
        checksum = self.tmp / "snapshot.age.sha256"
        checksum.write_text(f"{sha(artifact)}  snapshot.age\n", encoding="utf-8")
        tokens = {}
        for name in ("identity", "operator", "probe"):
            tokens[name] = self.tmp / name
            tokens[name].write_text(f"{name}-value\n", encoding="utf-8")
            tokens[name].chmod(0o600)
        return subprocess.run(
            [str(ROOT / "scripts/restore-test.sh")],
            env=self.env(
                CODESTRA_ENVIRONMENT="staging",
                OPENBAO_RESTORE_ARTIFACT=str(artifact),
                OPENBAO_RESTORE_CHECKSUM=str(checksum),
                OPENBAO_AGE_IDENTITY_FILE=str(tokens["identity"]),
                OPENBAO_PRODUCTION_CLUSTER_ID="production",
                OPENBAO_RESTORE_EVIDENCE=str(self.tmp / "evidence.json"),
                OPENBAO_OPERATOR_TOKEN_FILE=str(tokens["operator"]),
                OPENBAO_RESTORED_PROBE_TOKEN_FILE=str(tokens["probe"]),
                OPENBAO_RESTORED_PROBE_EXPECTED_POLICY="restore-probe",
                OPENBAO_RESTORE_STARTED_EPOCH=started if started is not None else str(int(time.time())),
                OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED="true",
                BAO_TOKEN="operator-value",
                BAO_ADDR=address,
            ),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_restore_host_is_parsed_not_substring_matched(self) -> None:
        for address in (
            "https://vault.prod.example/restore",
            "https://vault.prod.example/?localhost",
            "https://127.0.0.1.prod.example:8200",
        ):
            with self.subTest(address=address):
                (self.marks / "age").unlink(missing_ok=True)
                self.run_restore(address)
                self.assertFalse(self.reached("age"))
        for address in ("https://openbao-restore.internal:8200", "http://127.0.0.1:8200"):
            with self.subTest(address=address):
                (self.marks / "age").unlink(missing_ok=True)
                self.run_restore(address)
                self.assertTrue(self.reached("age"))

    def test_start_epoch_is_validated_before_any_restore_step(self) -> None:
        future = str(int(time.time()) + 86400)
        for started in ("", "yesterday", "1e9", future):
            with self.subTest(started=started):
                (self.marks / "bao").unlink(missing_ok=True)
                result = self.run_restore("https://openbao-restore.internal", started)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.reached("bao"))

    def test_rto_is_enforced_and_recorded(self) -> None:
        source = (ROOT / "scripts/restore-test.sh").read_text(encoding="utf-8")
        self.assertIn(".rtoTargetHours", source)
        self.assertIn("(( duration > rto_seconds ))", source)
        self.assertIn("rtoMet:true", source)
        self.assertLess(source.index("(( duration > rto_seconds ))"), source.index('> "$evidence"'))


class UnsealTransportTests(unittest.TestCase):
    def context(self, address: str, environment: str = "staging"):
        with mock.patch.dict(
            os.environ, {"BAO_ADDR": address, "CODESTRA_ENVIRONMENT": environment}, clear=True
        ):
            return UNSEAL.context()

    def test_cleartext_only_to_development_or_test_loopback(self) -> None:
        for environment in ("development", "test"):
            for address in ("http://127.0.0.1:8200", "http://localhost:8200", "http://[::1]:8200"):
                self.assertIsNone(self.context(address, environment))
        for address, environment, error in (
            ("http://10.0.0.5:8200", "test", "loopback"),
            ("http://127.0.0.1.evil.example:8200", "test", "loopback"),
            ("http://127.0.0.1:8200", "staging", "loopback"),
            ("http://127.0.0.1:8200", "production", "loopback"),
            ("ftp://127.0.0.1", "test", "plain HTTP\\(S\\) origin"),
            ("127.0.0.1:8200", "test", "plain HTTP\\(S\\) origin"),
        ):
            with self.subTest(address=address, environment=environment):
                with self.assertRaisesRegex(ValueError, error):
                    self.context(address, environment)

    def test_https_still_requires_a_ca(self) -> None:
        with self.assertRaisesRegex(ValueError, "BAO_CACERT is required"):
            self.context("https://openbao-restore.internal:8200")


class SavedPlanTokenTests(Workspace):
    def test_empty_operator_token_fails_before_preflight(self) -> None:
        scripts = self.tmp / "repo/scripts"
        scripts.mkdir(parents=True)
        for name in ("apply_saved_plan.sh", "verify_artifact_checksum.sh"):
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        write_stub(scripts, "preflight.sh", f'touch "{self.marks}/preflight"; exit 1')
        plan = self.tmp / "plan.json"
        source_sha = "a" * 40
        plan.write_text(
            json.dumps({"planSourceSha": source_sha, "environment": "staging", "counts": {"destroy": 0}}),
            encoding="utf-8",
        )
        checksum = self.tmp / "plan.json.sha256"
        checksum.write_text(f"{sha(plan)}  plan.json\n", encoding="utf-8")
        token = self.tmp / "token"
        for content, expect_preflight in (("", False), ("operator-value\n", True)):
            token.write_text(content, encoding="utf-8")
            (self.marks / "preflight").unlink(missing_ok=True)
            evidence = self.tmp / f"evidence-{expect_preflight}"
            with self.subTest(empty=not content):
                subprocess.run(
                    ["bash", "scripts/apply_saved_plan.sh"],
                    cwd=self.tmp / "repo",
                    env=self.env(
                        CODESTRA_ENVIRONMENT="staging",
                        CODESTRA_SOURCE_SHA=source_sha,
                        OPENBAO_SAVED_PLAN=str(plan),
                        OPENBAO_SAVED_PLAN_CHECKSUM=str(checksum),
                        OPENBAO_EXPECTED_PLAN_SHA256=sha(plan),
                        OPENBAO_DEPLOYMENT_EVIDENCE_DIR=str(evidence),
                        OPENBAO_OPERATOR_TOKEN_FILE=str(token),
                    ),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(self.reached("preflight"), expect_preflight)


class PreflightPublishedPortTests(unittest.TestCase):
    def test_preflight_rejects_publish_all_and_runtime_port_bindings(self) -> None:
        source = (ROOT / "scripts/preflight.sh").read_text(encoding="utf-8")
        self.assertIn(".HostConfig.PublishAllPorts // false", source)
        self.assertIn(".NetworkSettings.Ports", source)
        publish_all = {"HostConfig": {"PublishAllPorts": True, "PortBindings": {}}}
        bound = {"NetworkSettings": {"Ports": {"8200/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32768"}]}}}
        private = {"HostConfig": {"PortBindings": {}}, "NetworkSettings": {"Ports": {"8200/tcp": None}}}
        filters = (
            "jq -r '.[0].HostConfig.PublishAllPorts // false'",
            "jq '[.[0].NetworkSettings.Ports // {} | .[] | select(. != null and . != [])] | length'",
        )
        if shutil.which("jq") is None:
            self.skipTest("jq unavailable")
        for container, expected in ((publish_all, ("true", "0")), (bound, ("false", "1")), (private, ("false", "0"))):
            outputs = tuple(
                subprocess.run(
                    ["bash", "-c", command], input=json.dumps([container]), capture_output=True,
                    text=True, check=True,
                ).stdout.strip()
                for command in filters
            )
            self.assertEqual(outputs, expected)
        # The exercised jq programs are the ones preflight.sh runs.
        for command in filters:
            self.assertIn(command.split("'")[1], source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
