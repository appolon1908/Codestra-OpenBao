from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("initialization_preflight", ROOT / "scripts/initialization_preflight.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class InitializationFixture:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.parent = self.work / "custody"
        self.parent.mkdir(mode=0o700)
        self.keys = []
        for index in range(6):
            path = self.work / f"public-{index}.asc"
            path.write_text(str(index), encoding="utf-8")
            self.keys.append(path)
        self.env = {
            "OPENBAO_INIT_CUSTODY_DIR": str(self.parent / "ceremony"),
            "OPENBAO_UNSEAL_PGP_KEY_FILES": ":".join(map(str, self.keys[:5])),
            "OPENBAO_ROOT_TOKEN_PGP_KEY_FILE": str(self.keys[5]),
        }


class InitializationInputTests(InitializationFixture, unittest.TestCase):
    def test_valid_inputs_do_not_create_output(self) -> None:
        preflight.validate(self.env)
        self.assertFalse((self.parent / "ceremony").exists())
        self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o700)

    def test_invalid_destination_does_not_create_or_change_parent(self) -> None:
        self.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            preflight.validate(self.env)
        self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o755)
        self.assertFalse((self.parent / "ceremony").exists())

    def test_missing_parent_is_not_created(self) -> None:
        self.env["OPENBAO_INIT_CUSTODY_DIR"] = str(self.work / "absent" / "ceremony")
        with self.assertRaises(OSError):
            preflight.validate(self.env)
        self.assertFalse((self.work / "absent").exists())

    def test_repository_destination_is_rejected(self) -> None:
        self.env["OPENBAO_INIT_CUSTODY_DIR"] = str(ROOT / "ceremony")
        with self.assertRaises(ValueError):
            preflight.validate(self.env)

    def test_temporary_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as parent:
            self.env["OPENBAO_INIT_CUSTODY_DIR"] = parent + "/ceremony"
            with self.assertRaises(ValueError):
                preflight.validate(self.env)

    def test_existing_destination_is_preserved(self) -> None:
        destination = self.parent / "ceremony"
        destination.mkdir()
        evidence = destination / "existing"
        evidence.write_text("preserve", encoding="utf-8")
        with self.assertRaises(ValueError):
            preflight.validate(self.env)
        self.assertEqual(evidence.read_text(), "preserve")

    def test_symbolic_or_relative_destinations_are_rejected(self) -> None:
        link = self.work / "link"
        link.symlink_to(self.parent, target_is_directory=True)
        for value in ("relative/ceremony", str(link / "ceremony"), str(self.parent / ".." / "ceremony")):
            with self.subTest(value=value):
                self.env["OPENBAO_INIT_CUSTODY_DIR"] = value
                with self.assertRaises(ValueError):
                    preflight.validate(self.env)

    def test_dangling_destination_symlink_is_rejected(self) -> None:
        destination = self.parent / "ceremony"
        destination.symlink_to(self.work / "absent")
        with self.assertRaises(ValueError):
            preflight.validate(self.env)
        self.assertTrue(destination.is_symlink())

    def test_duplicate_keys_and_hardlinks_are_rejected(self) -> None:
        for duplicate in (self.keys[0], self.work / "hardlink"):
            if not duplicate.exists():
                os.link(self.keys[0], duplicate)
            self.env["OPENBAO_ROOT_TOKEN_PGP_KEY_FILE"] = str(duplicate)
            with self.assertRaises(ValueError):
                preflight.validate(self.env)

    def test_public_key_delimiters_and_empty_entries_are_rejected(self) -> None:
        original = self.env["OPENBAO_UNSEAL_PGP_KEY_FILES"]
        for value in (original + ":", original.replace(":", "::", 1), original.replace("public-0", "public,0")):
            self.env["OPENBAO_UNSEAL_PGP_KEY_FILES"] = value
            with self.assertRaises((ValueError, OSError)):
                preflight.validate(self.env)

    def test_symbolic_public_key_is_rejected(self) -> None:
        link = self.work / "public-link.asc"
        link.symlink_to(self.keys[5])
        self.env["OPENBAO_ROOT_TOKEN_PGP_KEY_FILE"] = str(link)
        with self.assertRaises(ValueError):
            preflight.validate(self.env)

    def test_cli_error_does_not_echo_input(self) -> None:
        self.env["OPENBAO_INIT_CUSTODY_DIR"] = "sensitive-canary-path"
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/initialization_preflight.py")],
            env={**os.environ, **self.env}, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("sensitive-canary-path", result.stdout + result.stderr)


class InitializerExecutionTests(InitializationFixture, unittest.TestCase):
    """Exercise the real shell entry point with local fake bao/gpg commands."""

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        commands = {
            "bao": """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$1" >> "$FAKE_BAO_CALLS"
if [[ "$1" == status ]]; then
  if [[ -n "${FAKE_BAO_STATUS:-}" ]]; then
    printf '%s\\n' "$FAKE_BAO_STATUS"
  else
    printf '{"initialized":false,"sealed":true}\\n'
  fi
  exit 2
fi
if [[ "$1" == operator && "${FAKE_BAO_INIT:-}" == fixture ]]; then
  printf '%s\\n' "$FAKE_BAO_RESPONSE"
  exit 0
fi
exit 99
""",
            "gpg": """#!/usr/bin/env bash
set -eu
read -r index < "${!#}" || true
if [[ "${FAKE_GPG_MODE:-public}" == private ]]; then
  printf 'sec::::::::::\\n'
else
  printf 'pub::::::::::\\n'
fi
if [[ "${FAKE_GPG_MODE:-public}" == multiple ]]; then
  printf 'pub::::::::::\\n'
fi
if [[ "${FAKE_GPG_MODE:-public}" == duplicate ]]; then index=0; fi
printf 'fpr:::::::::%040d:\\n' "$((index + 1))"
""",
            "stat": """#!/usr/bin/env bash
printf '%s\\n' "${FAKE_RAM_TYPE:-tmpfs}"
""",
        }
        for name, body in commands.items():
            path = self.bin / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o700)
        self.calls = self.work / "bao-calls"
        self.env.update({
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "FAKE_BAO_CALLS": str(self.calls),
            "CODESTRA_ENVIRONMENT": "test",
            "OPENBAO_INIT_CONFIRMATION": "INITIALIZE_NEW_TEST_CLUSTER",
            "OPENBAO_OFFLINE_CUSTODY_ACKNOWLEDGED": "true",
            "OPENBAO_INIT_RAM_ROOT": str(self.work),
        })
        self.hold_mutation_lease()

    def hold_mutation_lease(self) -> None:
        """Initialization is a mutation: the ceremony must hold the test cluster's lease."""
        sys.path.insert(0, str(ROOT))
        from codestra.change_kernel.authority import Authority
        from codestra.change_kernel.kernel import ChangeKernel
        from codestra.change_kernel.store import Store

        url = f"sqlite:///{(self.work / 'kernel.db').as_posix()}"
        store = Store(url)
        store.migrate()
        lease = ChangeKernel(store, Authority()).acquire_lock(
            "test", holder="initialization-test", purpose="initialize", run_ref="unit-test")
        store.close()
        self.lease_file = self.work / "lease.json"
        self.lease_file.write_text(json.dumps({
            "exclusionKey": lease.exclusion_key, "holder": lease.holder,
            "fenceToken": lease.fence_token, "expiresAt": lease.expires_at}), encoding="utf-8")
        self.env.update({"OPENBAO_CHANGE_KERNEL_DATABASE_URL": url,
                         "OPENBAO_CHANGE_KERNEL_LEASE_FILE": str(self.lease_file)})

    def run_initializer(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(ROOT / "scripts/initialize.sh")],
            env={**os.environ, **self.env}, capture_output=True, text=True, check=False, timeout=15,
        )

    def test_missing_or_released_lease_never_reaches_operator_init(self) -> None:
        self.enable_synthetic_init()
        self.lease_file.unlink()
        result = self.run_initializer()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("operator", self.calls.read_text() if self.calls.exists() else "")
        self.assertFalse((self.parent / "ceremony").exists())

    def test_bad_parent_fails_before_bao_and_preserves_mode(self) -> None:
        self.parent.chmod(0o755)
        result = self.run_initializer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(stat.S_IMODE(self.parent.stat().st_mode), 0o755)

    def test_non_ram_scratch_fails_before_bao(self) -> None:
        self.env["FAKE_RAM_TYPE"] = "ext4"
        result = self.run_initializer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.parent / "ceremony").exists())

    def test_private_multiple_or_duplicate_pgp_material_never_initializes(self) -> None:
        for mode in ("private", "multiple", "duplicate"):
            with self.subTest(mode=mode):
                self.env["FAKE_GPG_MODE"] = mode
                result = self.run_initializer()
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.calls.exists(), result.stderr)
                self.assertNotIn("operator", self.calls.read_text())
                self.assertFalse((self.parent / "ceremony").exists())

    def enable_synthetic_init(self) -> dict:
        # Fake command output only: these are deliberately not keys or tokens.
        response = {
            "unseal_keys_b64": [f"encrypted-fixture-{index}" for index in range(5)],
            "root_token": "encrypted-root-fixture",
        }
        self.env.update({"FAKE_BAO_INIT": "fixture", "FAKE_BAO_RESPONSE": json.dumps(response)})
        return response

    def test_success_exports_private_custody_then_removes_ram_buffer(self) -> None:
        response = self.enable_synthetic_init()
        result = self.run_initializer()
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = self.parent / "ceremony"
        files = list(destination.iterdir())
        self.assertEqual(len(files), 8)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in files))
        manifest = json.loads((destination / "MANIFEST.json").read_text())
        self.assertEqual((manifest["key_shares"], manifest["key_threshold"]), (5, 3))
        self.assertEqual(len(manifest["unseal_share_public_key_fingerprints"]), 5)
        self.assertEqual((destination / "initial-root-token.pgp.b64").read_text().strip(), response["root_token"])
        self.assertFalse(list(self.work.glob("openbao-init.*")))
        self.assertNotIn("encrypted-fixture", result.stdout + result.stderr)
        self.assertNotIn(response["root_token"], result.stdout + result.stderr)
        again = self.run_initializer()
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines().count("operator"), 1)

    def test_export_failure_preserves_private_ram_response_and_refuses_retry(self) -> None:
        response = self.enable_synthetic_init()
        failing_hash = self.bin / "sha256sum"
        failing_hash.write_text("#!/usr/bin/env bash\nexit 73\n", encoding="utf-8")
        failing_hash.chmod(0o700)
        result = self.run_initializer()
        self.assertEqual(result.returncode, 73)
        self.assertIn("RAM_BUFFER_RETAINED=YES DO_NOT_REINITIALIZE", result.stderr)
        buffers = list(self.work.glob("openbao-init.*/init.json"))
        self.assertEqual(len(buffers), 1)
        self.assertEqual(json.loads(buffers[0].read_text()), response)
        self.assertEqual(stat.S_IMODE(buffers[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(buffers[0].parent.stat().st_mode), 0o700)
        self.assertNotIn(response["root_token"], result.stdout + result.stderr)
        again = self.run_initializer()
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(self.calls.read_text().splitlines().count("operator"), 1)

    def test_malformed_init_result_preserved_for_operator_without_success(self) -> None:
        response = self.enable_synthetic_init()
        response["unseal_keys_b64"][4] = None
        self.env["FAKE_BAO_RESPONSE"] = json.dumps(response)
        result = self.run_initializer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RAM_BUFFER_RETAINED=YES", result.stderr)
        self.assertNotIn("OPENBAO_INITIALIZATION_PERFORMED=YES", result.stdout)
        self.assertFalse(list((self.parent / "ceremony").glob("*.pgp.b64")))

    def test_persistence_failure_keeps_encrypted_ram_copy(self) -> None:
        self.enable_synthetic_init()
        failing_sync = self.bin / "sync"
        failing_sync.write_text("#!/usr/bin/env bash\nexit 74\n", encoding="utf-8")
        failing_sync.chmod(0o700)
        result = self.run_initializer()
        self.assertEqual(result.returncode, 74)
        self.assertIn("RAM_BUFFER_RETAINED=YES", result.stderr)
        self.assertEqual(len(list(self.work.glob("openbao-init.*/init.json"))), 1)
        self.assertNotIn("OPENBAO_INITIALIZATION_PERFORMED=YES", result.stdout)

    def test_ambiguous_or_initialized_status_never_initializes(self) -> None:
        for status in ('{"initialized":"false","sealed":true}', '{"initialized":true}',
                       '{"initialized":false,"sealed":false}', '{}', 'invalid'):
            with self.subTest(status=status):
                self.env["FAKE_BAO_STATUS"] = status
                result = self.run_initializer()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("operator", self.calls.read_text())
                self.assertFalse((self.parent / "ceremony").exists())

    def test_missing_acknowledgement_or_wrong_confirmation_never_contacts_bao(self) -> None:
        for field in ("OPENBAO_OFFLINE_CUSTODY_ACKNOWLEDGED", "OPENBAO_INIT_CONFIRMATION"):
            original = self.env[field]
            self.env[field] = ""
            result = self.run_initializer()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.calls.exists())
            self.env[field] = original


if __name__ == "__main__":
    unittest.main()
