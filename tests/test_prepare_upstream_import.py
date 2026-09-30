from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "prepare_upstream_import", ROOT / "scripts" / "prepare_upstream_import.py"
)
assert SPEC is not None and SPEC.loader is not None
IMPORTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMPORTER
SPEC.loader.exec_module(IMPORTER)

UPSTREAM_SHA = "a" * 40
UPSTREAM_URL = "https://github.com/openbao/openbao.git"


def git_blob_oid(path: Path, mode: str) -> str:
    if mode == "120000":
        data = os.fsencode(os.readlink(path))
    else:
        data = path.read_bytes()
    digest = hashlib.sha1()
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


class PrepareUpstreamImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / ".gitignore").write_text(
            "\n".join(
                [
                    ".env",
                    ".env.*",
                    "!.env.example",
                    "*.pem",
                    "*.key",
                    "*.p12",
                    "*.pfx",
                    "*.jks",
                    "*.keystore",
                    "*.unseal",
                    "*.token",
                    "*.secret",
                    "secrets/",
                    "credentials/",
                    "runtime-data/",
                    "bao-data/",
                    "raft-data/",
                    ".tmp/",
                    ".cache/",
                    ".DS_Store",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        self.root = self.repo / "upstream"
        self.root.mkdir()
        self.stage_index = self.repo / "reviewed-index.z"
        self.manifest = self.repo / "CODESTRA_UPSTREAM_SANITIZATION.json"
        self.lock = self.repo / "CODESTRA_UPSTREAM_LOCK.json"
        self.pathspec = self.repo / "pathspecs.z"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, data: bytes, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def write_stage_index(self, entries: list[tuple[str, str]]) -> None:
        payload = bytearray()
        for relative, mode in sorted(entries):
            path = self.root / relative
            oid = git_blob_oid(path, mode)
            payload.extend(f"{mode} {oid} 0\t{relative}".encode("utf-8"))
            payload.append(0)
        self.stage_index.write_bytes(bytes(payload))

    def prepare(self) -> dict[str, object]:
        return IMPORTER.prepare_import(
            repo_root=self.repo,
            root=self.root,
            stage_index_path=self.stage_index,
            upstream_url=UPSTREAM_URL,
            upstream_ref="main",
            upstream_sha=UPSTREAM_SHA,
            manifest_path=self.manifest,
            lock_path=self.lock,
            pathspec_output=self.pathspec,
        )

    def test_exact_normal_source_passes_and_emits_literal_paths(self) -> None:
        self.write("api/main.go", b"package api\n")
        self.write_stage_index([("api/main.go", "100644")])
        lock = self.prepare()
        self.assertEqual(lock["tracked_path_count"], 1)
        self.assertEqual(lock["ignored_path_count"], 0)
        self.assertEqual(self.pathspec.read_bytes(), b"upstream/api/main.go\0")

    def test_binary_secret_fixture_is_replaced_before_force_add(self) -> None:
        path = self.write("tests/fixtures/client.p12", b"\x00binary-private-material")
        self.write_stage_index([("tests/fixtures/client.p12", "100644")])
        lock = self.prepare()
        self.assertEqual(lock["ignored_path_count"], 1)
        self.assertIn(
            b"CODESTRA_REVIEWED_UPSTREAM_SECRET_FIXTURE_REMOVED", path.read_bytes()
        )
        self.assertNotIn(b"binary-private-material", path.read_bytes())

    def test_generic_file_under_secret_directory_is_replaced_wholesale(self) -> None:
        path = self.write(
            "tests/secrets/database.json",
            b'{"password":"arbitrary-value-not-covered-by-token-regexes"}\n',
        )
        self.write_stage_index([("tests/secrets/database.json", "100644")])
        lock = self.prepare()
        self.assertEqual(lock["ignored_path_count"], 1)
        self.assertIn(
            b"CODESTRA_REVIEWED_UPSTREAM_SECRET_FIXTURE_REMOVED", path.read_bytes()
        )
        self.assertNotIn(b"arbitrary-value-not-covered", path.read_bytes())

    def test_ignored_path_without_review_context_is_rejected(self) -> None:
        self.write("config/client.p12", b"\x00binary-private-material")
        self.write_stage_index([("config/client.p12", "100644")])
        with self.assertRaises(IMPORTER.ImportPolicyError):
            self.prepare()

    def test_runtime_state_directory_is_rejected_even_under_tests(self) -> None:
        self.write("tests/runtime-data/state.bin", b"state")
        self.write_stage_index([("tests/runtime-data/state.bin", "100644")])
        with self.assertRaises(IMPORTER.ImportPolicyError):
            self.prepare()

    def test_oversized_ignored_fixture_is_rejected_not_skipped(self) -> None:
        path = self.root / "tests" / "fixtures" / "large.key"
        path.parent.mkdir(parents=True)
        with path.open("wb") as handle:
            handle.truncate(IMPORTER.MAX_IGNORED_FILE_BYTES + 1)
        self.write_stage_index([("tests/fixtures/large.key", "100644")])
        with self.assertRaises(IMPORTER.ImportPolicyError):
            self.prepare()

    def test_untracked_file_is_rejected(self) -> None:
        self.write("api/main.go", b"package api\n")
        self.write("api/generated.tmp", b"not reviewed\n")
        self.write_stage_index([("api/main.go", "100644")])
        with self.assertRaises(IMPORTER.ImportPolicyError):
            self.prepare()

    def test_private_key_block_is_removed_from_reviewed_test_source(self) -> None:
        path = self.write(
            "builtin/backend_test.go",
            (
                b"package builtin\nconst fixture = `-----BEGIN "
                + b"PRIVATE KEY-----\nnot-a-real-key\n-----END "
                + b"PRIVATE KEY-----`\n"
            ),
        )
        self.write_stage_index([("builtin/backend_test.go", "100644")])
        self.prepare()
        private_key_marker = b"BEGIN " + b"PRIVATE KEY"
        self.assertNotIn(private_key_marker, path.read_bytes())
        self.assertIn(b"CODESTRA_PRIVATE_KEY_TEST_INVALID", path.read_bytes())

    def test_public_certificate_pem_is_admitted_only_as_reviewed_fixture(self) -> None:
        path = self.write(
            "api/test-fixtures/root.pem",
            b"-----BEGIN CERTIFICATE-----\npublic-fixture\n-----END CERTIFICATE-----\n",
        )
        self.write_stage_index([("api/test-fixtures/root.pem", "100644")])
        lock = self.prepare()
        self.assertEqual(lock["ignored_path_count"], 1)
        self.assertIn(b"BEGIN CERTIFICATE", path.read_bytes())

    def test_escaping_symlink_is_rejected(self) -> None:
        outside = self.repo / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "docs-link"
        link.symlink_to("../outside.txt")
        self.write_stage_index([("docs-link", "120000")])
        with self.assertRaises(IMPORTER.ImportPolicyError):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
