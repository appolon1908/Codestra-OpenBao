from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
REPAIR_PATH = ROOT / "scripts" / "upstream_import_site" / "repair.py"
INSTALLER = ROOT / "scripts" / "install_ci_tools.sh"

spec = importlib.util.spec_from_file_location("openbao_snapshot_repair", REPAIR_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load snapshot repair module")
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


class SnapshotArchiveImportRepairTests(unittest.TestCase):
    def _archive_bytes(self, state: bytes, declared_digest: str) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, payload in (
                ("meta.json", b'{"fixture":true}\n'),
                ("state.bin", state),
                ("SHA256SUMS", f"{declared_digest}  state.bin\n".encode("ascii")),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                member.mode = 0o600
                member.uid = 1000
                member.gid = 1000
                member.mtime = 1_700_000_000
                member.uname = "openbao"
                member.gname = "openbao"
                archive.addfile(member, io.BytesIO(payload))
        return output.getvalue()

    def test_repair_is_fixed_width_metadata_preserving_and_idempotent(self) -> None:
        state = b"sanitized-state-without-private-key\n"
        stale = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            target = (
                Path(temporary)
                / "upstream"
                / "physical"
                / "raft"
                / "snapshot"
                / "testdata"
                / "spaces-meta.tar"
            )
            target.parent.mkdir(parents=True)
            target.write_bytes(self._archive_bytes(state, stale))
            before = target.read_bytes()

            self.assertTrue(repair.repair_known_archive(target))
            after = target.read_bytes()
            self.assertEqual(len(before), len(after))

            with tarfile.open(target, mode="r:") as archive:
                members = archive.getmembers()
                self.assertEqual(
                    [member.name for member in members],
                    ["meta.json", "state.bin", "SHA256SUMS"],
                )
                self.assertTrue(all(member.mode == 0o600 for member in members))
                self.assertTrue(all(member.uid == 1000 for member in members))
                self.assertTrue(all(member.gid == 1000 for member in members))
                state_bytes = archive.extractfile("state.bin").read()
                sums_bytes = archive.extractfile("SHA256SUMS").read()

            self.assertEqual(state_bytes, state)
            self.assertEqual(
                sums_bytes,
                f"{hashlib.sha256(state).hexdigest()}  state.bin\n".encode("ascii"),
            )
            self.assertFalse(repair.repair_known_archive(target))
            self.assertEqual(target.read_bytes(), after)

    def test_rejects_unapproved_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "unapproved.tar"
            target.write_bytes(self._archive_bytes(b"state", "b" * 64))
            with self.assertRaisesRegex(RuntimeError, "unsupported archive repair target"):
                repair.repair_known_archive(target)

    def test_installer_enables_hook_only_for_source_sync_workflow(self) -> None:
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('GITHUB_WORKFLOW:-}" == "Codestra Upstream Source Sync"', text)
        self.assertIn("scripts/upstream_import_site", text)
        self.assertIn("PYTHONPATH=", text)
        self.assertIn("PYTHONNOUSERSITE=1", text)
        self.assertNotIn("git add -f -A upstream", text)


if __name__ == "__main__":
    unittest.main()
