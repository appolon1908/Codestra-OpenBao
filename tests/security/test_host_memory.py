from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/validate_host_memory.py"
SPEC = importlib.util.spec_from_file_location("validate_host_memory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HostMemoryTests(unittest.TestCase):
    def swaps(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "swaps"
        path.write_text("Filename Type Size Used Priority\n" + body, encoding="utf-8")
        return path

    def test_disabled_swap_passes(self) -> None:
        self.assertEqual(MODULE.validate(self.swaps("")), ("disabled", 0))

    def test_encrypted_swap_passes(self) -> None:
        path = self.swaps("/dev/mapper/cryptswap partition 1024 0 -2\n")
        self.assertEqual(
            MODULE.validate(path, {"/dev/mapper/cryptswap": "crypt"}),
            ("encrypted", 1),
        )

    def test_unencrypted_swap_fails(self) -> None:
        path = self.swaps("/dev/md0 partition 1024 0 -2\n")
        with self.assertRaisesRegex(ValueError, "unencrypted_swap_active:/dev/md0"):
            MODULE.validate(path, {"/dev/md0": "raid1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
