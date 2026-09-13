from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/verify_sbom.py"
SPEC = importlib.util.spec_from_file_location("verify_sbom", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SbomContractTests(unittest.TestCase):
    def test_committed_sbom_has_exact_image_and_generator_identity(self) -> None:
        document = json.loads(MODULE.AUTHORITY.read_text(encoding="utf-8"))
        MODULE.validate(document)

    def test_inventory_ignores_nondeterministic_metadata_only(self) -> None:
        document = json.loads(MODULE.AUTHORITY.read_text(encoding="utf-8"))
        candidate = json.loads(json.dumps(document))
        candidate["serialNumber"] = "urn:uuid:00000000-0000-0000-0000-000000000000"
        candidate["metadata"]["timestamp"] = "2099-01-01T00:00:00Z"
        self.assertEqual(MODULE.inventory(candidate), MODULE.inventory(document))
        self.assertEqual(
            MODULE.dependency_inventory(candidate), MODULE.dependency_inventory(document)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
