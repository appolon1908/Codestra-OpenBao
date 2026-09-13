from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class InitializationGuardTests(unittest.TestCase):
    def test_only_guarded_initialization_call_exists(self) -> None:
        matches = []
        for path in ROOT.rglob("*"):
            if ".git" in path.parts or "tests" in path.parts or not path.is_file():
                continue
            if path.suffix not in {".sh", ".py", ".yml", ".yaml"}:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
            if "operator init" in source:
                matches.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(matches, ["scripts/initialize.sh"])

    def test_compose_never_initializes(self) -> None:
        source = (ROOT / "deploy/compose/compose.yaml").read_text(encoding="utf-8")
        self.assertNotIn("operator init", source)
        self.assertNotIn("-dev", source)

    def test_initialization_workflow_is_non_production_and_never_uploads_custody(self) -> None:
        workflow = (ROOT / ".github/workflows/initialize.yml").read_text(encoding="utf-8")
        self.assertIn("options: [development, test, staging]", workflow)
        self.assertNotIn("options: [development, test, staging, production]", workflow)
        self.assertIn("scripts/verify_environment_approval.sh", workflow)
        self.assertIn("scripts/initialize.sh", workflow)
        self.assertIn("custodyArtifactUploaded:false", workflow)
        self.assertNotIn("path: ${{ vars.OPENBAO_INIT_CUSTODY_FILE }}", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
