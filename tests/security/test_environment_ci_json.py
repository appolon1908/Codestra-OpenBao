"""JSONC exceptions must stay restricted to exact upstream TypeScript configs."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class EnvironmentJsonCiTests(unittest.TestCase):
    def test_exact_jsonc_exceptions_with_all_other_json_strict(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/codestra-environment-cicd.yml").read_text())
        steps = workflow["jobs"]["ci"]["steps"]
        script = next(step["run"] for step in steps if step.get("name") == "Validate JSON and Python syntax")
        code = script.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        self.assertIn("json.JSONDecodeError", code)
        self.assertNotIn('part == "upstream"', code)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "upstream/ui").mkdir(parents=True)
            (root / "upstream/website").mkdir(parents=True)
            (root / "upstream/ui/tsconfig.json").write_text('{"comment": true,}\n')
            (root / "upstream/website/tsconfig.json").write_text('{"comment": true,}\n')
            (root / "valid.json").write_text('{"ok": true}\n')
            clean = subprocess.run(["python3", "-c", code], cwd=root, capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            (root / "broken.json").write_text('{"invalid": }\n')
            broken = subprocess.run(["python3", "-c", code], cwd=root, capture_output=True, text=True)
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("JSON_VALIDATION_FAIL=broken.json", broken.stderr)
