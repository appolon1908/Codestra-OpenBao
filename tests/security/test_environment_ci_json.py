"""Execute the workflow entrypoint; JSONC is restricted to two upstream files."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class EnvironmentJsonCiTests(unittest.TestCase):
    def test_exact_jsonc_exceptions_with_all_other_json_strict(self) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/codestra-environment-cicd.yml").read_text()
        )
        steps = workflow["jobs"]["ci"]["steps"]
        script = next(
            step["run"]
            for step in steps
            if step.get("name") == "Validate JSON and Python syntax"
        )
        self.assertIn("python3 scripts/validate_environment_source_syntax.py", script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            shutil.copyfile(
                ROOT / "scripts/validate_environment_source_syntax.py",
                root / "scripts/validate_environment_source_syntax.py",
            )
            paths = (
                root / "upstream/ui/tsconfig.json",
                root / "upstream/website/tsconfig.json",
            )
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"comment": true,}\n')
            (root / "valid.json").write_text('{"ok": true}\n')

            def run():
                return subprocess.run(
                    ["bash", "-c", script], cwd=root, capture_output=True, text=True,
                    timeout=30,
                )

            clean = run()
            self.assertEqual(clean.returncode, 0, clean.stderr)
            broken_path = root / "upstream/other.json"
            broken_path.write_text('{"invalid": }\n')
            broken = run()
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn("JSON_VALIDATION_FAIL=upstream/other.json", broken.stderr)
            broken_path.unlink()
            paths[0].write_text('{"invalid": }\n')
            malformed_jsonc = run()
            self.assertNotEqual(malformed_jsonc.returncode, 0)
            self.assertIn("JSON_VALIDATION_FAIL=upstream/ui/tsconfig.json", malformed_jsonc.stderr)
            paths[0].unlink()
            missing = run()
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("reviewed upstream JSONC paths missing", missing.stderr)


if __name__ == "__main__":
    unittest.main()
