"""Works under built-in unittest and pytest; no optional runner required."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_environment_source_syntax import JSONC_FILES, parse_jsonc, validate_tree


class EnvironmentSourceSyntaxTests(unittest.TestCase):
    def test_exact_typescript_jsonc_allowlist(self):
        self.assertEqual(
            JSONC_FILES,
            {"upstream/ui/tsconfig.json", "upstream/website/tsconfig.json"},
        )
        for name in JSONC_FILES:
            parsed = parse_jsonc((Path(__file__).resolve().parents[1] / name).read_text())
            self.assertIsInstance(parsed, dict)
            self.assertIn("compilerOptions", parsed)

    def test_jsonc_string_literals_and_comments(self):
        example = '{"url":"https://source.invalid/x//y", // comment\n "a":[1,2,],}'
        self.assertEqual(
            parse_jsonc(example),
            {"url": "https://source.invalid/x//y", "a": [1, 2]},
        )

    def test_malformed_jsonc_is_rejected(self):
        for source in ("{ bad }", '{"a":true, "b":}', '{"a": 1 /* unterminated'):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    parse_jsonc(source)

    def test_other_json_files_must_remain_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            (root / "config" / "config.json").write_text('{"enabled":true // comment\n}')
            with self.assertRaises(json.JSONDecodeError):
                validate_tree(root)


if __name__ == "__main__":
    unittest.main()
