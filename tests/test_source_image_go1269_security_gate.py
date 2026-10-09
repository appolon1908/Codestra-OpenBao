#!/usr/bin/env python3
"""Build-only 2026-10 Go toolchain security pin; no imported-source edits."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/openbao-source-image-authority.yml"
UPSTREAM_TOOLCHAIN = ROOT / "upstream/.go-version"


class Go1269SourceImageGateTests(unittest.TestCase):
    def test_both_source_image_builds_pin_security_toolchain(self):
        source = WORKFLOW.read_text()
        self.assertEqual(source.count("go-version: '1.26.9'"), 2)
        self.assertNotIn("go-version-file: upstream/.go-version", source)
        self.assertEqual(source.count('test "$(go env GOVERSION)" = "go1.26.9"'), 2)
        self.assertEqual(source.count(r"go1\.26\.9[[:space:]]*$"), 2)
        self.assertEqual(source.count("python3 tests/test_source_image_go1269_security_gate.py"), 2)
        self.assertEqual(source.count("tests/test_source_image_go1269_security_gate.py"), 5)
        self.assertNotIn("go-version: '1.26.x'", source)
        self.assertNotIn("go-version: 'stable'", source)

    def test_provenance_and_fail_closed_scanning_remain(self):
        self.assertEqual(UPSTREAM_TOOLCHAIN.read_text().strip(), "1.26.6")
        source = WORKFLOW.read_text()
        self.assertIn("upstream/go.sum", source)
        self.assertEqual(source.count("go version -m bin/bao"), 2)
        self.assertIn("golang.org/x/text", source)
        self.assertIn("CVE-2026-56851", source)
        self.assertIn('{"HIGH", "CRITICAL", "UNKNOWN"}', source)

    def test_binary_go_version_match_is_strict(self):
        expression = r"^.+:\s+go1\.26\.9\s*$"
        self.assertIsNotNone(re.match(expression, "bin/bao: go1.26.9"))
        self.assertIsNone(re.match(expression, "bin/bao: go1.26.6"))
        self.assertIsNone(re.match(expression, "bin/bao: go1.27.2"))
        self.assertIsNone(re.match(expression, "bin/bao: go1.26.90"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
