#!/usr/bin/env python3
"""Fail-closed, build-only Go x/net v0.60.0 source-image review contract."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/openbao-source-image-authority.yml"
OVERLAY = ROOT / "scripts/prepare_openbao_source_build.py"
SOURCE = ROOT / "upstream/go.mod"
SPEC = importlib.util.spec_from_file_location("source_build_graph", OVERLAY)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Net060SourceImageGateTests(unittest.TestCase):
    def test_security_module_graph_is_complete_and_exact(self):
        graph = {
            "golang.org/x/crypto": ("v0.55.0", "v0.57.0"),
            "golang.org/x/mod": ("v0.38.0", "v0.41.0"),
            "golang.org/x/net": ("v0.58.0", "v0.60.0"),
            "golang.org/x/sync": ("v0.22.0", "v0.23.0"),
            "golang.org/x/sys": ("v0.47.0", "v0.48.0"),
            "golang.org/x/term": ("v0.45.0", "v0.46.0"),
            "golang.org/x/text": ("v0.41.0", "v0.42.0"),
            "golang.org/x/tools": ("v0.48.0", "v0.49.0"),
        }
        self.assertEqual(MODULE.SECURITY_GRAPH_UPGRADES, graph)
        self.assertEqual(MODULE.SOURCE_GO_DIRECTIVE, "1.25.8")
        self.assertEqual(MODULE.BUILD_GO_DIRECTIVE, "1.26.0")
        for module, (old, new) in graph.items():
            self.assertIn(f"\t{module} {old}", SOURCE.read_text())
            self.assertEqual(MODULE.REVIEWED_GRPC_GRAPH_VERSIONS[module], new)
            checksum, go_mod_checksum = MODULE.REVIEWED_SECURITY_SUM_LINES[module]
            self.assertTrue(checksum.startswith(f"{module} {new} h1:"))
            self.assertTrue(go_mod_checksum.startswith(f"{module} {new}/go.mod h1:"))

    def test_both_image_paths_check_net_and_text_from_binary(self):
        source = WORKFLOW.read_text()
        self.assertEqual(source.count(r"golang.org/x/net[[:space:]]+v0\\.60\\.0"), 2)
        self.assertEqual(source.count(r"golang.org/x/text[[:space:]]+v0\\.42\\.0"), 2)
        self.assertEqual(source.count("python3 tests/test_source_image_xnet060_gate.py"), 2)
        self.assertEqual(source.count("tests/test_source_image_xnet060_gate.py"), 5)
        self.assertEqual(source.count("go-version: '1.26.9'"), 2)
        self.assertIn("CVE-2026-56851", source)
        self.assertIn('{"HIGH", "CRITICAL", "UNKNOWN"}', source)

    def test_imported_source_is_never_rewritten(self):
        self.assertIn("go 1.25.8", SOURCE.read_text())
        self.assertIn("\tgolang.org/x/net v0.58.0", SOURCE.read_text())
        code = OVERLAY.read_text()
        self.assertIn("source_tree_modified_for_build_only", code)
        self.assertIn("repository_source_mutated", code)
        self.assertIn("GOTOOLCHAIN", code)
        self.assertIn("REVIEWED_SECURITY_SUM_LINES", code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
