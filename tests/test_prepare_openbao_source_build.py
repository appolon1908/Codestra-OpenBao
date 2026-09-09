#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "prepare_openbao_source_build.py"
SPEC = importlib.util.spec_from_file_location("source_build_patch", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceBuildPatchTests(unittest.TestCase):
    def create_source(self, directory: str) -> Path:
        source = Path(directory)
        source.joinpath("go.mod").write_text(
            "module example.test/openbao\n\ngo 1.25.8\n\nrequire (\n"
            + MODULE.OLD_MOD_LINE
            + "\n)\n",
            encoding="utf-8",
        )
        source.joinpath("go.sum").write_text(
            "unrelated.example/module v1.0.0 h1:example=\n"
            + "\n".join(MODULE.OLD_SUM_LINES)
            + "\n",
            encoding="utf-8",
        )
        return source

    def test_exact_transform_replaces_module_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            evidence = MODULE.apply(source)
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["new_version"], "0.3.2")
            self.assertFalse(evidence["go_mod_tidy_performed"])
            go_mod = source.joinpath("go.mod").read_text(encoding="utf-8")
            go_sum = source.joinpath("go.sum").read_text(encoding="utf-8")
            self.assertIn(MODULE.NEW_MOD_LINE, go_mod)
            self.assertNotIn(MODULE.OLD_MOD_LINE, go_mod)
            for line in MODULE.NEW_SUM_LINES:
                self.assertIn(line, go_sum)
            for line in MODULE.OLD_SUM_LINES:
                self.assertNotIn(line, go_sum)

    def test_transform_rejects_unexpected_upstream_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            source.joinpath("go.mod").write_text(
                source.joinpath("go.mod").read_text().replace("v0.2.0", "v0.2.1"),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.apply(source)

    def test_transform_cannot_run_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            MODULE.apply(source)
            with self.assertRaises(SystemExit):
                MODULE.apply(source)

    def test_missing_checksum_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            content = source.joinpath("go.sum").read_text(encoding="utf-8")
            source.joinpath("go.sum").write_text(
                content.replace(MODULE.OLD_SUM_LINES[0] + "\n", ""),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.apply(source)

    def reviewed_tidy_documents(self) -> tuple[str, str, str, str]:
        original_mod = """module example.test/openbao

go 1.25.8

require (
\tgithub.com/moby/go-archive v0.2.0 // indirect
\tgithub.com/moby/patternmatcher v0.6.0 // indirect
\tgithub.com/moby/sys/sequential v0.6.0 // indirect
\tgithub.com/moby/sys/user v0.4.0 // indirect
\tgoogle.golang.org/grpc v1.83.2
)
"""
        final_mod = """module example.test/openbao

go 1.25.8

require (
\tgithub.com/moby/go-archive v0.3.2 // indirect
\tgithub.com/moby/patternmatcher v0.6.1 // indirect
\tgithub.com/moby/sys/sequential v0.7.0 // indirect
\tgithub.com/moby/sys/user v0.4.1 // indirect
\tgoogle.golang.org/grpc v1.83.2
)
"""
        original_sum = "\n".join(MODULE.OLD_SUM_LINES) + "\n"
        final_lines = [*MODULE.NEW_SUM_LINES]
        for lines in MODULE.REVIEWED_TRANSITIVE_SUM_LINES.values():
            final_lines.extend(lines)
        final_sum = "\n".join(final_lines) + "\n"
        return original_mod, original_sum, final_mod, final_sum

    def test_tidy_validation_accepts_only_reviewed_transitive_updates(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        changes = MODULE.validate_tidy_result(
            original_mod, original_sum, final_mod, final_sum
        )
        self.assertEqual(
            changes["go_mod_changed_modules"],
            sorted(
                {
                    MODULE.MODULE,
                    "github.com/moby/patternmatcher",
                    "github.com/moby/sys/sequential",
                    "github.com/moby/sys/user",
                }
            ),
        )

    def test_tidy_validation_rejects_unreviewed_module_change(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        final_mod = final_mod.replace(
            ")\n",
            "\tunreviewed.example/module v9.9.9 // indirect\n)\n",
        )
        final_sum += "unreviewed.example/module v9.9.9 h1:example=\n"
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(
                original_mod, original_sum, final_mod, final_sum
            )

    def test_tidy_validation_rejects_go_directive_drift(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        final_mod = final_mod.replace("go 1.25.8", "go 1.26.0")
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(
                original_mod, original_sum, final_mod, final_sum
            )

    def test_tidy_validation_rejects_reviewed_graph_version_drift(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        final_mod = final_mod.replace(
            "google.golang.org/grpc v1.83.2",
            "google.golang.org/grpc v1.83.1",
        )
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(
                original_mod, original_sum, final_mod, final_sum
            )


if __name__ == "__main__":
    unittest.main()
