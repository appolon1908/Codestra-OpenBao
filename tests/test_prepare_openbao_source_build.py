#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import contextlib
import io
import json
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
            + "\n" + "\n".join(
                f"\t{module} {old_version}"
                for module, (old_version, _) in MODULE.SECURITY_GRAPH_UPGRADES.items()
            )
            + "\n)\n",
            encoding="utf-8",
        )
        source.joinpath("go.sum").write_text(
            "unrelated.example/module v1.0.0 h1:example=\n"
            + "\n".join((*MODULE.OLD_SUM_LINES, *MODULE.JOSE_OLD_SUM_LINES, *MODULE.CAP_OLD_SUM_LINES,
                         *(line for lines in MODULE.CEL_OTEL_OLD_SUM_LINES.values() for line in lines)))
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
            self.assertEqual(evidence["build_go_directive"], "1.26.0")
            go_mod = source.joinpath("go.mod").read_text(encoding="utf-8")
            go_sum = source.joinpath("go.sum").read_text(encoding="utf-8")
            self.assertIn("go 1.26.0\n", go_mod)
            self.assertNotIn("go 1.25.8\n", go_mod)
            for module, (old, new) in MODULE.SECURITY_GRAPH_UPGRADES.items():
                self.assertIn(f"\t{module} {new}\n", go_mod)
                self.assertNotIn(f"\t{module} {old}\n", go_mod)
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

    def test_unreviewed_security_graph_baseline_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            mod = source.joinpath("go.mod")
            mod.write_text(mod.read_text().replace("golang.org/x/net v0.58.0", "golang.org/x/net v0.59.0"))
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

go 1.26.0

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
        for lines in MODULE.REVIEWED_SECURITY_SUM_LINES.values():
            final_lines.extend(lines)
        final_sum = "\n".join(final_lines) + "\n"
        return original_mod, original_sum, final_mod, final_sum

    def test_tidy_cannot_reintroduce_retired_crypto_packages(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        for module in ("github.com/go-jose/go-jose/v3", "golang.org/x/crypto/openpgp"):
            with self.subTest(module=module), self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(original_mod, original_sum,
                    final_mod + "\t" + module + " v3.0.5\n", final_sum)
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(original_mod, original_sum, final_mod,
                final_sum + "github.com/go-jose/go-jose/v3 v3.0.5 h1:untrusted=\n")

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

    def test_retired_jose_diagnostic_distinguishes_requirement_from_checksum(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        checksum = MODULE.RETIRED_JOSE_MODULE + " v3.0.5/go.mod h1:public-checksum="
        for selected in (False, True):
            with self.subTest(selected=selected):
                mod = final_mod
                if selected:
                    mod += "\t" + MODULE.RETIRED_JOSE_MODULE + " v3.0.5 // indirect\n"
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
                    MODULE.validate_tidy_result(original_mod, original_sum, mod,
                                                final_sum + checksum + "\n")
                self.assertEqual(error.exception.code, 1)
                self.assertIn("details=", output.getvalue())
                diagnostic = json.loads(output.getvalue().split("details=", 1)[1])
                self.assertEqual(diagnostic, {
                    "selected_version": "v3.0.5" if selected else None,
                    "checksum_records": [checksum],
                })

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

    def test_unreviewed_tidy_diagnostics_preserve_denial_for_each_change_kind(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        module = "unreviewed.example/module"
        old_sum = module + " v1.0.0/go.mod h1:old-public-checksum="
        new_sum = module + " v2.0.0/go.mod h1:new-public-checksum="
        for before, after, old_records, new_records in (
            (None, "v2.0.0", [], [new_sum]),
            ("v1.0.0", None, [old_sum], []),
            ("v1.0.0", "v2.0.0", [old_sum], [new_sum]),
            ("v1.0.0", "v1.0.0", [old_sum, new_sum], [old_sum]),
        ):
            with self.subTest(before=before, after=after, checksums=new_records):
                before_mod = original_mod + (f"\t{module} {before}\n" if before else "")
                after_mod = final_mod + (f"\t{module} {after}\n" if after else "")
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as error:
                    MODULE.validate_tidy_result(
                        before_mod, original_sum + "\n".join(old_records) + "\n",
                        after_mod, final_sum + "\n".join(new_records) + "\n",
                    )
                self.assertEqual(error.exception.code, 1)
                self.assertIn("details=", output.getvalue())
                self.assertEqual(json.loads(output.getvalue().split("details=", 1)[1]), {
                    module: {
                        "version_before": before,
                        "version_after": after,
                        "checksums_removed": sorted(set(old_records) - set(new_records)),
                        "checksums_added": sorted(set(new_records) - set(old_records)),
                    },
                })

    def test_tidy_validation_rejects_go_directive_drift(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        final_mod = final_mod.replace("go 1.26.0", "go 1.26.1")
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(
                original_mod, original_sum, final_mod, final_sum
            )

    def okta_pruning_documents(self):
        before_mod, before_sum, after_mod, after_sum = self.reviewed_tidy_documents()
        backoff = "github.com/cenkalti/backoff/v4"
        cmp = "github.com/google/go-cmp"
        before_mod += f"{backoff} v4.3.0\n{cmp} v0.7.0\n{MODULE.OKTA_OLD_MODULE} v2.20.0\n"
        after_mod += f"{cmp} v0.7.0\n{MODULE.OKTA_MODULE} v6.1.7\n"
        records = [line for line in (ROOT / "upstream/go.sum").read_text().splitlines()
                   if line.startswith((backoff + " ", cmp + " "))]
        before_sum += "\n".join(records + list(MODULE.OKTA_OLD_SUM_LINES)) + "\n"
        after_sum += "\n".join(line for line in records
                              if not line.startswith((backoff + " ", cmp + " v0.5.9/"))) + "\n"
        after_sum += "\n".join(MODULE.REVIEWED_OPTIONAL_SUM_LINES[MODULE.OKTA_MODULE]) + "\n"
        return before_mod, before_sum, after_mod, after_sum

    def test_exact_hosted_okta_pruning_preserves_other_checksum_records(self) -> None:
        documents = self.okta_pruning_documents()
        changes = MODULE.validate_tidy_result(*documents)
        self.assertIn("github.com/cenkalti/backoff/v4", changes["go_mod_changed_modules"])
        self.assertNotIn("github.com/google/go-cmp", changes["go_mod_changed_modules"])
        self.assertIn("github.com/google/go-cmp", changes["go_sum_changed_modules"])

    def test_okta_pruning_rejects_other_versions_additions_removals_and_wrong_context(self) -> None:
        before_mod, before_sum, after_mod, after_sum = self.okta_pruning_documents()
        backoff = "github.com/cenkalti/backoff/v4"
        cmp = "github.com/google/go-cmp"
        kept_cmp = cmp + " v0.7.0/go.mod h1:pXiqmnSA92OHEEa9HXL2W4E7lf9JzCmGVUdgjX3N/iU=\n"
        backoff_record = backoff + " v4.3.0/go.mod h1:Y3VNntkOUPxTVeUxJ/G5vcM//AlwfmyYozVcomhLiZE=\n"
        cases = (
            (before_mod.replace(backoff + " v4.3.0", backoff + " v4.2.0"), before_sum, after_mod, after_sum),
            (before_mod, before_sum, after_mod + backoff + " v4.3.0\n", after_sum),
            (before_mod, before_sum, after_mod, after_sum + backoff_record),
            (before_mod, before_sum + backoff + " v4.2.0/go.mod h1:extra=\n", after_mod, after_sum),
            (before_mod, before_sum, after_mod.replace(cmp + " v0.7.0", cmp + " v0.8.0"), after_sum),
            (before_mod.replace(cmp + " v0.7.0", cmp + " v0.6.0"), before_sum, after_mod, after_sum),
            (before_mod, before_sum, after_mod, after_sum.replace(kept_cmp, "")),
            (before_mod, before_sum, after_mod, after_sum + cmp + " v0.8.0/go.mod h1:extra=\n"),
            (before_mod.replace(MODULE.OKTA_OLD_MODULE + " v2.20.0\n", ""), before_sum, after_mod, after_sum),
            (before_mod, before_sum, after_mod + "unreviewed.example/module v1.0.0\n", after_sum),
        )
        for index, documents in enumerate(cases):
            with self.subTest(index=index), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(*documents)

    def test_missing_reviewed_xnet_checksum_is_rejected(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        xnet_sum = MODULE.REVIEWED_SECURITY_SUM_LINES["golang.org/x/net"][0]
        self.assertIn(xnet_sum, final_sum)
        final_sum = final_sum.replace(xnet_sum + "\n", "")
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(original_mod, original_sum, final_mod, final_sum)

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


    def test_optional_telemetry_metadata_is_exact_and_selected_package_requires_zip_sum(self) -> None:
        original_mod, original_sum, final_mod, final_sum = self.reviewed_tidy_documents()
        module = "golang.org/x/telemetry"
        version = "v0.0.0-20260924152758-ed294f943157"
        zip_sum = module + " " + version + " h1:DftxASHKl6JolFPqoN+2WrFO53JvkHwRXvFqf8gsivA="
        mod_sum = module + " " + version + "/go.mod h1:i+ivNqjDnTF3WTElsdk5g9V5DTSBYgdNo7xTU9SDwYA="
        MODULE.validate_tidy_result(original_mod, original_sum, final_mod, final_sum + mod_sum + "\n")
        selected = final_mod.replace(")\n", "\t" + module + " " + version + " // indirect\n)\n")
        with self.assertRaises(SystemExit):
            MODULE.validate_tidy_result(original_mod, original_sum, selected, final_sum + mod_sum + "\n")
        MODULE.validate_tidy_result(original_mod, original_sum, selected, final_sum + zip_sum + "\n" + mod_sum + "\n")
        for bad in (mod_sum.replace("h1:i+", "h1:bad"), mod_sum.replace(version, "v0.0.0-20260101000000-aaaaaaaaaaaa")):
            with self.subTest(checksum=bad), self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(original_mod, original_sum, final_mod, final_sum + bad + "\n")


if __name__ == "__main__":
    unittest.main()
