from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jose_overlay", ROOT / "scripts/prepare_openbao_source_build.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
JOSE = "github.com/go-jose/go-jose/v4"
OLD_SUMS = (
    JOSE + " v4.1.4 h1:moDMcTHmvE6Groj34emNPLs/qtYXRVcd6S7NHbHz3kA=",
    JOSE + " v4.1.4/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=",
)
NEW_SUMS = (
    JOSE + " v4.1.6 h1:sNRkftxFJxwsILiQukqp5z83QBSmntVwmgRY7AqBDO4=",
    JOSE + " v4.1.6/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=",
)


class JoseSourceImageSecurityTests(unittest.TestCase):
    def source_copy(self, directory):
        source = Path(directory)
        for name in ("go.mod", "go.sum"):
            (source / name).write_bytes((ROOT / "upstream" / name).read_bytes())
        return source

    def test_real_pinned_source_gets_fixed_jose_without_mutating_import(self):
        before = {name: hashlib.sha256((ROOT / "upstream" / name).read_bytes()).hexdigest()
                  for name in ("go.mod", "go.sum")}
        with tempfile.TemporaryDirectory() as directory:
            source = self.source_copy(directory)
            evidence = MODULE.apply(source)
            self.assertEqual(MODULE.module_versions((source / "go.mod").read_text()).get(JOSE), "v4.1.6")
            self.assertEqual(evidence["reviewed_security_module_versions"][JOSE], "v4.1.6")
            sums = (source / "go.sum").read_text().splitlines()
            for old, new in zip(OLD_SUMS, NEW_SUMS):
                self.assertNotIn(old, sums)
                self.assertEqual(sums.count(new), 1)
            # v3 remains an actual, separately unresolved dependency.
            self.assertIn("github.com/go-jose/go-jose/v3 v3.0.5", (source / "go.mod").read_text())
        for name, digest in before.items():
            self.assertEqual(hashlib.sha256((ROOT / "upstream" / name).read_bytes()).hexdigest(), digest)

    def test_tampered_jose_baseline_version_or_checksums_are_refused(self):
        for name, old, new in (("go.mod", JOSE + " v4.1.4", JOSE + " v4.1.3"),
                               ("go.sum", OLD_SUMS[0], ""),
                               ("go.sum", OLD_SUMS[1], "")):
            with self.subTest(name=name, old=old), tempfile.TemporaryDirectory() as directory:
                source = self.source_copy(directory)
                path = source / name
                path.write_text(path.read_text().replace(old, new))
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    MODULE.apply(source)

    def tidy_fixture(self):
        original_mod = ("module example.test/openbao\n\ngo 1.25.8\n\nrequire (\n"
                        + MODULE.OLD_MOD_LINE + "\n\t" + JOSE + " v4.1.4\n)\n")
        final_mod = original_mod.replace("go 1.25.8", "go 1.26.0").replace(
            MODULE.OLD_MOD_LINE, MODULE.NEW_MOD_LINE).replace(JOSE + " v4.1.4", JOSE + " v4.1.6")
        original_sum = "\n".join((*MODULE.OLD_SUM_LINES, *OLD_SUMS)) + "\n"
        lines = set((*MODULE.NEW_SUM_LINES, *NEW_SUMS))
        for mapping in (MODULE.REVIEWED_TRANSITIVE_SUM_LINES, MODULE.REVIEWED_SECURITY_SUM_LINES):
            for records in mapping.values():
                lines.update(records)
        return original_mod, original_sum, final_mod, "\n".join(sorted(lines)) + "\n"

    def test_reviewed_jose_tidy_is_accepted(self):
        MODULE.validate_tidy_result(*self.tidy_fixture())

    def test_jose_downgrade_and_missing_fixed_checksums_are_refused(self):
        old_mod, old_sum, final_mod, final_sum = self.tidy_fixture()
        cases = [(final_mod.replace(JOSE + " v4.1.6", JOSE + " v4.1.4"), final_sum)]
        cases += [(final_mod, final_sum.replace(line + "\n", "")) for line in NEW_SUMS]
        for mod, sums in cases:
            with self.subTest(mod=mod, sums=sums), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(old_mod, old_sum, mod, sums)


if __name__ == "__main__":
    unittest.main()
