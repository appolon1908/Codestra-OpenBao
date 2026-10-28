"""Pin CAP's registered-claim confusion fix in isolated source builds."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cap_overlay", ROOT / "scripts/prepare_openbao_source_build.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CAP = "github.com/hashicorp/cap"


class CapSourceSecurityTests(unittest.TestCase):
    def source(self, root):
        for name in ("go.mod", "go.sum"):
            (root / name).write_bytes((ROOT / "upstream" / name).read_bytes())
        return root

    def test_real_source_selects_fixed_cap_and_preserves_imported_bytes(self):
        before = {
            name: hashlib.sha256((ROOT / "upstream" / name).read_bytes()).hexdigest()
            for name in ("go.mod", "go.sum")
        }
        with tempfile.TemporaryDirectory() as temp:
            root = self.source(Path(temp))
            proof = MODULE.apply(root)
            self.assertEqual(
                MODULE.module_versions((root / "go.mod").read_text()).get(CAP), "v0.14.0"
            )
            self.assertEqual(proof["reviewed_security_module_versions"].get(CAP), "v0.14.0")
            for line in MODULE.REVIEWED_SECURITY_SUM_LINES[CAP]:
                self.assertIn(line, (root / "go.sum").read_text().splitlines())
        self.assertEqual(
            before,
            {
                name: hashlib.sha256((ROOT / "upstream" / name).read_bytes()).hexdigest()
                for name in before
            },
        )

    def test_changed_cap_baseline_fails_before_either_file_is_written(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.source(Path(temp))
            path = root / "go.mod"
            path.write_text(path.read_text().replace(CAP + " v0.13.0", CAP + " v0.12.0"))
            before = {name: (root / name).read_bytes() for name in ("go.mod", "go.sum")}
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                MODULE.apply(root)
            self.assertEqual(
                before, {name: (root / name).read_bytes() for name in before}
            )

    def test_missing_or_tampered_cap_checksums_fail_before_writing(self):
        for expected in MODULE.CAP_OLD_SUM_LINES:
            for replacement in ("", expected.replace("h1:", "h1:tampered")):
                with self.subTest(expected=expected, replacement=replacement):
                    with tempfile.TemporaryDirectory() as temp:
                        root = self.source(Path(temp))
                        path = root / "go.sum"
                        path.write_text(path.read_text().replace(expected, replacement))
                        before = {
                            name: (root / name).read_bytes() for name in ("go.mod", "go.sum")
                        }
                        with contextlib.redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit):
                                MODULE.apply(root)
                        self.assertEqual(
                            before, {name: (root / name).read_bytes() for name in before}
                        )

    def test_signed_cap_regressions_are_run_by_candidate_builder(self):
        source = (ROOT / "scripts/validate_source_artifacts.sh").read_text()
        self.assertIn("tests/go/josev3security/cap_claims_test.go", source)
        self.assertIn("./builtin/credential/jwt", source)
        self.assertIn("./codestra/plugins/codestra-jwt-replay", source)


if __name__ == "__main__":
    unittest.main()
