"""Fail-closed application of the maintainer-origin v3 parser backport."""
import importlib.util
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jose_vendor", ROOT / "scripts/patch_jose_v3_vendor.py")

class VendorBackportTests(unittest.TestCase):
    def module(self):
        module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(module)
        return module

    def fixture(self, root):
        vendor = root / "vendor"
        target = vendor / "github.com/go-jose/go-jose/v3"
        target.mkdir(parents=True)
        (vendor / "modules.txt").write_text("# github.com/go-jose/go-jose/v3 v3.0.5\n## explicit; go 1.12\ngithub.com/go-jose/go-jose/v3\n")
        (target / "jwk.go").write_text("old\n")
        (target / "shared.go").write_text("second\n")
        manifest = {"upstream_fix": "a0111f82742fa92bceec9ede40845e73319e6230", "files": {
            "jwk.go": {"before": hashlib.sha256(b"old\n").hexdigest(), "after": hashlib.sha256(b"new\n").hexdigest()},
            "shared.go": {"before": hashlib.sha256(b"second\n").hexdigest(), "after": hashlib.sha256(b"third\n").hexdigest()}}}
        patchfile = root / "fix.patch"
        patchfile.write_text("--- a/jwk.go\n+++ b/jwk.go\n@@ -1 +1 @@\n-old\n+new\n--- a/shared.go\n+++ b/shared.go\n@@ -1 +1 @@\n-second\n+third\n")
        return target, manifest, patchfile

    def test_verified_backport_records_honest_version_and_hashes(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target, manifest, patchfile = self.fixture(root)
            evidence = module.apply(root, manifest, patchfile)
            self.assertEqual(evidence["module_version"], "v3.0.5")
            self.assertIs(evidence["runtime_authorized"], False)
            self.assertEqual((target / "jwk.go").read_text(), "new\n")
            self.assertEqual(evidence["files"]["shared.go"]["after"], manifest["files"]["shared.go"]["after"])
            self.assertRegex(evidence["vendor_tree_sha256"], r"^[0-9a-f]{64}$")

    def test_bad_second_baseline_does_not_patch_first_file(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target, manifest, patchfile = self.fixture(root)
            (target / "shared.go").write_text("unexpected\n")
            with self.assertRaisesRegex(ValueError, "baseline"):
                module.apply(root, manifest, patchfile)
            self.assertEqual((target / "jwk.go").read_text(), "old\n")

    def test_replacement_or_wrong_version_is_refused(self):
        module = self.module()
        for header in ("# github.com/go-jose/go-jose/v3 v3.0.4", "# github.com/go-jose/go-jose/v3 v3.0.5 => ./fake"):
            with self.subTest(header=header), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target, manifest, patchfile = self.fixture(root)
                (root / "vendor/modules.txt").write_text(header + "\n")
                with self.assertRaisesRegex(ValueError, "module identity"):
                    module.apply(root, manifest, patchfile)

    def test_symlinked_vendor_source_is_refused(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target, manifest, patchfile = self.fixture(root)
            (target / "jwk.go").rename(root / "outside.go")
            (target / "jwk.go").symlink_to(root / "outside.go")
            with self.assertRaisesRegex(ValueError, "symlink"):
                module.apply(root, manifest, patchfile)

    def test_bad_patch_is_refused_before_mutation(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target, manifest, patchfile = self.fixture(root)
            patchfile.write_text(patchfile.read_text().replace("-second", "-missing"))
            with self.assertRaisesRegex(ValueError, "patch"):
                module.apply(root, manifest, patchfile)
            self.assertEqual((target / "jwk.go").read_text(), "old\n")


    def test_directory_symlink_or_hardlink_cannot_mutate_external_source(self):
        import os
        module=self.module()
        for variant in ("directory-symlink","hardlink"):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                target,manifest,patchfile=self.fixture(root)
                outside=root/"external"; outside.mkdir()
                for name in manifest["files"]:
                    (outside/name).write_bytes((target/name).read_bytes())
                original={n:(outside/n).read_bytes() for n in manifest["files"]}
                if variant=="directory-symlink":
                    for p in target.iterdir(): p.unlink()
                    target.rmdir();target.symlink_to(outside,target_is_directory=True)
                else:
                    (target/"jwk.go").unlink()
                    os.link(outside/"jwk.go",target/"jwk.go")
                with self.assertRaisesRegex(ValueError,"symlink|hardlink"):
                    module.apply(root,manifest,patchfile)
                self.assertEqual(original,{n:(outside/n).read_bytes() for n in original})

if __name__ == "__main__":
    unittest.main()
