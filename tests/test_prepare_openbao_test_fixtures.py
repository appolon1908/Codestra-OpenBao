"""Restore runnable sanitized test fixtures without storing a private test key."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("jwt_fixture_repair",ROOT/"scripts/prepare_openbao_test_fixtures.py")

class SanitizedJWTFixtureTests(unittest.TestCase):
    def module(self):
        module=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(module);return module
    def source(self,root):
        for name in ("path_login_test.go","path_config_test.go"):
            path=root/"builtin/credential/jwt"/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/"upstream/builtin/credential/jwt"/name).read_bytes())
    def test_only_fixture_declarations_and_sanitized_expectation_change(self):
        module=self.module()
        original={n:(ROOT/"upstream"/n).read_bytes() for n in module.BASELINES}
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp);self.source(source)
            evidence=module.apply(source)
            login=(source/module.LOGIN).read_text()
            before=original[module.LOGIN].decode()
            self.assertEqual(login.split("var ecdsaPrivKey,")[0],before.split("const (\n\tecdsaPrivKey")[0])
            self.assertIn("codestraGeneratedJWTFixtureKeys()",login)
            config=(source/module.CONFIG).read_text()
            self.assertEqual(config.replace('OIDCClientSecret:           "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>",',
                                            'OIDCClientSecret:           "def",'),original[module.CONFIG].decode())
            self.assertFalse(evidence["assertions_removed"])
            self.assertFalse(evidence["reusable_private_key_material_stored"])
            self.assertTrue(evidence["test_only"])
            self.assertNotIn("BEGIN",json.dumps(evidence))
            helper=source/"builtin/credential/jwt/codestra_generated_keys_test.go"
            self.assertEqual(helper.read_bytes(),module.FIXTURE.read_bytes())
        for name,raw in original.items():
            self.assertEqual((ROOT/"upstream"/name).read_bytes(),raw)
    def test_any_unreviewed_baseline_fails_before_either_file_changes(self):
        module=self.module()
        for name in module.BASELINES:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp);self.source(source)
                path=source/name;path.write_text(path.read_text()+"// unexpected\n")
                before={n:(source/n).read_bytes() for n in module.BASELINES}
                with self.assertRaisesRegex(ValueError,"baseline"):
                    module.apply(source)
                self.assertEqual(before,{n:(source/n).read_bytes() for n in module.BASELINES})
    def test_second_application_is_refused(self):
        module=self.module()
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp);self.source(source);module.apply(source)
            with self.assertRaisesRegex(ValueError,"baseline"):
                module.apply(source)
    def test_symlink_and_hardlink_refused_without_external_mutation(self):
        import os
        module=self.module()
        for kind in ("symlink","hardlink"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                source=Path(tmp);self.source(source)
                path=source/module.LOGIN;outside=source/"outside.go"
                path.rename(outside)
                if kind=="symlink":path.symlink_to(outside)
                else:os.link(outside,path)
                before=outside.read_bytes()
                with self.assertRaises(ValueError):module.apply(source)
                self.assertEqual(outside.read_bytes(),before)

if __name__=="__main__":
    unittest.main()
