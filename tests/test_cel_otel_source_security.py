"""Verify fixed CEL/trace SDK selection and reject artifact identity drift."""
from __future__ import annotations
import contextlib
import hashlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cel_otel_overlay", ROOT/"scripts/prepare_openbao_source_build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PINS = {"github.com/google/cel-go":"v0.30.0", "github.com/go-logr/logr":"v1.4.4",
        **{"go.opentelemetry.io/"+name:"v1.45.0" for name in ("otel","otel/sdk","otel/trace","otel/metric")}}

class CelOtelSourceSecurityTests(unittest.TestCase):
    def source(self, root):
        for name in ("go.mod","go.sum"):
            (root/name).write_bytes((ROOT/"upstream"/name).read_bytes())
        return root

    def test_real_import_selects_maintainer_fixed_releases_without_mutating_upstream(self):
        original={name:hashlib.sha256((ROOT/"upstream"/name).read_bytes()).hexdigest() for name in ("go.mod","go.sum")}
        with tempfile.TemporaryDirectory() as tmp:
            root=self.source(Path(tmp)); result=MODULE.apply(root)
            selected=MODULE.module_versions((root/"go.mod").read_text())
            for module,version in PINS.items():
                with self.subTest(module=module):
                    self.assertEqual(selected.get(module),version)
                    self.assertEqual(result["reviewed_security_module_versions"].get(module),version)
                    for line in MODULE.REVIEWED_SECURITY_SUM_LINES[module]:
                        self.assertIn(line,(root/"go.sum").read_text().splitlines())
        self.assertEqual(original,{name:hashlib.sha256((ROOT/"upstream"/name).read_bytes()).hexdigest() for name in original})

    def test_unreviewed_cel_or_sdk_baseline_is_rejected_before_any_write(self):
        for name,old,new in (
            ("go.mod","github.com/google/cel-go v0.28.1","github.com/google/cel-go v0.29.0"),
            ("go.mod","go.opentelemetry.io/otel/sdk v1.44.0","go.opentelemetry.io/otel/sdk v1.43.0"),
            ("go.sum","go.opentelemetry.io/otel/sdk v1.44.0 h1:nHYwb9lK+fJPU/dnT6s7W7Z8itMWyqrnVfbheVYrZ58=","")):
            with self.subTest(old=old),tempfile.TemporaryDirectory() as tmp:
                root=self.source(Path(tmp)); p=root/name;p.write_text(p.read_text().replace(old,new))
                before={n:(root/n).read_bytes() for n in ("go.mod","go.sum")}
                with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                    MODULE.apply(root)
                self.assertEqual(before,{n:(root/n).read_bytes() for n in before})

    def test_candidate_builder_executes_new_semantics_and_actual_diagnose_consumer(self):
        script=(ROOT/"scripts/validate_source_artifacts.sh").read_text()
        self.assertIn("./codestra/security/celotel",script)
        self.assertIn("tests/go/celotelsecurity/openbao_test.go.fixture",script)
        self.assertIn("./vault/diagnose",script)
        self.assertIn("^TestDiagnoseOtelResults$",script)

    def tidy_documents(self):
        original_mod=("module example.invalid/openbao\n\ngo 1.25.8\n\nrequire (\n"+
                      MODULE.OLD_MOD_LINE+"\n"+
                      "".join(" "+m+" "+old+"\n" for m,(old,_) in MODULE.SECURITY_GRAPH_UPGRADES.items())+")\n")
        final_mod=original_mod.replace("go 1.25.8","go 1.26.0").replace(MODULE.OLD_MOD_LINE,MODULE.NEW_MOD_LINE)
        for module,(old,new) in MODULE.SECURITY_GRAPH_UPGRADES.items():
            final_mod=final_mod.replace(module+" "+old,module+" "+new)
        original_sum="\n".join((*MODULE.OLD_SUM_LINES,*MODULE.JOSE_OLD_SUM_LINES,
                                 *(line for lines in MODULE.CEL_OTEL_OLD_SUM_LINES.values() for line in lines)))+"\n"
        final_sum="\n".join((*MODULE.NEW_SUM_LINES,
                              *(line for mapping in (MODULE.REVIEWED_TRANSITIVE_SUM_LINES,MODULE.REVIEWED_SECURITY_SUM_LINES)
                                for lines in mapping.values() for line in lines)))+"\n"
        return original_mod,original_sum,final_mod,final_sum

    def test_tidy_rejects_cel_sdk_downgrades_and_missing_fixed_checksums(self):
        old_mod,old_sum,final_mod,final_sum=self.tidy_documents()
        MODULE.validate_tidy_result(old_mod,old_sum,final_mod,final_sum)
        cases=[(final_mod.replace(module+" "+version,module+" v0.0.1"),final_sum) for module,version in PINS.items()]
        cases += [(final_mod,final_sum.replace(line+"\n",""))
                  for module in PINS for line in MODULE.REVIEWED_SECURITY_SUM_LINES[module]]
        for mod,sums in cases:
            with self.subTest(mod=mod,sums=sums),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(old_mod,old_sum,mod,sums)

    def test_optional_sdk_graph_records_are_exact_and_selected_packages_need_zip_sum(self):
        old_mod,old_sum,final_mod,final_sum=self.tidy_documents()
        for module,version in (("go.opentelemetry.io/otel/sdk/metric","v1.45.0"),
                               ("go.opentelemetry.io/otel/metric/x","v0.67.0")):
            zip_sum,mod_sum=MODULE.REVIEWED_OPTIONAL_SUM_LINES[module]
            MODULE.validate_tidy_result(old_mod,old_sum,final_mod,final_sum+mod_sum+"\n")
            selected=final_mod.replace(")\n"," "+module+" "+version+" // indirect\n)\n")
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(old_mod,old_sum,selected,final_sum+mod_sum+"\n")
            MODULE.validate_tidy_result(old_mod,old_sum,selected,final_sum+zip_sum+"\n"+mod_sum+"\n")
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                MODULE.validate_tidy_result(old_mod,old_sum,final_mod,final_sum+mod_sum.replace("h1:","h1:bad")+"\n")

if __name__=="__main__":
    unittest.main()
