#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okta_overlay", ROOT / "scripts/prepare_openbao_source_build.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
OLD = "github.com/okta/okta-sdk-golang/v2"
NEW = "github.com/okta/okta-sdk-golang/v6"
FILES = ("go.mod", "go.sum", "vault/login_mfa.go", "vault/workflow_store.go")


class OktaSourceSecurityTests(unittest.TestCase):
    def source(self, root):
        for name in FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / "upstream" / name).read_bytes())
        return root

    def test_real_overlay_migrates_mfa_and_preserves_imported_source(self):
        before = {name: (ROOT / "upstream" / name).read_bytes() for name in FILES}
        with tempfile.TemporaryDirectory() as temp:
            source = self.source(Path(temp))
            proof = MODULE.apply(source)
            versions = MODULE.module_versions((source / "go.mod").read_text())
            self.assertNotIn(OLD, versions)
            self.assertEqual(versions.get(NEW), "v6.1.7")
            self.assertNotIn(OLD, (source / "go.sum").read_text())
            transformed = (source / "vault/login_mfa.go").read_bytes()
            self.assertNotIn(OLD.encode(), transformed)
            self.assertIn(NEW.encode(), transformed)
            self.assertEqual(proof["okta_mfa_overlay"]["source_sha256_after"], hashlib.sha256(transformed).hexdigest())
            # Other authentication methods retain their exact imported bodies.
            original = before["vault/login_mfa.go"]
            marker = b"func (c *Core) validatePingID("
            self.assertEqual(original.split(marker, 1)[1], transformed.split(marker, 1)[1])
        self.assertEqual(before, {name: (ROOT / "upstream" / name).read_bytes() for name in FILES})

    def test_go126_workflow_diagnostic_changes_only_integer_count_verb(self):
        original = (ROOT / "upstream/vault/workflow_store.go").read_text()
        old = 'fmt.Errorf("have %q values for %q header; expected only 1", len(values), consts.NamespaceHeaderName)'
        new = old.replace('have %q values', 'have %d values')
        self.assertEqual(original.count(old), 1)
        with tempfile.TemporaryDirectory() as temp:
            source = self.source(Path(temp))
            proof = MODULE.apply(source)
            actual = (source / "vault/workflow_store.go").read_text()
            self.assertEqual(actual, original.replace(old, new, 1))
            self.assertEqual(proof["workflow_go126_overlay"]["source_sha256_after"],
                             hashlib.sha256(actual.encode()).hexdigest())
        self.assertEqual((ROOT / "upstream/vault/workflow_store.go").read_text(), original)

    def test_changed_or_missing_workflow_baseline_is_rejected_before_any_write(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                source = self.source(Path(temp))
                path = source / "vault/workflow_store.go"
                if missing:
                    path.unlink()
                else:
                    path.write_text(path.read_text().replace('len(values) > 1', 'len(values) > 2'))
                before = {name: (source / name).read_bytes() for name in FILES if (source / name).exists()}
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    MODULE.apply(source)
                self.assertEqual(before, {name: (source / name).read_bytes() for name in before})
                if missing:
                    self.assertFalse(path.exists())

    def test_changed_mfa_or_dependency_baseline_is_rejected_before_any_write(self):
        for name in FILES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                source = self.source(Path(temp))
                path = source / name
                text = path.read_text()
                if name == "go.mod":
                    text = text.replace(OLD + " v2.20.0", OLD + " v2.19.0")
                elif name == "go.sum":
                    text = text.replace(OLD + " v2.20.0 h1:", OLD + " v2.20.0 h1:tampered")
                elif name == "vault/workflow_store.go":
                    text = text.replace("len(values) > 1", "len(values) > 2")
                else:
                    text = text.replace('case "SUCCESS":', 'case "ACCEPT_ANYTHING":', 1)
                path.write_text(text)
                before = {item: (source / item).read_bytes() for item in FILES}
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    MODULE.apply(source)
                self.assertEqual(before, {item: (source / item).read_bytes() for item in FILES})

    @unittest.skipUnless(shutil.which("go"), "standalone standard-library transport check needs local Go")
    def test_fixture_intercepts_the_sdk_allocated_http_client(self):
        fixture = (ROOT / "tests/go/oktamfa/security_test.go.fixture").read_text()
        transport_type = fixture.split("type codestraOktaTransport", 1)[1].split("// Exercise", 1)[0]
        setup = fixture.split("local, _ := url.Parse(server.URL)", 1)[1].split(
            "// Exercise the production override", 1)[0]
        # Execute the fixture's actual setup with the fresh empty HTTPClient that
        # envconfig creates, rather than assuming the SDK uses DefaultClient.
        source = r'''package vault
import ("errors"; "io"; "net/http"; "net/http/httptest"; "net/url"; "testing")
type codestraOktaTransport''' + transport_type + r'''
func TestAllocatedSDKClientUsesFixtureTransport(t *testing.T) {
    // A broken interception must fail locally rather than attempt external DNS.
    originalTransport := http.DefaultTransport
    http.DefaultTransport = codestraOktaTransport(func(*http.Request) (*http.Response, error) {
        return nil, errors.New("test transport seam bypassed")
    })
    defer func() { http.DefaultTransport = originalTransport }()
    calls := 0
    server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls++
        io.WriteString(w, "isolated-fixture")
    }))
    defer server.Close()
    local, _ := url.Parse(server.URL)
''' + setup + r'''
    response, err := (&http.Client{}).Get("https://tenant.example.test/probe")
    if err != nil { t.Fatal(err) }
    defer response.Body.Close()
    body, err := io.ReadAll(response.Body)
    if err != nil || string(body) != "isolated-fixture" || calls != 1 {
        t.Fatalf("request missed isolated server: calls=%d, body=%q, error=%v", calls, body, err)
    }
}
'''
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "transport_test.go").write_text(source)
            env = {**os.environ, "GO111MODULE": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
                   "GOPROXY": "off", "GOSUMDB": "off"}
            result = subprocess.run([shutil.which("go"), "test", "-count=1", "-timeout=15s", "."],
                                    cwd=root, env=env, text=True, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_declared_okta_graph_rejects_other_versions_and_checksums(self):
        # Minimal valid reconciliation documents from the existing overlay suite.
        spec = importlib.util.spec_from_file_location("base_test", ROOT / "tests/test_prepare_openbao_source_build.py")
        base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
        original_mod, original_sum, final_mod, final_sum = base.SourceBuildPatchTests().reviewed_tidy_documents()
        for module, item in MODULE.OKTA_GRAPH.items():
            with self.subTest(module=module):
                selected = final_mod + module + " " + item['version'] + " // indirect\n"
                sums = final_sum + "\n".join(item['checksums']) + "\n"
                MODULE.validate_tidy_result(original_mod, original_sum, selected, sums)
                for mod, checksums in (
                    (selected.replace(module + " " + item['version'], module + " v999.0.0"), sums),
                    (selected, sums.replace(item['checksums'][0], item['checksums'][0] + "tampered")),
                ):
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        MODULE.validate_tidy_result(original_mod, original_sum, mod, checksums)


if __name__ == "__main__":
    unittest.main()
