from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("unseal_from_files", ROOT / "scripts/unseal_from_files.py")
unseal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(unseal)


class UnsealTransportTests(unittest.TestCase):
    def test_http_requires_explicit_local_development_or_test(self) -> None:
        for environment in ("development", "test"):
            for address in ("http://127.0.0.1:8200", "http://[::1]:8200", "http://localhost:8200"):
                unseal.validate_address(address, environment)
        for environment, address in (
            ("", "http://127.0.0.1"),
            ("production", "http://127.0.0.1"),
            ("staging", "http://localhost"),
            ("test", "http://127.0.0.1.example.invalid"),
            ("development", "http://192.0.2.1"),
        ):
            with self.subTest(environment=environment, address=address):
                with self.assertRaises(ValueError):
                    unseal.validate_address(address, environment)

    def test_malformed_origins_are_rejected(self) -> None:
        for address in (
            "https://user:password@bao.example.invalid",
            "https://bao.example.invalid/path", "https://bao.example.invalid?q=x",
            "https://bao.example.invalid#fragment", "file:///share",
            "https://bao.example.invalid:99999", "https://bao.example.invalid\n",
        ):
            with self.subTest(address=address), self.assertRaises(ValueError):
                unseal.validate_address(address, "production")

    def test_https_requires_client_authentication_and_tls13(self) -> None:
        env = {"BAO_ADDR": "https://bao.example.invalid", "CODESTRA_ENVIRONMENT": "production", "BAO_CACERT": "/test/ca"}
        with patch.dict(os.environ, env, clear=True), patch.object(ssl, "create_default_context") as create:
            with self.assertRaises(ValueError):
                unseal.context()
            os.environ.update(BAO_CLIENT_CERT="/test/cert", BAO_CLIENT_KEY="/test/key")
            tls = unseal.context()
            self.assertEqual(tls.minimum_version, ssl.TLSVersion.TLSv1_3)
            tls.load_cert_chain.assert_called_once_with("/test/cert", "/test/key")
            self.assertEqual(create.call_args.kwargs, {"cafile": "/test/ca"})

    def test_local_redirect_does_not_forward_request(self) -> None:
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(307)
                self.send_header("Location", "/redirected")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises((ValueError, urllib.error.HTTPError)):
                unseal.submit(f"http://127.0.0.1:{server.server_port}", "local-test-only", None)
            self.assertEqual(requests, ["/v1/sys/unseal"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_proxy_environment_is_ignored_and_response_is_checked(self) -> None:
        with patch.object(unseal.urllib.request, "build_opener") as build:
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"sealed":false}'
            with patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128"}):
                self.assertEqual(unseal.submit("https://bao.example.invalid", "local-test-only", None), {"sealed": False})
            handlers = build.call_args.args
            proxy = next(h for h in handlers if isinstance(h, unseal.urllib.request.ProxyHandler))
            self.assertEqual(proxy.proxies, {})
            self.assertTrue(any(isinstance(h, unseal.NoRedirects) for h in handlers))
            build.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"sealed":"false"}'
            with self.assertRaises(ValueError):
                unseal.submit("https://bao.example.invalid", "local-test-only", None)


class UnsealFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.files = []
        for index in range(3):
            path = self.work / f"share-{index}"
            path.write_text(f"synthetic-share-{index}", encoding="utf-8")
            path.chmod(0o400)
            self.files.append(str(path))

    def test_private_distinct_files_pass(self) -> None:
        self.assertEqual(unseal.read_shares(self.files), [f"synthetic-share-{i}" for i in range(3)])

    def test_public_or_symbolic_files_are_rejected(self) -> None:
        Path(self.files[0]).chmod(0o644)
        with self.assertRaises(ValueError):
            unseal.read_shares(self.files)
        Path(self.files[0]).chmod(0o400)
        link = self.work / "symbolic-share"
        link.symlink_to(self.files[0])
        with self.assertRaises(ValueError):
            unseal.read_shares([str(link)])

    def test_duplicate_files_or_contents_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            unseal.read_shares([self.files[0], self.files[0]])
        alias = self.work / "hardlink"
        os.link(self.files[0], alias)
        with self.assertRaises(ValueError):
            unseal.read_shares([self.files[0], str(alias)])
        duplicate = self.work / "duplicate"
        duplicate.write_text("synthetic-share-0", encoding="utf-8")
        duplicate.chmod(0o400)
        with self.assertRaises(ValueError):
            unseal.read_shares([self.files[0], str(duplicate)])

    def test_empty_oversized_and_nonregular_files_are_rejected(self) -> None:
        for content in ("", "x" * 16385):
            path = self.work / "invalid"
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                unseal.read_shares([str(path)])
        fifo = self.work / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError):
            unseal.read_shares([str(fifo)])

    def env(self) -> dict[str, str]:
        return {"BAO_ADDR": "http://127.0.0.1:8200", "CODESTRA_ENVIRONMENT": "test", "OPENBAO_UNSEAL_KEY_FILES": ":".join(self.files)}

    def test_all_files_checked_before_first_submission(self) -> None:
        Path(self.files[-1]).chmod(0o644)
        with patch.dict(os.environ, self.env(), clear=True), patch.object(unseal, "submit") as submit:
            with self.assertRaises(SystemExit):
                unseal.main()
            submit.assert_not_called()

    def test_validate_only_checks_inputs_without_submitting(self) -> None:
        output = io.StringIO()
        with patch.dict(os.environ, self.env(), clear=True), patch.object(unseal, "submit") as submit, contextlib.redirect_stdout(output):
            unseal.main(validate_only=True)
            submit.assert_not_called()
        self.assertEqual(output.getvalue(), "OPENBAO_UNSEAL_INPUTS=PASS\n")

    def test_restore_rejects_invalid_unseal_inputs_before_external_commands(self) -> None:
        fake_bin = self.work / "bin"
        fake_bin.mkdir()
        calls = self.work / "external-calls"
        for command in ("age", "bao", "jq", "realpath", "sha256sum", "shred", "stat"):
            executable = fake_bin / command
            executable.write_text('#!/usr/bin/env bash\nprintf "unexpected\\n" >> "$FAKE_EXTERNAL_CALLS"\nexit 97\n', encoding="utf-8")
            executable.chmod(0o700)
        env = {
            **self.env(),
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "FAKE_EXTERNAL_CALLS": str(calls),
            "CODESTRA_ENVIRONMENT": "staging",
            "OPENBAO_RESTORE_ARTIFACT": self.files[0],
            "OPENBAO_RESTORE_CHECKSUM": self.files[0],
            "OPENBAO_AGE_IDENTITY_FILE": self.files[0],
            "OPENBAO_PRODUCTION_CLUSTER_ID": "excluded-synthetic-cluster",
            "OPENBAO_RESTORE_EVIDENCE": str(self.work / "evidence.json"),
            "OPENBAO_OPERATOR_TOKEN_FILE": self.files[0],
            "OPENBAO_RESTORED_PROBE_TOKEN_FILE": self.files[1],
            "OPENBAO_RESTORED_PROBE_EXPECTED_POLICY": "restored-probe",
            "OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED": "true",
        }
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/restore-test.sh")],
            env={**os.environ, **env}, capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("OPENBAO_UNSEAL=FAIL", result.stderr)
        self.assertFalse(calls.exists())
        self.assertFalse((self.work / "evidence.json").exists())

    def test_stop_after_success_and_print_only_sanitized_result(self) -> None:
        output = io.StringIO()
        with patch.dict(os.environ, self.env(), clear=True), patch.object(unseal, "submit", side_effect=[{"sealed": True}, {"sealed": False}]) as submit, contextlib.redirect_stdout(output):
            unseal.main()
        self.assertEqual(submit.call_count, 2)
        self.assertEqual(output.getvalue(), "OPENBAO_UNSEAL=PASS\nUNSEAL_SHARES_SUBMITTED=2\n")

    def test_transport_failure_does_not_echo_error_content(self) -> None:
        for failure in (ValueError, OSError, unseal.HTTPException):
            with self.subTest(failure=failure), patch.dict(os.environ, self.env(), clear=True), patch.object(unseal, "submit", side_effect=failure("sensitive-response-canary")):
                with self.assertRaises(SystemExit) as error:
                    unseal.main()
            self.assertNotIn("sensitive-response-canary", str(error.exception))
            self.assertNotIn("synthetic-share", str(error.exception))


if __name__ == "__main__":
    unittest.main()
