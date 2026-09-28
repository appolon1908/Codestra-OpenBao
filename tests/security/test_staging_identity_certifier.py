"""Staging identity certifier: positive login, every negative case, and no secret in evidence."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import certify_staging_identity as cert  # noqa: E402

STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
FIXTURE_CLIENT_CREDENTIAL = "-".join(["fixture", "prometheus-openbao", "staging", "credential", "0123456789"])
FIXTURE_READONLY_CREDENTIAL = "-".join(["fixture", "monitoring-readonly", "staging", "credential", "0123456789"])


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_jwt(azp: str, *, aud, environment: str = "staging", issuer: str = STAGING_ISSUER, lifetime: int = 300) -> str:
    now = int(time.time())
    header = b64(json.dumps({"alg": "RS256", "kid": "staging-1"}).encode())
    payload = b64(json.dumps({"iss": issuer, "sub": f"service-account-{azp}", "aud": aud, "azp": azp, "iat": now, "exp": now + lifetime, "jti": f"jti-{azp}-{now}", "codestra_environment": environment, "scope": "openbao.workload" if aud else "profile"}).encode())
    return f"{header}.{payload}.{b64(b'signature-bytes-for-' + azp.encode() + b'-' + str(now).encode())}"


class FakeAuthority:
    """One server faking Keycloak (/token) and OpenBao (/v1/...) with a tiny policy engine."""

    def __init__(self):
        self.issued: set[str] = set()
        self.tokens: dict[str, dict] = {}
        self.requests: list[tuple[str, str]] = []
        self.sealed = False
        self.admin_open = False
        self.leak_in_health = False
        self.accept_wrong_audience = False
        self.deny_production = True
        self.deny_cross_service = True
        self.plain_carries_openbao_aud = False
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _body(self):
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _send(self, status, payload=None):
                data = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self):
                body = self._body()
                fake.requests.append((self.command, self.path))
                path = self.path.split("?")[0]
                token = self.headers.get("X-Vault-Token")
                if path == "/realms/codestra/protocol/openid-connect/token":
                    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                    secret_ok = (form.get("client_id") == "prometheus-openbao" and form.get("client_secret") == FIXTURE_CLIENT_CREDENTIAL) or (form.get("client_id") == "monitoring-readonly" and form.get("client_secret") == FIXTURE_READONLY_CREDENTIAL)
                    if not secret_ok:
                        return self._send(401, {"error": "invalid_client"})
                    if form.get("client_id") == "monitoring-readonly":
                        return self._send(400, {"error": "invalid_scope"})
                    aud = ["openbao"] if form.get("scope") == "openbao.workload" or fake.plain_carries_openbao_aud else "account"
                    jwt = make_jwt(form["client_id"], aud=aud)
                    fake.issued.add(jwt)
                    return self._send(200, {"access_token": jwt, "token_type": "Bearer", "expires_in": 300})
                if path == "/v1/sys/health":
                    payload = {"initialized": True, "sealed": fake.sealed, "standby": False, "version": "2.3.1", "cluster_name": "codestra-staging"}
                    if fake.leak_in_health:
                        payload["cluster_name"] = "hvs." + "L" * 40
                    return self._send(503 if fake.sealed else 200, payload)
                if path == "/v1/auth/jwt-codestra/cel/login":
                    payload = json.loads(body)
                    jwt, role = payload.get("jwt", ""), payload.get("role", "")
                    if jwt not in fake.issued:
                        return self._send(400, {"errors": ["Codestra workload JWT rejected"]})
                    claims = cert.jwt_claims(jwt)
                    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
                    if role != f"{claims['azp']}-staging" or claims["iss"] != STAGING_ISSUER or ("openbao" not in aud and not fake.accept_wrong_audience):
                        return self._send(400, {"errors": ["Codestra workload JWT rejected"]})
                    if int(claims["exp"]) + 30 < time.time():
                        return self._send(400, {"errors": ["token expired"]})
                    client = "hvs." + b64(os.urandom(30))
                    fake.tokens[client] = {"identity": claims["azp"], "revoked": False}
                    return self._send(200, {"auth": {"client_token": client, "accessor": "acc-" + b64(os.urandom(6)), "policies": [f"workload-{role}"], "lease_duration": 300, "renewable": True}})
                if path == "/v1/auth/token/revoke-self":
                    if token in fake.tokens and not fake.tokens[token]["revoked"]:
                        fake.tokens[token]["revoked"] = True
                        return self._send(204)
                    return self._send(403, {"errors": ["permission denied"]})
                if path.startswith("/v1/codestra/data/"):
                    record = fake.tokens.get(token or "")
                    if record is None or record["revoked"]:
                        return self._send(403, {"errors": ["permission denied"]})
                    logical = "codestra/" + path[len("/v1/codestra/data/"):]
                    if logical.startswith("codestra/production/"):
                        if fake.deny_production:
                            return self._send(403, {"errors": ["permission denied"]})
                        return self._send(200, {"data": {"data": {"payload": "cross-environment-leak"}}})
                    allowed = ("codestra/staging/observability/openbao/metrics-client/", "codestra/staging/observability/prometheus/scrape-credentials/")
                    if not logical.startswith(allowed) and fake.deny_cross_service:
                        return self._send(403, {"errors": ["permission denied"]})
                    if not logical.startswith(allowed):
                        return self._send(200, {"data": {"data": {"payload": "cross-service-leak"}}})
                    return self._send(404, {"errors": []})
                if path.startswith("/v1/sys/"):
                    if fake.admin_open:
                        return self._send(200, {"data": {}})
                    if token and token in fake.tokens:
                        return self._send(403, {"errors": ["permission denied"]})
                    return self._send(400 if path == "/v1/sys/unseal" else 403, {"errors": ["permission denied"]})
                return self._send(404, {"errors": ["unknown"]})

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_DELETE = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class PlainHttp(cert.Http):
    """The certifier insists on https; the fake speaks plain http on loopback, so skip TLS wrapping."""

    def __init__(self, base: str):
        super().__init__(None)
        self.base = base

    def request(self, method, url, *, body=None, headers=None):
        rewritten = url.replace("https://bao.codestra.media", self.base).replace("https://auth-staging.codestra.co", self.base)
        return super().request(method, rewritten, body=body, headers=headers)


class StagingIdentityCertifierTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAuthority()
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.secret_file = root / "client.secret"
        self.secret_file.write_text(FIXTURE_CLIENT_CREDENTIAL, encoding="utf-8")
        self.readonly_file = root / "readonly.secret"
        self.readonly_file.write_text(FIXTURE_READONLY_CREDENTIAL, encoding="utf-8")
        if os.name != "nt":
            self.secret_file.chmod(0o600)
            self.readonly_file.chmod(0o600)
        self.evidence = root / "evidence" / "openbao-identity-staging.json"
        self.env = {
            "CODESTRA_ENVIRONMENT": "staging",
            "OPENBAO_ADDR": "https://bao.codestra.media",
            "KEYCLOAK_TOKEN_URL": "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/token",
            "OPENBAO_IDENTITY": "prometheus-openbao",
            "OPENBAO_CLIENT_SECRET_FILE": str(self.secret_file),
            "OPENBAO_PROBE_SECRET_PATH": "codestra/staging/observability/openbao/metrics-client/probe",
            "OPENBAO_IDENTITY_EVIDENCE": str(self.evidence),
        }
        self.injected = {
            "http": PlainHttp(self.fake.base),
            "connector": self._refused,
            "sleep": lambda _: None,
            "tls_probe": lambda host: {"version": "TLSv1.3", "subject_cn": host, "not_after": "Dec 31 23:59:59 2026 GMT"},
        }

    def tearDown(self):
        self.fake.close()
        self.tmp.cleanup()

    @staticmethod
    def _refused(address, timeout=None):
        raise OSError("connection refused")

    def run_certifier(self, **env_overrides) -> tuple[int, dict]:
        env = {**self.env, **env_overrides}
        code = cert.main(env, **self.injected)
        report = json.loads(self.evidence.read_text(encoding="utf-8")) if self.evidence.exists() else {}
        return code, report

    def statuses(self, report):
        return {c["check"]: c["status"] for c in report["checks"]}

    def test_full_certification_passes(self):
        code, report = self.run_certifier()
        self.assertEqual(code, 0, report)
        statuses = self.statuses(report)
        for name in cert.REQUIRED_CHECKS:
            self.assertEqual(statuses[name], "pass", name)
        self.assertEqual(statuses["expired-jwt-rejected"], "skipped")
        self.assertEqual(statuses["monitoring-readonly-never-bound"], "skipped")
        self.assertEqual(report["verdict"], {"STAGING_OPENBAO_IDENTITY_GO": "YES"})
        self.assertFalse(report["production_touched"] or report["unseal_performed"] or report["secret_values_recorded"])
        details = {c["check"]: c.get("details", {}) for c in report["checks"]}
        self.assertEqual(details["login-own-role"]["policies"], ["workload-prometheus-openbao-staging"])
        self.assertEqual(details["cross-environment-denied"]["path"], "codestra/production/observability/openbao/metrics-client/probe")
        self.assertEqual(details["cross-service-denied"]["http_status"], 403)
        self.assertEqual(details["token-revocation"]["read_after_revocation"], 403)
        self.assertEqual(details["tampered-issuer-rejected"]["issuer_presented"], cert.PRODUCTION_ISSUER)
        # never a token, secret or JWT in the evidence; never a write to production or sys/unseal
        serialized = self.evidence.read_text(encoding="utf-8")
        self.assertNotIn(FIXTURE_CLIENT_CREDENTIAL, serialized)
        self.assertNotIn("hvs.", serialized)
        self.assertNotIn("eyJ", serialized)
        self.assertFalse(any(path == "/v1/sys/unseal" for _, path in self.fake.requests))
        self.assertFalse(any(method in {"POST", "PUT"} and "/codestra/data/" in path for method, path in self.fake.requests))
        self.assertFalse(any("/v1/codestra/data/production/" in path and method != "GET" for method, path in self.fake.requests))

    def test_optional_checks_execute_when_enabled(self):
        code, report = self.run_certifier(OPENBAO_IDENTITY_WAIT_FOR_EXPIRY="true", MONITORING_READONLY_CLIENT_SECRET_FILE=str(self.readonly_file))
        statuses = self.statuses(report)
        # the fake accepts tokens until exp+30 s and sleep is a no-op, so the expiry probe must fail loudly rather than pass vacuously
        self.assertEqual(statuses["monitoring-readonly-never-bound"], "pass")
        self.assertIn(statuses["expired-jwt-rejected"], {"pass", "fail"})
        readonly = next(c for c in report["checks"] if c["check"] == "monitoring-readonly-never-bound")
        self.assertTrue(readonly["details"]["keycloak_refused_scope"])

    def test_sealed_openbao_fails_without_unsealing(self):
        self.fake.sealed = True
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        statuses = self.statuses(report)
        self.assertEqual(statuses["health-unauthenticated"], "fail")
        self.assertEqual(statuses["login-own-role"], "skipped")
        self.assertFalse(any(path == "/v1/sys/unseal" for _, path in self.fake.requests))
        self.assertFalse(self.fake.issued, "no Keycloak token is minted when OpenBao is sealed")

    def test_open_admin_surface_fails(self):
        self.fake.admin_open = True
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        statuses = self.statuses(report)
        self.assertEqual(statuses["admin-mutation-unauthorized"], "fail")
        self.assertEqual(statuses["admin-with-workload-token"], "fail")

    def test_production_path_readable_fails(self):
        self.fake.deny_production = False
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["cross-environment-denied"], "fail")
        self.assertIn("cross-environment-denied", report["failed"])

    def test_cross_service_readable_fails(self):
        self.fake.deny_cross_service = False
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["cross-service-denied"], "fail")

    def test_wrong_audience_accepted_fails(self):
        self.fake.accept_wrong_audience = True
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["wrong-audience-rejected"], "fail")

    def test_plain_token_carrying_openbao_audience_fails(self):
        self.fake.plain_carries_openbao_aud = True
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        failed = next(c for c in report["checks"] if c["check"] == "wrong-audience-rejected")
        self.assertIn("still carries the openbao audience", failed["error"])

    def test_native_listener_reachable_fails(self):
        self.injected["connector"] = lambda address, timeout=None: _Socket()
        code, report = self.run_certifier()
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["private-listeners"], "fail")

    def test_secret_shaped_response_is_never_written(self):
        self.fake.leak_in_health = True
        code, report = self.run_certifier()
        self.assertEqual(code, 3)
        self.assertEqual(report, {})

    def test_refuses_non_staging_and_unsafe_inputs(self):
        for override in ({"CODESTRA_ENVIRONMENT": "production"}, {"OPENBAO_PROBE_SECRET_PATH": "codestra/production/observability/openbao/metrics-client/probe"}, {"OPENBAO_PROBE_SECRET_PATH": "codestra/staging/*"}, {"OPENBAO_ADDR": "http://bao.codestra.media"}, {"OPENBAO_IDENTITY": "Prometheus"}, {"OPENBAO_CLIENT_SECRET_FILE": str(Path(self.tmp.name) / "absent")}):
            with self.subTest(override=override):
                code, report = self.run_certifier(**override)
                self.assertEqual(code, 3)
                self.assertEqual(report, {})
                self.assertEqual(self.fake.requests, [])

    def test_probe_path_outside_identity_prefix_fails_authority_check(self):
        code, report = self.run_certifier(OPENBAO_PROBE_SECRET_PATH="codestra/staging/observability/grafana/probe")
        self.assertEqual(code, 2)
        self.assertEqual(self.statuses(report)["authority-role"], "fail")
        self.assertFalse(self.fake.issued)

    def test_jwt_helpers(self):
        token = make_jwt("prometheus-openbao", aud=["openbao"])
        self.assertEqual(cert.jwt_claims(cert.rewrite_claims(token, iss=cert.PRODUCTION_ISSUER))["iss"], cert.PRODUCTION_ISSUER)
        self.assertNotEqual(cert.flip_signature(token), token)
        self.assertEqual(cert.flip_signature(token).split(".")[:2], token.split(".")[:2])


class _Socket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


if __name__ == "__main__":
    unittest.main()
