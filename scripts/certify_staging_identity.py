#!/usr/bin/env python3
"""Staging OpenBao identity certification: one workload identity, positive and negative, hashes only.

    CODESTRA_ENVIRONMENT=staging OPENBAO_ADDR=https://bao.codestra.media \
    KEYCLOAK_TOKEN_URL=https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/token \
    OPENBAO_IDENTITY=prometheus-openbao OPENBAO_CLIENT_SECRET_FILE=/abs/0600/secret \
    OPENBAO_PROBE_SECRET_PATH=codestra/staging/observability/openbao/metrics-client/probe \
    OPENBAO_IDENTITY_EVIDENCE=/abs/0700/dir/openbao-identity-staging.json \
    python3 scripts/certify_staging_identity.py

Proves, against the live staging authority and only for staging:

  authority-role              the identity is a reviewed staging role of workload-secret-authority.v1.json
  private-listeners           the public name answers TLS on 443 only; native 8200/8201 are not reachable
  health-unauthenticated      GET /v1/sys/health answers without credentials; sealed state is recorded, never changed
  admin-mutation-unauthorized seal/unseal/policy/audit mutations without a token are refused
  keycloak-token              client_credentials + scope=openbao.workload yields a token bound to iss/aud/azp/env/<=300 s
  login-own-role              auth/jwt-codestra/cel/login returns exactly the workload policy with <=300 s TTL
  own-path-read               a path under the role's prefix is authorised (200 or 404, never 403)
  cross-environment-denied    the same path under codestra/production/ is 403
  cross-service-denied        another staging identity's prefix is 403
  admin-with-workload-token   sys/policies and sys/audit are 403 for the workload token
  wrong-audience-rejected     a token minted without scope=openbao.workload cannot log in
  wrong-role-rejected         the token cannot log in as another identity's role
  tampered-signature-rejected a token with a modified signature cannot log in
  tampered-issuer-rejected    a token whose iss claim was rewritten to the production issuer cannot log in
  token-revocation            revoke-self succeeds and the revoked token is then denied
  expired-jwt-rejected        (optional, OPENBAO_IDENTITY_WAIT_FOR_EXPIRY=true) login after exp+leeway is refused
  monitoring-readonly-never-bound (optional, MONITORING_READONLY_CLIENT_SECRET_FILE) no role admits monitoring-readonly

Never touches production, never unseals, never writes a secret, never prints a
token: the evidence holds statuses, claim summaries, and sha256 prefixes of
identifiers. Exit 0 = every executed check passed and no required check was
skipped; 2 = a check failed; 3 = the run could not start safely.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "config" / "workload-secret-authority.v1.json"
JWT_ROLES = ROOT / "openbao" / "auth" / "jwt-roles.v1.json"
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|s\.[A-Za-z0-9]{24,}|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN)"
)
IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")
LOGICAL_PATH = re.compile(r"^codestra/staging/[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)+$")
REQUIRED_CHECKS = (
    "authority-role", "private-listeners", "health-unauthenticated", "admin-mutation-unauthorized",
    "keycloak-token", "login-own-role", "own-path-read", "cross-environment-denied", "cross-service-denied",
    "admin-with-workload-token", "wrong-audience-rejected", "wrong-role-rejected",
    "tampered-signature-rejected", "tampered-issuer-rejected", "token-revocation",
)
OPTIONAL_CHECKS = ("expired-jwt-rejected", "monitoring-readonly-never-bound")


class CertificationError(RuntimeError):
    pass


class CheckFailed(RuntimeError):
    pass


def h(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:24]


def read_secret_file(path: str) -> str:
    file = Path(path)
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise CertificationError(f"secret file {file.name} is unavailable or unsafe")
    if os.name != "nt" and file.stat().st_mode & 0o077:
        raise CertificationError(f"secret file {file.name} must be mode 0600")
    value = file.read_text(encoding="utf-8").strip()
    if not value:
        raise CertificationError(f"secret file {file.name} is empty")
    return value


def required(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise CertificationError(f"{name} is required")
    return value


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise CheckFailed("token is not a compact JWS")
    return json.loads(b64url_decode(parts[1]))


def rewrite_claims(token: str, **changes: Any) -> str:
    """Return the same JWT with modified payload claims; its signature no longer verifies (by design)."""
    header, _, signature = token.split(".")
    claims = jwt_claims(token)
    claims.update(changes)
    payload = b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    return ".".join([header, payload, signature])


def flip_signature(token: str) -> str:
    header, payload, signature = token.split(".")
    replacement = "A" if signature[-1] != "A" else "B"
    return ".".join([header, payload, signature[:-1] + replacement])


class Http:
    def __init__(self, ca_file: str | None, timeout: float = 10.0, opener: Callable[..., Any] | None = None):
        self.context = ssl.create_default_context(cafile=ca_file)
        self.timeout = timeout
        self.opener = opener

    def request(self, method: str, url: str, *, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any] | None]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise CertificationError("only plain http(s) URLs without embedded credentials are allowed")
        request = urllib.request.Request(url, data=body, method=method, headers={"Accept": "application/json", "User-Agent": "codestra-openbao-identity-certifier/1", **(headers or {})})
        build = self.opener or urllib.request.build_opener
        opener = build(NoRedirect(), urllib.request.HTTPSHandler(context=self.context))
        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1 << 20)
                return response.status, (json.loads(raw) if raw.strip() else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read(1 << 20) if exc.fp else b""
            try:
                return exc.code, (json.loads(raw) if raw.strip() else None)
            except json.JSONDecodeError:
                return exc.code, None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CheckFailed(f"{method} {parsed.path} unreachable: {getattr(exc, 'reason', exc)}") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise CheckFailed(f"redirect refused ({code})")


def tcp_reachable(host: str, port: int, timeout: float = 3.0, connector: Callable[..., Any] | None = None) -> bool:
    connect = connector or socket.create_connection
    try:
        with connect((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Certifier:
    def __init__(self, env: dict[str, str], http: Http | None = None, connector: Callable[..., Any] | None = None, sleep: Callable[[float], None] = time.sleep, tls_probe: Callable[[str], dict[str, Any]] | None = None):
        if required("CODESTRA_ENVIRONMENT", env) != "staging":
            raise CertificationError("this certifier runs against staging only")
        self.addr = required("OPENBAO_ADDR", env).rstrip("/")
        self.token_url = required("KEYCLOAK_TOKEN_URL", env)
        self.identity = required("OPENBAO_IDENTITY", env)
        self.probe_path = required("OPENBAO_PROBE_SECRET_PATH", env)
        self.evidence_path = Path(required("OPENBAO_IDENTITY_EVIDENCE", env))
        self.wait_for_expiry = env.get("OPENBAO_IDENTITY_WAIT_FOR_EXPIRY", "false") == "true"
        self.public_host = env.get("OPENBAO_PUBLIC_HOST") or urllib.parse.urlsplit(self.addr).hostname or ""
        if not IDENTITY.fullmatch(self.identity):
            raise CertificationError("OPENBAO_IDENTITY must be a lower-case identity name")
        if not LOGICAL_PATH.fullmatch(self.probe_path) or ".." in self.probe_path or "*" in self.probe_path:
            raise CertificationError("OPENBAO_PROBE_SECRET_PATH must be an exact codestra/staging/... logical path")
        if not self.addr.startswith("https://") or not self.token_url.startswith("https://"):
            raise CertificationError("OPENBAO_ADDR and KEYCLOAK_TOKEN_URL must be https")
        if not self.evidence_path.is_absolute():
            raise CertificationError("OPENBAO_IDENTITY_EVIDENCE must be absolute")
        self.client_secret = read_secret_file(required("OPENBAO_CLIENT_SECRET_FILE", env))
        readonly_file = env.get("MONITORING_READONLY_CLIENT_SECRET_FILE", "").strip()
        self.readonly_secret = read_secret_file(readonly_file) if readonly_file else None
        self.http = http or Http(env.get("OPENBAO_CA_FILE") or None)
        self.connector = connector
        self.sleep = sleep
        self.tls_probe = tls_probe or self._tls_probe
        self.authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
        self.roles = json.loads(JWT_ROLES.read_text(encoding="utf-8"))
        self.staging_issuer = self.authority["issuersByEnvironment"]["staging"]
        self.mount = self.roles["mount"]
        self.role_name = f"{self.identity}-staging"
        self.results: list[dict[str, Any]] = []
        self.secrets: list[str] = [self.client_secret] + ([self.readonly_secret] if self.readonly_secret else [])
        self.jwt: str | None = None
        self.workload_token: str | None = None
        self.prefixes: list[str] = []
        self.other_prefix: str | None = None

    # -- infrastructure --------------------------------------------------------------------

    def _tls_probe(self, host: str) -> dict[str, Any]:
        context = self.http.context
        with socket.create_connection((host, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {"version": tls.version(), "subject_cn": dict(x[0] for x in cert.get("subject", ())).get("commonName"), "not_after": cert.get("notAfter")}

    def bao(self, method: str, path: str, token: str | None = None, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any] | None]:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if token:
            headers["X-Vault-Token"] = token
        data = json.dumps(body).encode("utf-8") if body is not None else None
        return self.http.request(method, f"{self.addr}/v1/{path}", body=data, headers=headers)

    def keycloak_token(self, client_id: str, secret: str, scope: str | None) -> tuple[int, dict[str, Any] | None]:
        form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
        if scope:
            form["scope"] = scope
        return self.http.request("POST", self.token_url, body=urllib.parse.urlencode(form).encode("utf-8"), headers={"Content-Type": "application/x-www-form-urlencoded"})

    def login(self, jwt: str, role: str) -> tuple[int, dict[str, Any] | None]:
        return self.bao("POST", f"auth/{self.mount}/cel/login", body={"role": role, "jwt": jwt})

    def kv_read(self, token: str, logical_path: str) -> int:
        mount, _, rest = logical_path.partition("/")
        status, _ = self.bao("GET", f"{mount}/data/{rest}", token=token)
        return status

    def check(self, name: str, action: Callable[[], dict[str, Any]]) -> bool:
        try:
            details = action()
            self.results.append({"check": name, "status": "pass", "details": details})
            return True
        except CheckFailed as exc:
            self.results.append({"check": name, "status": "fail", "error": str(exc)[:300]})
            return False

    def skip(self, name: str, reason: str) -> None:
        self.results.append({"check": name, "status": "skipped", "reason": reason})

    # -- checks -----------------------------------------------------------------------------

    def authority_role(self) -> dict[str, Any]:
        roles = [r for r in self.authority["roles"] if r["environment"] == "staging" and r["serviceIdentity"] == self.identity]
        if len(roles) != 1:
            raise CheckFailed(f"{self.identity} is not a single reviewed staging role")
        role = roles[0]
        self.prefixes = list(role["pathPrefixes"])
        if not any(self.probe_path.startswith(prefix) for prefix in self.prefixes):
            raise CheckFailed("OPENBAO_PROBE_SECRET_PATH is outside the identity's prefixes")
        if any("*" in prefix or not prefix.startswith("codestra/staging/") for prefix in self.prefixes):
            raise CheckFailed("identity prefixes are not exact staging prefixes")
        others = [r for r in self.authority["roles"] if r["environment"] == "staging" and r["serviceIdentity"] != self.identity]
        self.other_prefix = next((p for r in others for p in r["pathPrefixes"] if not any(p.startswith(own) or own.startswith(p) for own in self.prefixes)), None)
        if self.other_prefix is None:
            raise CheckFailed("no disjoint other-service prefix exists to test cross-service denial")
        generated = next((r for r in self.roles["roles"] if r["name"] == self.role_name), None)
        if generated is None or generated["payload"]["bound_audiences"] != [self.authority["audience"]]:
            raise CheckFailed("generated JWT role is missing or not bound to the openbao audience")
        expression = generated["payload"]["cel_program"]["expression"]
        if f"claims.iss == '{self.staging_issuer}'" not in expression or "claims.codestra_environment == 'staging'" not in expression:
            raise CheckFailed("generated JWT role does not bind the staging issuer and environment")
        return {"role": self.role_name, "mount": self.mount, "prefixes": self.prefixes, "operations": role["operations"], "ttl_seconds": role["tokenTtlSeconds"], "max_ttl_seconds": role["tokenMaximumTtlSeconds"], "other_service_prefix": self.other_prefix, "issuer": self.staging_issuer}

    def private_listeners(self) -> dict[str, Any]:
        tls = self.tls_probe(self.public_host)
        native = {port: tcp_reachable(self.public_host, port, connector=self.connector) for port in (8200, 8201)}
        if any(native.values()):
            raise CheckFailed("native OpenBao listener is reachable on the public name: " + ", ".join(str(p) for p, up in native.items() if up))
        return {"public_host": self.public_host, "tls": tls, "native_8200_reachable": False, "native_8201_reachable": False}

    def health(self) -> dict[str, Any]:
        status, payload = self.bao("GET", "sys/health")
        if status not in {200, 429, 472, 473, 501, 503} or not isinstance(payload, dict):
            raise CheckFailed(f"sys/health answered {status}")
        if payload.get("initialized") is not True:
            raise CheckFailed("OpenBao is not initialized; initialization is a ceremony, not a certification step")
        if payload.get("sealed") is True:
            raise CheckFailed("OpenBao is sealed; unsealing is an operator ceremony and is never performed here")
        return {"http_status": status, "initialized": True, "sealed": False, "standby": payload.get("standby"), "version": payload.get("version"), "cluster_name": payload.get("cluster_name")}

    def admin_mutation_unauthorized(self) -> dict[str, Any]:
        attempts = {
            "PUT sys/seal": self.bao("PUT", "sys/seal")[0],
            "PUT sys/policies/acl/certification-probe": self.bao("PUT", "sys/policies/acl/certification-probe", body={"policy": "path \"codestra/*\" { capabilities = [\"deny\"] }"})[0],
            "GET sys/audit": self.bao("GET", "sys/audit")[0],
            "GET sys/policies/acl": self.bao("GET", "sys/policies/acl?list=true")[0],
        }
        accepted = {name: code for name, code in attempts.items() if 200 <= code < 300}
        if accepted:
            raise CheckFailed(f"unauthenticated administrative operations were accepted: {accepted}")
        return {name: code for name, code in attempts.items()}

    def keycloak_token_check(self) -> dict[str, Any]:
        status, payload = self.keycloak_token(self.identity, self.client_secret, "openbao.workload")
        if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
            raise CheckFailed(f"keycloak refused client_credentials for {self.identity} ({status}: {(payload or {}).get('error', '')})")
        self.jwt = payload["access_token"]
        self.secrets.append(self.jwt)
        claims = jwt_claims(self.jwt)
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        problems = []
        if claims.get("iss") != self.staging_issuer:
            problems.append("iss")
        if "openbao" not in audiences:
            problems.append("aud")
        if claims.get("azp") != self.identity:
            problems.append("azp")
        if claims.get("codestra_environment") != "staging":
            problems.append("codestra_environment")
        if not claims.get("jti"):
            problems.append("jti")
        lifetime = int(claims.get("exp", 0)) - int(claims.get("iat", 0))
        if lifetime <= 0 or lifetime > self.authority["maximumTokenLifetimeSeconds"]:
            problems.append("lifetime")
        if problems:
            raise CheckFailed("token claims violate the contract: " + ", ".join(problems))
        return {"iss": claims["iss"], "aud": audiences, "azp": claims["azp"], "codestra_environment": "staging", "lifetime_seconds": lifetime, "jti": h(str(claims["jti"])), "sub": h(str(claims.get("sub", "")))}

    def login_own_role(self) -> dict[str, Any]:
        status, payload = self.login(self.jwt or "", self.role_name)
        auth = (payload or {}).get("auth") if isinstance(payload, dict) else None
        if status != 200 or not isinstance(auth, dict) or not auth.get("client_token"):
            raise CheckFailed(f"login as {self.role_name} failed ({status})")
        self.workload_token = auth["client_token"]
        self.secrets.append(self.workload_token)
        policies = sorted(auth.get("policies") or auth.get("token_policies") or [])
        if policies != [f"workload-{self.role_name}"]:
            raise CheckFailed(f"login granted unexpected policies: {policies}")
        ttl = int(auth.get("lease_duration", 0))
        if ttl <= 0 or ttl > 300:
            raise CheckFailed(f"token TTL {ttl} exceeds the 300 s contract")
        return {"policies": policies, "lease_duration": ttl, "renewable": auth.get("renewable"), "accessor": h(str(auth.get("accessor", ""))), "token": h(self.workload_token)}

    def own_path_read(self) -> dict[str, Any]:
        status = self.kv_read(self.workload_token or "", self.probe_path)
        if status not in {200, 404}:
            raise CheckFailed(f"own-prefix read returned {status}")
        return {"path": self.probe_path, "http_status": status, "authorized": True, "value_recorded": False}

    def cross_environment_denied(self) -> dict[str, Any]:
        production = self.probe_path.replace("codestra/staging/", "codestra/production/", 1)
        status = self.kv_read(self.workload_token or "", production)
        if status != 403:
            raise CheckFailed(f"production path returned {status}, expected 403")
        return {"path": production, "http_status": 403}

    def cross_service_denied(self) -> dict[str, Any]:
        path = (self.other_prefix or "") + "probe"
        status = self.kv_read(self.workload_token or "", path)
        if status != 403:
            raise CheckFailed(f"other-service path returned {status}, expected 403")
        return {"path": path, "http_status": 403}

    def admin_with_workload_token(self) -> dict[str, Any]:
        attempts = {
            "GET sys/policies/acl": self.bao("GET", "sys/policies/acl?list=true", token=self.workload_token)[0],
            "GET sys/audit": self.bao("GET", "sys/audit", token=self.workload_token)[0],
            "PUT sys/seal": self.bao("PUT", "sys/seal", token=self.workload_token)[0],
            "GET sys/health": self.bao("GET", "sys/health", token=self.workload_token)[0],
        }
        offending = {name: code for name, code in attempts.items() if name != "GET sys/health" and 200 <= code < 300}
        if offending:
            raise CheckFailed(f"workload token performed administrative operations: {offending}")
        return attempts

    def wrong_audience_rejected(self) -> dict[str, Any]:
        status, payload = self.keycloak_token(self.identity, self.client_secret, None)
        if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
            raise CheckFailed(f"keycloak refused a plain token ({status}); cannot prove audience enforcement")
        plain = payload["access_token"]
        self.secrets.append(plain)
        aud = jwt_claims(plain).get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if "openbao" in audiences:
            raise CheckFailed("a token requested without scope=openbao.workload still carries the openbao audience")
        code, _ = self.login(plain, self.role_name)
        if code < 400:
            raise CheckFailed(f"login accepted a token without the openbao audience ({code})")
        return {"login_status": code, "audiences": audiences}

    def wrong_role_rejected(self) -> dict[str, Any]:
        other = next(r["name"] for r in self.roles["roles"] if r["name"].endswith("-staging") and r["name"] != self.role_name)
        code, _ = self.login(self.jwt or "", other)
        if code < 400:
            raise CheckFailed(f"login as {other} accepted a {self.identity} token ({code})")
        return {"role": other, "login_status": code}

    def tampered_signature_rejected(self) -> dict[str, Any]:
        code, _ = self.login(flip_signature(self.jwt or ""), self.role_name)
        if code < 400:
            raise CheckFailed(f"login accepted a token with a modified signature ({code})")
        return {"login_status": code}

    def tampered_issuer_rejected(self) -> dict[str, Any]:
        code, _ = self.login(rewrite_claims(self.jwt or "", iss=PRODUCTION_ISSUER), self.role_name)
        if code < 400:
            raise CheckFailed(f"login accepted a token rewritten to the production issuer ({code})")
        return {"login_status": code, "issuer_presented": PRODUCTION_ISSUER, "note": "a genuine production-issuer token cannot be minted from staging; the staging mount binds the staging issuer (offline-validated) and this rewritten token proves the signature/issuer path fails closed"}

    def token_revocation(self) -> dict[str, Any]:
        code, _ = self.bao("POST", "auth/token/revoke-self", token=self.workload_token)
        if code not in {200, 204}:
            raise CheckFailed(f"revoke-self returned {code}")
        after = self.kv_read(self.workload_token or "", self.probe_path)
        if after != 403:
            raise CheckFailed(f"revoked token still reads ({after})")
        return {"revoke_status": code, "read_after_revocation": 403}

    def expired_jwt_rejected(self) -> dict[str, Any]:
        claims = jwt_claims(self.jwt or "")
        leeway = int(self.authority.get("clockSkewLeewaySeconds", 30))
        wait = int(claims["exp"]) + leeway + 5 - int(time.time())
        if wait > 400:
            raise CheckFailed("token lifetime exceeds the waiting budget")
        if wait > 0:
            self.sleep(wait)
        code, _ = self.login(self.jwt or "", self.role_name)
        if code < 400:
            raise CheckFailed(f"login accepted an expired token ({code})")
        return {"waited_seconds": max(wait, 0), "login_status": code}

    def monitoring_readonly_never_bound(self) -> dict[str, Any]:
        status, payload = self.keycloak_token("monitoring-readonly", self.readonly_secret or "", "openbao.workload")
        outcome: dict[str, Any] = {"token_status": status}
        if status == 200 and isinstance(payload, dict) and payload.get("access_token"):
            token = payload["access_token"]
            self.secrets.append(token)
            aud = jwt_claims(token).get("aud")
            audiences = aud if isinstance(aud, list) else [aud]
            if "openbao" in audiences:
                raise CheckFailed("monitoring-readonly received the openbao audience")
            code, _ = self.login(token, "monitoring-readonly-staging")
            if code < 400:
                raise CheckFailed(f"OpenBao admitted monitoring-readonly ({code})")
            outcome.update({"audiences": audiences, "login_status": code})
        elif status not in {400, 401, 403}:
            raise CheckFailed(f"unexpected keycloak response for monitoring-readonly ({status})")
        else:
            outcome["keycloak_refused_scope"] = True
        if any(r["name"] == "monitoring-readonly-staging" for r in self.roles["roles"]):
            raise CheckFailed("a monitoring-readonly OpenBao role exists in the generated roles")
        return outcome

    # -- orchestration --------------------------------------------------------------------

    def run(self) -> dict[str, Any]:
        ready = self.check("authority-role", self.authority_role)
        self.check("private-listeners", self.private_listeners)
        healthy = self.check("health-unauthenticated", self.health)
        self.check("admin-mutation-unauthorized", self.admin_mutation_unauthorized)
        if ready and healthy and self.check("keycloak-token", self.keycloak_token_check) and self.check("login-own-role", self.login_own_role):
            self.check("own-path-read", self.own_path_read)
            self.check("cross-environment-denied", self.cross_environment_denied)
            self.check("cross-service-denied", self.cross_service_denied)
            self.check("admin-with-workload-token", self.admin_with_workload_token)
            self.check("wrong-audience-rejected", self.wrong_audience_rejected)
            self.check("wrong-role-rejected", self.wrong_role_rejected)
            self.check("tampered-signature-rejected", self.tampered_signature_rejected)
            self.check("tampered-issuer-rejected", self.tampered_issuer_rejected)
            self.check("token-revocation", self.token_revocation)
            if self.wait_for_expiry:
                self.check("expired-jwt-rejected", self.expired_jwt_rejected)
            else:
                self.skip("expired-jwt-rejected", "OPENBAO_IDENTITY_WAIT_FOR_EXPIRY not set; lifetime bound proven from claims")
            if self.readonly_secret:
                self.check("monitoring-readonly-never-bound", self.monitoring_readonly_never_bound)
            else:
                self.skip("monitoring-readonly-never-bound", "MONITORING_READONLY_CLIENT_SECRET_FILE not supplied; absence of the role proven offline")
        else:
            done = {r["check"] for r in self.results}
            for name in REQUIRED_CHECKS + OPTIONAL_CHECKS:
                if name not in done:
                    self.skip(name, "prerequisite check failed")
        executed = {r["check"]: r["status"] for r in self.results}
        failed = sorted(name for name, status in executed.items() if status == "fail")
        skipped_required = sorted(name for name in REQUIRED_CHECKS if executed.get(name) == "skipped")
        verdict = "YES" if not failed and not skipped_required else "NO"
        return {
            "schema_version": 1,
            "certification": "OPENBAO_IDENTITY_STAGING",
            "environment": "staging",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "openbao": self.addr,
            "keycloak_token_endpoint": self.token_url,
            "identity": self.identity,
            "role": self.role_name,
            "checks": self.results,
            "failed": failed,
            "skipped_required": skipped_required,
            "verdict": {"STAGING_OPENBAO_IDENTITY_GO": verdict},
            "production_touched": False,
            "unseal_performed": False,
            "secret_values_recorded": False,
        }

    def write(self, report: dict[str, Any]) -> Path:
        serialized = json.dumps(report, indent=2, sort_keys=True)
        for secret in self.secrets:
            if secret and secret in serialized:
                raise CertificationError("evidence would contain a live credential; refusing to write it")
        if SECRET_SHAPED.search(serialized):
            raise CertificationError("evidence would contain secret-shaped material; refusing to write it")
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_path.write_text(serialized + "\n", encoding="utf-8")
        return self.evidence_path


def main(env: dict[str, str] | None = None, **injected: Any) -> int:
    try:
        certifier = Certifier(dict(os.environ if env is None else env), **injected)
    except CertificationError as exc:
        print(f"OPENBAO_IDENTITY_CERTIFICATION=FAIL reason={exc}", file=sys.stderr)
        return 3
    report = certifier.run()
    try:
        path = certifier.write(report)
    except CertificationError as exc:
        print(f"OPENBAO_IDENTITY_CERTIFICATION=FAIL reason={exc}", file=sys.stderr)
        return 3
    verdict = report["verdict"]["STAGING_OPENBAO_IDENTITY_GO"]
    print(f"STAGING_OPENBAO_IDENTITY_GO={verdict} identity={report['identity']} failed={report['failed']} skipped_required={report['skipped_required']} evidence={path.name}")
    return 0 if verdict == "YES" else 2


if __name__ == "__main__":
    sys.exit(main())
