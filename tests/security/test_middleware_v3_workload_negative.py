"""Middleware V3 workload negative matrix: every wrong token, role, service or path is denied.

The matrix is evaluated statically against the reviewed binding — the workload
authority, the JWT mount policy and the generated CEL roles — with a reference
decision function that mirrors what the auth mount enforces: exact issuer per
environment, exact audience, exact client (azp), exact environment claim, every
required claim present, lifetime <= 300 s and not expired, a valid signature, an
unseen jti, and a path beneath an approved prefix with an allowed operation. No
OpenBao runtime is touched; production is never exercised.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "middleware_v3_secret_binding", ROOT / "scripts" / "validate_middleware_v3_secret_binding.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

NOW = 1_790_000_000
AUDIENCE = "openbao"


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class Decision:
    """Reference evaluation of one login + one KV read against the declared binding."""

    def __init__(self) -> None:
        self.authority = load("config/workload-secret-authority.v1.json")
        self.jwt = load("config/auth/keycloak-jwt.v1.json")
        self.roles = {(r["environment"], r["serviceIdentity"]): r for r in self.authority["roles"]}
        self.seen_jti: set[str] = set()

    def login(self, claims: dict, *, role: str, signature_valid: bool = True, now: int = NOW) -> str | None:
        """Return the policy name granted by the role, or None when the login is denied."""
        if not signature_valid:
            return None
        if any(claim not in claims for claim in self.jwt["requiredClaims"]):
            return None
        client, _, env = role.rpartition("-")
        reviewed = self.roles.get((env, client))
        if reviewed is None:
            return None  # the role does not exist on the mount
        if claims["iss"] != self.jwt["issuersByEnvironment"][env]:
            return None
        aud = claims["aud"]
        if not (aud == AUDIENCE or (isinstance(aud, list) and AUDIENCE in aud)):
            return None
        if claims["azp"] != reviewed["boundClaims"]["azp"]:
            return None
        if claims["codestra_environment"] != reviewed["boundClaims"]["codestra_environment"]:
            return None
        if not (claims["exp"] > claims["iat"] and claims["exp"] - claims["iat"] <= self.jwt["maximumJwtLifetimeSeconds"]):
            return None
        if claims["exp"] + self.jwt["clockSkewLeewaySeconds"] < now:
            return None
        if claims["jti"] in self.seen_jti:
            return None
        self.seen_jti.add(claims["jti"])
        return f"workload-{client}-{env}"

    def read(self, policy: str | None, path: str, operation: str = "read") -> bool:
        if policy is None:
            return False
        client_env = policy.removeprefix("workload-")
        client, _, env = client_env.rpartition("-")
        reviewed = self.roles[(env, client)]
        if operation not in reviewed["operations"]:
            return False
        return any(path.startswith(prefix) for prefix in reviewed["pathPrefixes"])


def token(client: str, env: str, *, issuer: str | None = None, aud=AUDIENCE, jti: str = "jti-1",
          iat: int = NOW - 10, exp: int = NOW + 290, **overrides) -> dict:
    jwt = load("config/auth/keycloak-jwt.v1.json")
    claims = {
        "iss": issuer or jwt["issuersByEnvironment"][env],
        "sub": f"service-account-{client}",
        "aud": aud,
        "azp": client,
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "codestra_environment": env,
    }
    claims.update(overrides)
    return claims


class MiddlewareV3WorkloadNegativeTests(unittest.TestCase):
    PROD_PATH = "codestra/production/middleware/api/database"
    STAGING_PATH = "codestra/staging/middleware/api/database"

    def setUp(self) -> None:
        self.decision = Decision()

    def allow(self, claims: dict, role: str, path: str, **kwargs) -> bool:
        return self.decision.read(self.decision.login(claims, role=role, **kwargs), path)

    def test_positive_control_own_identity_own_environment_approved_path(self) -> None:
        self.assertTrue(self.allow(token("middleware-api", "production"), "middleware-api-production", self.PROD_PATH))
        self.assertTrue(self.allow(token("middleware-api", "staging", jti="jti-2"), "middleware-api-staging", self.STAGING_PATH))
        worker = token("middleware-worker", "production", jti="jti-3")
        self.assertTrue(self.allow(worker, "middleware-worker-production", "codestra/production/middleware/worker/email/klyrow"))

    def test_wrong_issuer_deny(self) -> None:
        claims = token("middleware-api", "production", issuer="https://auth-staging.codestra.co/realms/codestra")
        self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH))
        foreign = token("middleware-api", "production", issuer="https://accounts.example.com/")
        self.assertFalse(self.allow(foreign, "middleware-api-production", self.PROD_PATH))

    def test_wrong_audience_deny(self) -> None:
        for aud in ("middleware-api", ["middleware-api"], "vault", ""):
            claims = token("middleware-api", "production", aud=aud)
            self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH), aud)

    def test_wrong_client_deny(self) -> None:
        claims = token("middleware-worker", "production")
        self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH))
        spoofed = token("middleware-api", "production", azp="kong-gateway")
        self.assertFalse(self.allow(spoofed, "middleware-api-production", self.PROD_PATH))

    def test_wrong_role_deny(self) -> None:
        claims = token("middleware-api", "production")
        self.assertFalse(self.allow(claims, "middleware-worker-production", self.PROD_PATH))
        self.assertFalse(self.allow(claims, "middleware-api-staging", self.PROD_PATH))
        self.assertFalse(self.allow(claims, "middleware-admin-production", self.PROD_PATH))

    def test_expired_token_deny(self) -> None:
        expired = token("middleware-api", "production", iat=NOW - 400, exp=NOW - 100)
        self.assertFalse(self.allow(expired, "middleware-api-production", self.PROD_PATH))
        too_long = token("middleware-api", "production", iat=NOW - 10, exp=NOW + 3_590)
        self.assertFalse(self.allow(too_long, "middleware-api-production", self.PROD_PATH))
        inverted = token("middleware-api", "production", iat=NOW + 100, exp=NOW)
        self.assertFalse(self.allow(inverted, "middleware-api-production", self.PROD_PATH))

    def test_tampered_token_deny(self) -> None:
        claims = token("middleware-api", "production")
        self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH, signature_valid=False))

    def test_missing_required_claim_deny(self) -> None:
        for claim in ("jti", "codestra_environment", "azp", "sub"):
            claims = token("middleware-api", "production")
            del claims[claim]
            self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH), claim)

    def test_foreign_service_deny(self) -> None:
        for foreign in ("n8n-automation", "odoo-integration", "grafana-runtime", "superset-analytics", "unknown-service"):
            claims = token(foreign, "production")
            self.assertFalse(self.allow(claims, "middleware-api-production", self.PROD_PATH), foreign)
            self.assertFalse(self.allow(claims, f"{foreign}-production", self.PROD_PATH), foreign)

    def test_staging_to_production_deny(self) -> None:
        staging = token("middleware-api", "staging")
        self.assertFalse(self.allow(staging, "middleware-api-production", self.PROD_PATH))
        # A valid staging login can never read a production path either.
        policy = self.decision.login(token("middleware-api", "staging", jti="jti-s"), role="middleware-api-staging")
        self.assertEqual(policy, "workload-middleware-api-staging")
        self.assertFalse(self.decision.read(policy, self.PROD_PATH))
        mixed = token("middleware-api", "production", codestra_environment="staging")
        self.assertFalse(self.allow(mixed, "middleware-api-production", self.PROD_PATH))

    def test_unapproved_path_deny(self) -> None:
        policy = self.decision.login(token("middleware-api", "production"), role="middleware-api-production")
        for path in (
            "codestra/production/middleware/worker/email/klyrow",  # worker family
            "codestra/production/kong/runtime",  # another service
            "codestra/production/middleware/apix/database",  # prefix confusion
            "codestra/production/middleware/api",  # bare prefix without trailing segment
            "codestra/staging/middleware/api/database",
            "sys/policies/acl/root",
        ):
            self.assertFalse(self.decision.read(policy, path), path)
        self.assertFalse(self.decision.read(policy, self.PROD_PATH, operation="write"))
        self.assertFalse(self.decision.read(policy, self.PROD_PATH, operation="list"))

    def test_replayed_jti_deny(self) -> None:
        claims = token("middleware-api", "production", jti="jti-replay")
        self.assertIsNotNone(self.decision.login(claims, role="middleware-api-production"))
        self.assertIsNone(self.decision.login(claims, role="middleware-api-production"))

    def test_generated_cel_roles_carry_the_exact_literals(self) -> None:
        jwt_roles = {r["name"]: r for r in load("openbao/auth/jwt-roles.v1.json")["roles"]}
        issuers = load("config/auth/keycloak-jwt.v1.json")["issuersByEnvironment"]
        for client in ("middleware-api", "middleware-worker"):
            for env in ("staging", "production"):
                expression = jwt_roles[f"{client}-{env}"]["payload"]["cel_program"]["expression"]
                self.assertIn(f"claims.iss == '{issuers[env]}'", expression)
                self.assertIn(f"claims.azp == '{client}'", expression)
                self.assertIn(f"claims.codestra_environment == '{env}'", expression)
                self.assertIn("int(claims.exp) - int(claims.iat) <= 300", expression)
                self.assertIn("'jti' in claims", expression)
                self.assertNotIn("*", expression)

    def test_contract_validator_passes_and_rejects_activation(self) -> None:
        contract = load("contracts/middleware-v3-secret-reference-binding.v1.json")
        schema = load("contracts/secret-reference.v1.schema.json")
        authority = load("config/workload-secret-authority.v1.json")
        jwt_config = load("config/auth/keycloak-jwt.v1.json")
        jwt_roles = load("openbao/auth/jwt-roles.v1.json")
        VALIDATOR.validate(contract, schema, authority, jwt_config, jwt_roles)
        for flag in ("activation_enabled", "runtimeApplyAuthorized", "production_rotation_authorized"):
            mutated = json.loads(json.dumps(contract))
            mutated[flag] = True
            with self.assertRaises(SystemExit):
                VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)
        mutated = json.loads(json.dumps(contract))
        mutated["status"] = "ACTIVE"
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)
        mutated = json.loads(json.dumps(contract))
        mutated["secret_reference_contract"]["authority_schema_canonical_sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)
        mutated = json.loads(json.dumps(contract))
        mutated["workload_authentication_target"]["middleware_v3_identities"][0]["approved_path_prefixes_by_environment"]["production"] = ["codestra/production/"]
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)
        mutated = json.loads(json.dumps(contract))
        mutated["secret_reference_contract"]["resolved_values_must_never_enter"].remove("outbox")
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)
        mutated = json.loads(json.dumps(contract))
        mutated["notes"] = "hvs." + "A" * 32  # assembled so the repository secret scan never sees a token shape
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(mutated, schema, authority, jwt_config, jwt_roles)


if __name__ == "__main__":
    unittest.main()
