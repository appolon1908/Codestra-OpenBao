#!/usr/bin/env python3
"""Fail-closed validation of the Middleware V3 secret-reference binding contract.

``contracts/middleware-v3-secret-reference-binding.v1.json`` records how the
Middleware V3 command kernel will consume OpenBao: references only, exact
Keycloak-JWT identities, approved paths, fail-closed resolution. This validator
proves from source that the contract is dark (PREPARED_DISABLED, nothing
authorized), that its schema pin equals the canonical digest of the authority
schema, that every declared Middleware identity is backed by a reviewed role in
``config/workload-secret-authority.v1.json`` and a generated CEL role in
``openbao/auth/jwt-roles.v1.json`` with exactly the declared issuer, client,
environment, audience and lifetime, and that the reference model pin recorded
for the Middleware prep base is the same digest. It is stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "middleware-v3-secret-reference-binding.v1.json"
SCHEMA = ROOT / "contracts" / "secret-reference.v1.schema.json"
AUTHORITY = ROOT / "config" / "workload-secret-authority.v1.json"
JWT_CONFIG = ROOT / "config" / "auth" / "keycloak-jwt.v1.json"
JWT_ROLES = ROOT / "openbao" / "auth" / "jwt-roles.v1.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SECRET_SHAPED = re.compile(
    r"(hvs\.[A-Za-z0-9_-]{20,}|hvb\.[A-Za-z0-9_-]{20,}|\bs\.[A-Za-z0-9]{24,}\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)
FORBIDDEN_SINKS = {"command payload", "outbox", "ledger", "audit", "logs", "metrics", "traces"}
NEGATIVE_CASES = {
    "wrong_issuer", "wrong_audience", "wrong_client", "wrong_role", "expired_token",
    "tampered_token", "foreign_service", "staging_to_production", "unapproved_path",
}


def fail(message: str) -> None:
    print(f"MIDDLEWARE_V3_SECRET_BINDING_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def canonical_digest(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def walk_strings(value: Any, trail: str = "contract"):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk_strings(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{trail}[{index}]")
    elif isinstance(value, str):
        yield trail, value


def validate(contract: dict[str, Any], schema: dict[str, Any], authority: dict[str, Any],
             jwt_config: dict[str, Any], jwt_roles: dict[str, Any]) -> None:
    if contract.get("schema_version") != "1.0":
        fail("schema_version must be 1.0")
    if contract.get("contract_id") != "middleware-v3-secret-reference-binding":
        fail("contract_id drift")
    if contract.get("status") != "PREPARED_DISABLED":
        fail("the V3 binding must stay PREPARED_DISABLED until V3_FINAL_SHA exists and the owner activates it")
    for flag in (
        "activation_enabled", "runtimeApplyAuthorized", "provider_effects_enabled",
        "production_initialize_or_unseal_authorized", "production_rotation_authorized",
    ):
        if contract.get(flag) is not False:
            fail(f"{flag} must be false")

    middleware = contract.get("middleware")
    if not isinstance(middleware, dict):
        fail("middleware block is required")
    base = middleware.get("prep_base_sha")
    if not isinstance(base, str) or not SHA40.fullmatch(base):
        fail("middleware.prep_base_sha must be a 40-hex commit")
    final = middleware.get("v3_final_sha")
    if final != "PENDING" and not (isinstance(final, str) and SHA40.fullmatch(final)):
        fail("middleware.v3_final_sha must be PENDING or a 40-hex commit")
    if final == "PENDING" and middleware.get("repin_required_after_v3_merge") is not True:
        fail("a PENDING V3 pin must require re-pinning")

    pin = canonical_digest(schema)
    if middleware.get("vendored_schema_canonical_sha256_at_prep_base") != pin:
        fail("the Middleware vendored schema pin recorded for the prep base does not equal the authority schema digest")
    reference = contract.get("secret_reference_contract")
    if not isinstance(reference, dict):
        fail("secret_reference_contract is required")
    if reference.get("authority_schema_canonical_sha256") != pin:
        fail("secret_reference_contract.authority_schema_canonical_sha256 does not equal the authority schema digest")
    if reference.get("provider") != "openbao":
        fail("the only provider is openbao")
    if set(reference.get("forbidden_keys", [])) != set(schema.get("x-codestra-forbidden-keys", [])):
        fail("forbidden_keys must mirror the schema's x-codestra-forbidden-keys")
    if list(reference.get("secret_classes", [])) != list(schema["properties"]["secret_class"]["enum"]):
        fail("secret_classes must mirror the schema enum")
    sinks = set(reference.get("resolved_values_must_never_enter", []))
    if not FORBIDDEN_SINKS <= sinks:
        fail(f"resolved values must be forbidden from every sink: missing {sorted(FORBIDDEN_SINKS - sinks)}")
    fail_closed = reference.get("fail_closed_resolution", {})
    for flag in ("missing_secret_fails_startup", "never_fallback_to_environment_variables",
                 "never_fallback_to_git_materialization"):
        if fail_closed.get(flag) is not True:
            fail(f"fail_closed_resolution.{flag} must be true")

    target = contract.get("workload_authentication_target")
    if not isinstance(target, dict):
        fail("workload_authentication_target is required")
    if target.get("audience_exact") != jwt_config.get("boundAudience") or target.get("audience_exact") != authority.get("audience"):
        fail("audience_exact drifted from config/auth/keycloak-jwt.v1.json / the workload authority")
    if target.get("issuer_exact_by_environment") != jwt_config.get("issuersByEnvironment"):
        fail("issuer_exact_by_environment drifted from config/auth/keycloak-jwt.v1.json")
    if list(target.get("required_claims", [])) != list(jwt_config.get("requiredClaims", [])):
        fail("required_claims drifted from config/auth/keycloak-jwt.v1.json")
    if target.get("maximum_jwt_lifetime_seconds") != jwt_config.get("maximumJwtLifetimeSeconds") != 300:
        fail("maximum_jwt_lifetime_seconds must equal the JWT mount policy (300)")
    for flag, expected in (("jti_replay_denied", True), ("foreign_issuer_accepted", False),
                           ("wildcard_client_matching_allowed", False)):
        if target.get(flag) is not expected:
            fail(f"workload_authentication_target.{flag} must be {expected}")
    if jwt_config.get("foreignIssuerAccepted") is not False or jwt_config.get("wildcardClientMatchingAllowed") is not False:
        fail("the JWT mount must reject foreign issuers and wildcard clients")

    roles = {(r["environment"], r["serviceIdentity"]): r for r in authority.get("roles", [])}
    cel_roles = {r["name"]: r for r in jwt_roles.get("roles", [])}
    identities = target.get("middleware_v3_identities")
    if not isinstance(identities, list) or {i.get("client_exact") for i in identities} != {"middleware-api", "middleware-worker"}:
        fail("exactly the middleware-api and middleware-worker identities must be declared")
    for identity in identities:
        client = identity["client_exact"]
        if identity.get("operations") != ["read"]:
            fail(f"{client}: Middleware only reads secrets")
        envs = identity.get("role_exact_by_environment", {})
        if set(envs) != {"staging", "production"}:
            fail(f"{client}: staging and production roles must both be declared")
        for env, role_name in envs.items():
            role = roles.get((env, client))
            if role is None:
                fail(f"{client}/{env}: no reviewed role in the workload authority")
            if role.get("boundClaims") != {"azp": client, "codestra_environment": env}:
                fail(f"{client}/{env}: bound claims must be exactly azp + codestra_environment")
            if role.get("operations") != ["read"]:
                fail(f"{client}/{env}: the reviewed role must be read-only")
            if role.get("runtimeBindingAuthorized") is not False or role.get("providerBusinessEffectsEnabled") is not False:
                fail(f"{client}/{env}: runtime binding and provider effects must stay disabled in the prep phase")
            if role.get("tokenTtlSeconds") != 300 or role.get("tokenMaximumTtlSeconds") != 300:
                fail(f"{client}/{env}: token TTL must be exactly 300 seconds")
            declared_paths = identity["approved_path_prefixes_by_environment"].get(env)
            if declared_paths != role.get("pathPrefixes"):
                fail(f"{client}/{env}: approved path prefixes drifted from the workload authority")
            for prefix in declared_paths:
                if not prefix.startswith(f"codestra/{env}/middleware/") or not prefix.endswith("/") or "*" in prefix:
                    fail(f"{client}/{env}: {prefix} is not an exact own-environment middleware prefix")
            if role_name != f"{client}-{env}":
                fail(f"{client}/{env}: role name must be <client>-<environment>")
            cel = cel_roles.get(role_name)
            if cel is None:
                fail(f"{role_name}: no generated CEL role")
            expression = cel["payload"]["cel_program"]["expression"]
            issuer = jwt_config["issuersByEnvironment"][env]
            for literal in (
                f"claims.iss == '{issuer}'",
                f"claims.azp == '{client}'",
                f"claims.codestra_environment == '{env}'",
                "'openbao' in claims.aud",
                "int(claims.exp) - int(claims.iat) <= 300",
                f"policies: ['{identity['policy_exact_by_environment'][env]}']",
            ):
                if literal not in expression:
                    fail(f"{role_name}: generated CEL role lacks {literal}")
            if cel["payload"].get("bound_audiences") != ["openbao"]:
                fail(f"{role_name}: bound_audiences must be exactly ['openbao']")
            if cel.get("runtimeApplyAuthorized") is not False:
                fail(f"{role_name}: runtimeApplyAuthorized must be false")

    negative = contract.get("negative_tests", {}).get("cases", {})
    for case in NEGATIVE_CASES:
        if negative.get(case) != "DENY":
            fail(f"negative test {case} must be recorded as DENY")
    if negative.get("own_identity_own_environment_approved_path") != "ALLOW":
        fail("the positive control must be recorded as ALLOW")

    for section, flag in (("kv_v2_access", "cas_required"), ("audit_logging", "hmac_accessor"),
                          ("audit_logging", "fail_closed"), ("rotation", "revocation_test_required")):
        if contract.get(section, {}).get(flag) is not True:
            fail(f"{section}.{flag} must be true")
    if contract.get("kv_v2_access", {}).get("list_or_write_from_middleware") is not False:
        fail("Middleware never lists or writes KV paths")
    if contract.get("audit_logging", {}).get("log_raw") is not False or contract.get("audit_logging", {}).get("secret_values_allowed") is not False:
        fail("audit logging must never carry raw or secret values")
    if contract.get("rotation", {}).get("production_rotation_authorized") is not False:
        fail("production rotation is not authorized in Lane E")

    for trail, value in walk_strings(contract):
        if SECRET_SHAPED.search(value):
            fail(f"{trail}: secret-shaped value in a contract that may only carry references")


def main() -> None:
    validate(load(CONTRACT), load(SCHEMA), load(AUTHORITY), load(JWT_CONFIG), load(JWT_ROLES))
    print("MIDDLEWARE_V3_SECRET_BINDING=PASS")


if __name__ == "__main__":
    main()
