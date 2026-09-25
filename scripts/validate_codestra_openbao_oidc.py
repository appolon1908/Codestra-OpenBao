#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao human OIDC plan."""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "codestra" / "runtime-v1" / "oidc-plan.v1.json"
RUNTIME_PATH = ROOT / "codestra" / "runtime-v1" / "runtime.v1.json"
DESIRED_STATE_PATH = ROOT / "codestra" / "runtime-v1" / "desired-state.json"
DOC_PATH = ROOT / "codestra" / "docs" / "OIDC-PRIVATE-EDGE.md"

ISSUER = "https://auth.codestra.co/realms/codestra"
CLIENT_ID = "openbao-secrets"
SECRET_FILE = "/run/secrets/openbao_oidc_client_secret"
REDIRECTS = [
    "https://bao.codestra.media/v1/auth/oidc/callback",
    "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback",
]
REQUIRED_NEGATIVE_TESTS = {
    "wrong_issuer_denied",
    "wrong_audience_denied",
    "unregistered_callback_denied",
    "missing_keycloak_role_denied",
    "missing_mfa_denied",
    "missing_business_claim_denied",
    "missing_environment_claim_denied",
    "cross_business_policy_denied",
    "observability_role_denied",
    "native_api_public_access_denied",
    "revoked_session_cannot_continue_indefinitely",
}


def fail(message: str) -> None:
    print(f"OPENBAO_OIDC_VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def assert_all_false(value: Any, label: str) -> None:
    if not isinstance(value, dict) or not value:
        fail(f"{label} must be a non-empty object")
    enabled = sorted(key for key, state in value.items() if state is not False)
    if enabled:
        fail(f"{label} must remain false: {enabled}")


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("schemaVersion") != "1.0":
        fail("OIDC schemaVersion must be 1.0")
    if plan.get("status") != "CONTROL_PLANE_PREPARED_NOT_APPLIED":
        fail("OIDC status must remain CONTROL_PLANE_PREPARED_NOT_APPLIED")
    if plan.get("applyMode") != "plan-only":
        fail("OIDC applyMode must remain plan-only")

    auth_mount = plan.get("authMount", {})
    if auth_mount.get("path") != "oidc" or auth_mount.get("type") != "oidc":
        fail("OIDC auth mount contract mismatch")

    client = plan.get("client", {})
    expected_client = {
        "issuer": ISSUER,
        "clientId": CLIENT_ID,
        "clientType": "confidential",
        "clientSecretFile": SECRET_FILE,
        "pkceCodeChallengeMethod": "S256",
        "defaultRole": "",
        "redirectUris": REDIRECTS,
    }
    for key, expected in expected_client.items():
        if client.get(key) != expected:
            fail(f"OIDC client mismatch for {key}")

    claims = plan.get("claims", {})
    if claims != {
        "userClaim": "sub",
        "groupsClaim": "/realm_access/roles",
        "businessClaim": "codestra_business",
        "environmentClaim": "environment",
        "privilegedMfaRequired": True,
    }:
        fail("OIDC claim contract mismatch")

    roles = plan.get("roles")
    expected_roles = {
        "codestra-secrets-operator": {
            "keycloakRealmRole": "secrets-operator",
            "policyNamePattern": "codestra-secrets-operator-__BUSINESS__-__ENVIRONMENT__",
            "tokenTtl": "15m",
            "tokenMaxTtl": "30m",
        },
        "codestra-secrets-admin": {
            "keycloakRealmRole": "secrets-admin",
            "policyNamePattern": "codestra-secrets-admin-__BUSINESS__-__ENVIRONMENT__",
            "tokenTtl": "10m",
            "tokenMaxTtl": "15m",
        },
    }
    if not isinstance(roles, list) or len(roles) != len(expected_roles):
        fail("exactly two privileged human OIDC roles are required")
    by_name = {role.get("name"): role for role in roles if isinstance(role, dict)}
    if set(by_name) != set(expected_roles):
        fail("OIDC operator/admin role names mismatch")
    for name, expected in expected_roles.items():
        role = by_name[name]
        for key, value in expected.items():
            if role.get(key) != value:
                fail(f"{name}: mismatch for {key}")
        if role.get("boundAudiences") != [CLIENT_ID]:
            fail(f"{name}: audience must be {CLIENT_ID}")
        if role.get("allowedRedirectUris") != REDIRECTS:
            fail(f"{name}: callback set mismatch")
        for required_true in (
            "businessClaimRequired",
            "environmentClaimRequired",
            "mfaRequired",
        ):
            if role.get(required_true) is not True:
                fail(f"{name}: {required_true} must be true")
        pattern = str(role.get("policyNamePattern", ""))
        if "__BUSINESS__" not in pattern or "__ENVIRONMENT__" not in pattern:
            fail(f"{name}: policy must be business/environment scoped")

    policy = plan.get("policyPrerequisites", {})
    for required_true in (
        "exactBusinessAndEnvironmentPathsRequired",
        "policyGenerationAndReviewRequiredBeforeApply",
    ):
        if policy.get(required_true) is not True:
            fail(f"policy prerequisite must be true: {required_true}")
    for required_false in (
        "rootPolicyAllowed",
        "defaultBroadPolicyAllowed",
        "crossBusinessWildcardAllowed",
        "oidcAuthenticationReplacesOpenBaoPolicies",
    ):
        if policy.get(required_false) is not False:
            fail(f"policy prerequisite must be false: {required_false}")

    network = plan.get("networkBoundary", {})
    if network != {
        "nativeApiInternetExposureAllowed": False,
        "nativeHostPortPublished": False,
        "tlsMinimumVersion": "TLS13",
        "clientCertificateRequired": True,
        "edgeSourceAllowlistRequired": True,
    }:
        fail("OIDC private network boundary mismatch")

    negative_tests = plan.get("negativeTests")
    if not isinstance(negative_tests, list) or set(negative_tests) != REQUIRED_NEGATIVE_TESTS:
        fail("OIDC negative-test catalogue mismatch")
    if len(negative_tests) != len(set(negative_tests)):
        fail("duplicate OIDC negative tests")

    assert_all_false(plan.get("activation"), "OIDC activation")


def validate_integration() -> None:
    runtime = load_json(RUNTIME_PATH)
    if runtime.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("OpenBao runtime must remain CONFIG_PREPARED_NOT_DEPLOYED")
    activation = runtime.get("activation")
    assert_all_false(activation, "OpenBao runtime activation")

    desired = load_json(DESIRED_STATE_PATH)
    auth_methods = desired.get("authMethods", [])
    oidc_methods = [item for item in auth_methods if isinstance(item, dict) and item.get("type") == "oidc"]
    if len(oidc_methods) != 1:
        fail("desired state must define exactly one human OIDC method")
    oidc = oidc_methods[0]
    if oidc.get("tokenTtl") != "15m" or oidc.get("tokenMaxTtl") != "1h":
        fail("desired-state OIDC upper token bounds changed unexpectedly")
    if "PKCE" not in str(oidc.get("use", "")) or "MFA" not in str(oidc.get("use", "")):
        fail("desired-state OIDC method must require PKCE and MFA")

    try:
        doc = DOC_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {DOC_PATH.relative_to(ROOT)}: {exc}")
    for required in (
        ISSUER,
        CLIENT_ID,
        SECRET_FILE,
        "PKCE",
        "TLS 1.3",
        "required client-certificate",
        "No default OpenBao OIDC role",
        "Cross-business wildcards",
        "A green pull request validates the desired-state contract only",
    ):
        if required not in doc:
            fail(f"OIDC documentation missing required contract: {required}")
    if "tls_disable = true" in doc or "native TLS is disabled" in doc:
        fail("OIDC documentation must not reintroduce TLS-disabled listener guidance")


def main() -> None:
    plan = load_json(PLAN_PATH)
    validate_plan(plan)
    validate_integration()
    print("CODESTRA_OPENBAO_OIDC_VALIDATION_PASS=1")


if __name__ == "__main__":
    main()
