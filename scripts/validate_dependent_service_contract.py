#!/usr/bin/env python3
"""Validate dependent-service admissions against the canonical workload authority."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts/dependent-services.v1.json"
AUTHORITY_PATH = ROOT / "config/workload-secret-authority.v1.json"
AUTHORITY_VALIDATOR_PATH = ROOT / "scripts/validate_workload_secret_authority.py"
SPEC = importlib.util.spec_from_file_location(
    "validate_workload_secret_authority", AUTHORITY_VALIDATOR_PATH
)
assert SPEC and SPEC.loader
AUTHORITY_VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY_VALIDATOR)

CANONICAL_FRAMEWORK = {
    "deployment": "deploy/compose/compose.yaml",
    "workload_authority": "config/workload-secret-authority.v1.json",
    "keycloak_jwt": "config/auth/keycloak-jwt.v1.json",
    "jwt_roles": "openbao/auth/jwt-roles.v1.json",
    "audit": "config/audit/audit.v1.json",
    "secret_engines": "config/secrets/engines.v1.json",
    "initialize": "scripts/initialize.sh",
    "apply": "scripts/apply_saved_plan.sh",
    "verify": "scripts/verify.sh",
}

# Repository-to-identity admission is intentionally explicit. Prefixes and
# operations are derived from the canonical production authority below.
REQUIRED_CONSUMERS = {
    "appolon1908-hue/Middleware-": ("middleware-api", "middleware-worker"),
    "appolon1908-hue/Odoo": ("odoo-integration",),
    "appolon1908-hue/klyrow.com": ("klyrow-email-adapter",),
    "appolon1908-hue/telnexa": ("telnexa-sms-adapter",),
    "appolon1908-hue/Vicidialer-Codestra": ("vicidial-adapter",),
    "appolon1908-hue/Codestra-Prometheus": ("prometheus-openbao",),
}
CONSTRAINTS = {
    "appolon1908-hue/Odoo": "credentials only; no business data",
    "appolon1908-hue/klyrow.com": "live email delivery remains separately gated",
    "appolon1908-hue/telnexa": "live SMS remains separately gated",
    "appolon1908-hue/Vicidialer-Codestra": "production dialing remains separately gated",
    "appolon1908-hue/Codestra-Prometheus": "private OpenBao metrics client material only",
}
NO_DIRECT_IDENTITY_REPOSITORIES = {
    "appolon1908-hue/Keycloak",
    "appolon1908-hue/Codestra-Grafana-",
    "appolon1908-hue/Superset",
    "appolon1908-hue/Codestra-Alertmanager",
}
REQUIRED_RUNTIME_GATES = {
    "exact_scanned_image": True,
    "sbom_and_provenance": True,
    "three_voting_nodes": True,
    "pgp_offline_custody_3_of_5": True,
    "native_ports_private": True,
    "mtls": True,
    "keycloak_jwt_exact_claims": True,
    "audit_before_secret_use": True,
    "saved_plan_zero_destroy": True,
    "runtime_apply_authorized": True,
}
REQUIRED_INVARIANTS = {
    "secret_values_in_git": False,
    "browser_provider_secrets": False,
    "cross_environment_reads": False,
    "observability_application_provider_credentials": False,
    "odoo_business_data_in_openbao": False,
    "native_port_public": False,
    "parent_prefix_broadening": False,
    "unadmitted_workload_identities": False,
}


def fail(message: str) -> None:
    raise SystemExit(f"OPENBAO_DEPENDENCY_CONTRACT=FAIL: {message}")


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def production_roles(authority: dict) -> dict[str, dict]:
    roles: dict[str, dict] = {}
    for role in authority["roles"]:
        if role["environment"] != "production":
            continue
        identity = role["serviceIdentity"]
        if identity in roles:
            fail(f"duplicate production identity:{identity}")
        roles[identity] = role
    return roles


def validate(contract: dict, authority: dict, authority_blob_sha: str) -> None:
    AUTHORITY_VALIDATOR.validate(authority)
    if set(contract) != {
        "schema_version",
        "authority",
        "environment",
        "canonical_endpoint",
        "canonical_framework",
        "authority_binding",
        "consumers",
        "integrations_without_openbao_workload_identity",
        "required_runtime_gates",
        "invariants",
    }:
        fail("top-level fields drifted")
    if contract["schema_version"] != "1.1":
        fail("schema version drifted")
    if contract["authority"] != "appolon1908-hue/Codestra-OpenBao":
        fail("repository authority drifted")
    if contract["environment"] != "production":
        fail("dependency contract must be production-scoped")
    if contract["canonical_endpoint"] != "https://bao.codestra.media":
        fail("canonical endpoint drifted")
    if contract["canonical_framework"] != CANONICAL_FRAMEWORK:
        fail("canonical framework or guarded execution path drifted")

    binding = contract["authority_binding"]
    if set(binding) != {
        "source",
        "source_blob_sha",
        "derivation",
        "default_policy",
        "runtime_binding_authorized",
    }:
        fail("authority binding fields drifted")
    if binding["source"] != CANONICAL_FRAMEWORK["workload_authority"]:
        fail("workload authority source drifted")
    if binding["source_blob_sha"] != authority_blob_sha:
        fail("workload authority blob binding drifted")
    if binding["default_policy"] != "deny":
        fail("default policy must deny")
    if binding["runtime_binding_authorized"] is not False:
        fail("runtime binding was activated")

    roles = production_roles(authority)
    consumers = contract["consumers"]
    if not isinstance(consumers, list):
        fail("consumer list missing")
    by_repo: dict[str, dict] = {}
    for consumer in consumers:
        expected_fields = {"repo", "access"}
        if consumer.get("repo") in CONSTRAINTS:
            expected_fields.add("constraint")
        if set(consumer) != expected_fields:
            fail("consumer fields drifted")
        repo = consumer["repo"]
        if repo in by_repo:
            fail(f"duplicate consumer repository:{repo}")
        by_repo[repo] = consumer
        if any(marker in repo.lower() for marker in ("browser", "frontend", "portal")):
            fail(f"browser-facing consumer admitted:{repo}")
    if set(by_repo) != set(REQUIRED_CONSUMERS):
        fail("consumer repository coverage drifted")

    for repo, identities in REQUIRED_CONSUMERS.items():
        consumer = by_repo[repo]
        if repo in CONSTRAINTS and consumer["constraint"] != CONSTRAINTS[repo]:
            fail(f"consumer constraint drifted:{repo}")
        access = consumer["access"]
        if not isinstance(access, list) or len(access) != len(identities):
            fail(f"consumer access coverage drifted:{repo}")
        expected_access = []
        for identity in identities:
            role = roles.get(identity)
            if role is None:
                fail(f"dependency names unknown identity:{identity}")
            if role["operations"] != ["read"]:
                fail(f"non-read privilege admitted:{identity}")
            if role["runtimeBindingAuthorized"] is not False:
                fail(f"runtime role activated:{identity}")
            if role["providerBusinessEffectsEnabled"] is not False:
                fail(f"business effect enabled:{identity}")
            prefixes = role["pathPrefixes"]
            if any(not prefix.startswith("codestra/production/") for prefix in prefixes):
                fail(f"cross-environment prefix admitted:{identity}")
            expected_access.append({"identity": identity, "prefixes": prefixes})
        if access != expected_access:
            fail(f"identity or prefix drifted:{repo}")

    prometheus = by_repo["appolon1908-hue/Codestra-Prometheus"]["access"]
    if prometheus != [
        {
            "identity": "prometheus-openbao",
            "prefixes": ["codestra/production/observability/openbao/metrics-client/"],
        }
    ]:
        fail("observability received non-metrics or provider credentials")
    for repo, consumer in by_repo.items():
        if repo == "appolon1908-hue/Codestra-Prometheus":
            continue
        if any(
            prefix.startswith("codestra/production/observability/")
            for access in consumer["access"]
            for prefix in access["prefixes"]
        ):
            fail(f"non-observability consumer received observability material:{repo}")

    no_identity = contract["integrations_without_openbao_workload_identity"]
    if not isinstance(no_identity, list):
        fail("no-identity integration list missing")
    no_identity_repos = set()
    for integration in no_identity:
        if set(integration) != {"repo", "role"} or not integration["role"]:
            fail("no-identity integration fields drifted")
        repo = integration["repo"]
        if repo in no_identity_repos:
            fail(f"duplicate no-identity integration:{repo}")
        no_identity_repos.add(repo)
    if no_identity_repos != NO_DIRECT_IDENTITY_REPOSITORIES:
        fail("no-direct-identity coverage drifted")
    if no_identity_repos & set(by_repo):
        fail("integration without identity was admitted as a consumer")

    if contract["required_runtime_gates"] != REQUIRED_RUNTIME_GATES:
        fail("required runtime gates drifted")
    if contract["invariants"] != REQUIRED_INVARIANTS:
        fail("security invariants drifted")


def main() -> int:
    try:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        authority_bytes = AUTHORITY_PATH.read_bytes()
        authority = json.loads(authority_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))
    validate(contract, authority, git_blob_sha(authority_bytes))
    print("OPENBAO_DEPENDENCY_CONTRACT=PASS")
    print("DEPENDENCY_PREFIXES_DERIVED_FROM_CANONICAL_AUTHORITY=YES")
    print("DIRECT_OPENBAO_CONSUMERS=6")
    print("NO_DIRECT_IDENTITY_INTEGRATIONS=4")
    print("RUNTIME_BINDINGS_AUTHORIZED=NO")
    print("PROVIDER_BUSINESS_EFFECTS_ENABLED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
