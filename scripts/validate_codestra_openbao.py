#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao corporate overlay."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
RUNTIME_DIR = CODESTRA / "runtime-v1"
RUNTIME = RUNTIME_DIR / "runtime.v1.json"
CONTROL = RUNTIME_DIR / "secret-control-plane.v1.json"
DESIRED = RUNTIME_DIR / "desired-state.json"
CONFIG_TEMPLATE = RUNTIME_DIR / "openbao.hcl.example"
ACTIVE_CONFIG = RUNTIME_DIR / "openbao.hcl"
GENERATOR = RUNTIME_DIR / "generate_business_policies.py"
POLICIES = RUNTIME_DIR / "policies"
OPERATING_MODEL = CODESTRA / "docs" / "OPERATING-MODEL.md"
CORPORATE_FEATURES = CODESTRA / "docs" / "CORPORATE-FEATURES.md"
UPSTREAM_MANIFEST = ROOT / "CODESTRA_UPSTREAM.json"
UPSTREAM_WORKFLOW = ROOT / ".github" / "workflows" / "upstream-source-sync.yml"

BUSINESSES = {
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
}
PLATFORM_PRODUCTS = {
    "loki",
    "prometheus",
    "grafana",
    "tempo",
    "opentelemetry",
    "alloy",
    "node-exporter",
    "cadvisor",
    "redis-exporter",
    "blackbox-exporter",
    "superset",
    "openbao",
}
POLICY_FILES = {
    "auditor.hcl",
    "beyvra-execution-template.hcl",
    "beyvra-observability-deny.hcl",
    "business-admin-template.hcl",
    "grafana-runtime.hcl",
    "loki-runtime.hcl",
    "otel-runtime.hcl",
    "prometheus-openbao-metrics.hcl",
    "superset-runtime.hcl",
    "tempo-runtime.hcl",
    "workload-read-template.hcl",
}
PLATFORM_RUNTIME_POLICIES = {
    "grafana-runtime.hcl",
    "loki-runtime.hcl",
    "otel-runtime.hcl",
    "prometheus-openbao-metrics.hcl",
    "superset-runtime.hcl",
    "tempo-runtime.hcl",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_file(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(require_file(path))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def validate_runtime() -> None:
    runtime = load_json(RUNTIME)
    if runtime.get("schemaVersion") != "1.1" or runtime.get("component") != "openbao":
        fail("OpenBao runtime identity or schema mismatch")
    if runtime.get("canonicalHostname") != "bao.codestra.media":
        fail("canonical OpenBao hostname mismatch")
    if runtime.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("OpenBao runtime must remain source-only")
    if set(runtime.get("businessScope", [])) != BUSINESSES:
        fail("OpenBao business catalogue mismatch")
    if set(runtime.get("platformProductScope", [])) != PLATFORM_PRODUCTS:
        fail("OpenBao platform-product catalogue mismatch")
    if set(runtime.get("environmentScope", [])) != {
        "development",
        "test",
        "staging",
        "production",
    }:
        fail("OpenBao environment catalogue mismatch")

    storage = runtime.get("storage", {})
    if storage.get("backend") != "integrated-raft":
        fail("OpenBao must use integrated Raft")
    if storage.get("haRequired") is not True:
        fail("OpenBao HA must remain required")
    if int(storage.get("minimumVotingNodesProduction", 0)) < 3:
        fail("OpenBao production requires at least three voting nodes")
    for field in (
        "autopilotRequired",
        "snapshotsEncryptedAndTested",
        "snapshotRestoreValidationRequired",
    ):
        if storage.get(field) is not True:
            fail(f"OpenBao storage control missing: {field}")

    transport = runtime.get("transport", {})
    if transport.get("minimumVersion") != "TLS13":
        fail("OpenBao transport must require TLS 1.3")
    for field in ("tlsRequired", "clusterTlsRequired"):
        if transport.get(field) is not True:
            fail(f"OpenBao TLS control missing: {field}")
    for field in ("plaintextListener", "publicNativePort", "prometheusUnauthenticatedMetrics"):
        if transport.get(field) is not False:
            fail(f"OpenBao transport boundary must remain false: {field}")

    human = runtime.get("identity", {}).get("human", {})
    if human.get("method") != "keycloak-oidc":
        fail("OpenBao human identity must use Keycloak OIDC")
    if human.get("issuer") != "https://auth.codestra.co/realms/codestra":
        fail("OpenBao issuer mismatch")
    if human.get("pkce") != "S256" or human.get("mfaRequiredForPrivilegedRoles") is not True:
        fail("OpenBao privileged human access must require PKCE and MFA")
    if human.get("rootTokenDailyUse") is not False:
        fail("daily root-token use must remain prohibited")

    workload = runtime.get("identity", {}).get("workload", {})
    if workload.get("preferredMethod") != "jwt" or workload.get("requiredAudience") != "openbao":
        fail("OpenBao workload identity must use audience-bound JWT")
    if workload.get("staticLongLivedTokens") is not False:
        fail("static long-lived workload tokens must remain disabled")
    if int(workload.get("tokenTtlMinutes", 0)) > 15:
        fail("OpenBao workload token TTL exceeds 15 minutes")
    if int(workload.get("tokenMaxTtlMinutes", 0)) > 60:
        fail("OpenBao workload maximum TTL exceeds one hour")

    engines = runtime.get("secretEngines", {})
    required_mounts = {
        "platformKvV2Mount": "kv-platform/",
        "businessMountPattern": "kv-<business>/",
        "pkiIntermediateMount": "pki-platform-intermediate/",
        "pkiIssuingMount": "pki-platform-issuing/",
        "transitPlatformMount": "transit-platform/",
        "transitBeyvraMount": "transit-beyvra/",
    }
    for field, expected in required_mounts.items():
        if engines.get(field) != expected:
            fail(f"OpenBao mount contract mismatch for {field}")
    if engines.get("sshOrSigningEngineEnabledByDefault") is not False:
        fail("SSH/signing engines must remain disabled by default")

    isolation = runtime.get("businessIsolation", {})
    for field in ("mountPerBusiness", "environmentPathIsolation"):
        if isolation.get(field) is not True:
            fail(f"OpenBao isolation control missing: {field}")
    for field in (
        "crossBusinessWildcardPolicies",
        "customerControlledPolicyNames",
        "platformProductsMayReadBusinessSecretValues",
        "observabilityMayReadSecretValues",
        "supersetMayReadSecretValues",
        "n8nMayReadUnscopedSecretValues",
    ):
        if isolation.get(field) is not False:
            fail(f"OpenBao isolation boundary must remain false: {field}")

    beyvra = runtime.get("beyvraHighSecurityCompartment", {})
    if beyvra.get("mount") != "kv-beyvra/" or beyvra.get("transitMount") != "transit-beyvra/":
        fail("Beyvra high-security mount mismatch")
    if beyvra.get("brokerExchangeCustodySigningEnabledByDefault") is not False:
        fail("Beyvra signing must remain disabled by default")
    if beyvra.get("browserSecretValueAccess") is not False:
        fail("Beyvra browser secret access must remain disabled")
    if beyvra.get("dualApprovalForSigningActivation") is not True:
        fail("Beyvra signing activation must require dual approval")
    if not PLATFORM_PRODUCTS.issubset(set(beyvra.get("deniedReaders", [])) | {"openbao"}):
        fail("Beyvra compartment does not deny every non-OpenBao platform product")

    activation = runtime.get("activation", {})
    if not activation or any(value is not False for value in activation.values()):
        fail("all OpenBao activation gates must remain false")


def validate_control_plane() -> None:
    control = load_json(CONTROL)
    if control.get("schemaVersion") != "1.1":
        fail("OpenBao control-plane schema mismatch")
    if control.get("status") != "CONTROL_PLANE_PREPARED_NOT_APPLIED":
        fail("OpenBao control plane must remain unapplied")
    if set(control.get("businesses", [])) != BUSINESSES:
        fail("OpenBao control-plane business catalogue mismatch")
    if set(control.get("platformProducts", [])) != PLATFORM_PRODUCTS:
        fail("OpenBao control-plane platform catalogue mismatch")

    mount_plan = control.get("mountPlan", {})
    expected_mounts = {
        "kvPlatform": "kv-platform/",
        "kvV2PerBusiness": "kv-<business>/",
        "transitSharedPlatform": "transit-platform/",
        "transitDedicatedBeyvra": "transit-beyvra/",
        "pkiIntermediate": "pki-platform-intermediate/",
        "pkiIssuing": "pki-platform-issuing/",
    }
    for field, expected in expected_mounts.items():
        if mount_plan.get(field) != expected:
            fail(f"OpenBao control-plane mount mismatch for {field}")

    for template_name in ("platformWorkloadRoleTemplate", "businessWorkloadRoleTemplate"):
        workload = control.get(template_name, {})
        if workload.get("authMethod") != "jwt" or workload.get("requiredAudience") != "openbao":
            fail(f"{template_name} must use audience-bound JWT")
        claims = workload.get("boundClaims", {})
        if set(claims) != {"codestra_business", "application", "environment"}:
            fail(f"{template_name} must bind business, application and environment")
        if int(workload.get("tokenTtlMinutes", 0)) > 15:
            fail(f"{template_name} token TTL exceeds policy")
        if int(workload.get("tokenMaximumTtlMinutes", 0)) > 60:
            fail(f"{template_name} maximum TTL exceeds policy")
        if workload.get("periodicWithoutMaximum") is not False:
            fail(f"{template_name} permits unbounded periodic tokens")

    platform_template = control.get("platformWorkloadRoleTemplate", {})
    if platform_template.get("businessMountRead") is not False:
        fail("platform workloads may not read business mounts")
    if not str(platform_template.get("secretPath", "")).startswith("kv-platform/data/"):
        fail("platform workload path must use kv-platform")

    business_template = control.get("businessWorkloadRoleTemplate", {})
    if not str(business_template.get("secretPath", "")).startswith("kv-<business>/data/"):
        fail("business workload path must use its business mount")

    rules = control.get("policyRules", {})
    for field in (
        "wildcardAcrossBusinessMounts",
        "platformPoliciesMayReadBusinessMounts",
        "policyNameFromCustomerInput",
        "mountAdministrationForWorkloads",
        "sysRawAccessForWorkloads",
        "tokenCreationForWorkloads",
        "identityMutationForWorkloads",
    ):
        if rules.get(field) is not False:
            fail(f"OpenBao policy boundary must remain false: {field}")

    pki = control.get("pkiRoles", {})
    if pki.get("allowAnyName") is not False or pki.get("allowIpSansDefault") is not False:
        fail("OpenBao PKI names must remain constrained")
    if int(pki.get("ttlHours", 0)) > 24 or int(pki.get("maxTtlHours", 0)) > 168:
        fail("OpenBao PKI TTL exceeds policy")

    beyvra = control.get("beyvra", {})
    if beyvra.get("brokerExchangeCustodyPrefixDefaultEnabled") is not False:
        fail("Beyvra broker/exchange/custody prefix must remain disabled")
    for field in ("generalAnalyticsAccess", "observabilityAccess", "n8nAccess", "exportableSigningKeys"):
        if beyvra.get(field) is not False:
            fail(f"Beyvra secret boundary must remain false: {field}")

    release_gates = control.get("releaseGates", {})
    if not release_gates or any(value is not False for value in release_gates.values()):
        fail("all OpenBao release gates must remain false")


def validate_desired_state() -> None:
    desired = load_json(DESIRED)
    if desired.get("schemaVersion") != "1.1":
        fail("OpenBao desired-state schema mismatch")
    if desired.get("status") != "SOURCE_PREPARED_NOT_APPLIED":
        fail("OpenBao desired state must remain unapplied")
    if set(desired.get("businesses", [])) != BUSINESSES:
        fail("OpenBao desired-state business catalogue mismatch")
    auth_types = {item.get("type") for item in desired.get("authMethods", [])}
    if auth_types != {"jwt", "oidc", "approle"}:
        fail("OpenBao desired state must define JWT, OIDC, and exception-only AppRole")
    serialized_engines = json.dumps(desired.get("secretEngines", []))
    for mount in (
        "kv-platform/",
        "kv-<business>/",
        "pki-platform-intermediate/",
        "pki-platform-issuing/",
        "database/",
        "transit-platform/",
        "transit-beyvra/",
    ):
        if mount not in serialized_engines:
            fail(f"OpenBao desired state omits mount {mount}")
    if '"path": "secret/"' in serialized_engines:
        fail("legacy generic secret/ mount remains in desired state")
    gates = desired.get("releaseGates", {})
    if gates.get("liveApplyFromPullRequestAllowed") is not False:
        fail("OpenBao pull requests may not apply live state")
    if gates.get("nativeSourceValidationComplete") is not False:
        fail("native source validation may not be claimed before import")
    if gates.get("productionApproved") is not False:
        fail("OpenBao production approval may not be predeclared")


def validate_hcl_configs() -> None:
    for path in (CONFIG_TEMPLATE, ACTIVE_CONFIG):
        config = require_file(path)
        for fragment in (
            'storage "raft"',
            'path = "/openbao/data"',
            'listener "tcp"',
            'tls_disable = 0',
            'tls_min_version = "tls13"',
            'unauthenticated_metrics_access = false',
            'default_lease_ttl = "15m"',
            'max_lease_ttl = "1h"',
            'raw_storage_endpoint = false',
            'plugin_directory = "/openbao/plugins"',
        ):
            if fragment not in config:
                fail(f"{path.name} omits control: {fragment}")
        for forbidden in (
            "tls_disable = 1",
            'tls_min_version = "tls10"',
            'tls_min_version = "tls11"',
            'tls_min_version = "tls12"',
            "disable_mlock",
            "unauthenticated_metrics_access = true",
            "http://",
            "token =",
        ):
            if forbidden in config:
                fail(f"{path.name} contains forbidden content: {forbidden}")


def validate_policies() -> None:
    files = {path.name for path in POLICIES.glob("*.hcl")}
    if files != POLICY_FILES:
        fail(f"OpenBao policy set mismatch: {sorted(files)}")

    all_policy_text = "\n".join(require_file(POLICIES / name) for name in sorted(files))
    for legacy in ('path "secret/', 'path "pki_observability/', 'path "transit/sign/', 'path "transit/decrypt/'):
        if legacy in all_policy_text:
            fail(f"legacy OpenBao path remains in policy set: {legacy}")
    if 'capabilities = ["sudo"]' in all_policy_text:
        fail("OpenBao policy set grants sudo capability")
    if re.search(r'path\s+"\*"', all_policy_text):
        fail("OpenBao policy set contains an unrestricted path wildcard")

    for name in PLATFORM_RUNTIME_POLICIES:
        text = require_file(POLICIES / name)
        if re.search(r'path\s+"kv-(?!platform/)', text):
            fail(f"platform policy {name} references a business mount")
        if "transit-beyvra/" in text or "kv-beyvra/" in text:
            fail(f"platform policy {name} references the Beyvra compartment")

    business_admin = require_file(POLICIES / "business-admin-template.hcl")
    if 'path "kv-__BUSINESS__/data/*"' not in business_admin:
        fail("business administrator policy is not business-scoped")
    if 'path "kv-__BUSINESS__/destroy/*"' not in business_admin or '["deny"]' not in business_admin:
        fail("business administrator policy must deny permanent destroy")

    workload = require_file(POLICIES / "workload-read-template.hcl")
    if 'path "kv-__BUSINESS__/data/__APPLICATION__/__ENVIRONMENT__/*"' not in workload:
        fail("workload policy is not application/environment scoped")
    if 'path "auth/token/create*"' not in workload:
        fail("workload policy must deny child-token creation")

    auditor = require_file(POLICIES / "auditor.hcl")
    if 'path "kv-*/data/*"' not in auditor or 'capabilities = ["deny"]' not in auditor:
        fail("auditor policy must deny business secret values")

    beyvra_execution = require_file(POLICIES / "beyvra-execution-template.hcl")
    if "DO NOT APPLY by default" not in beyvra_execution:
        fail("Beyvra execution template must remain disabled by default")
    if 'path "transit-beyvra/export/*"' not in beyvra_execution:
        fail("Beyvra execution policy must deny signing-key export")

    beyvra_deny = require_file(POLICIES / "beyvra-observability-deny.hcl")
    if 'capabilities = ["deny"]' not in beyvra_deny:
        fail("Beyvra observability policy must be deny-only")
    if re.search(r'capabilities\s*=\s*\[(?!"deny"\])', beyvra_deny):
        fail("Beyvra observability policy grants a capability")
    for path in ("kv-beyvra/", "transit-beyvra/sign/", "transit-beyvra/export/"):
        if path not in beyvra_deny:
            fail(f"Beyvra observability policy omits denial for {path}")

    generator = require_file(GENERATOR)
    for required in (
        "kv-platform/data/observability/clients/",
        "pki-platform-issuing/issue/telemetry-client-",
        'path "auth/token/create*"',
        'path "sys/mounts/*"',
        'path "sys/auth/*"',
        'path "sys/audit/*"',
        "transit-beyvra/sign/*",
        "transit-beyvra/export/*",
    ):
        if required not in generator:
            fail(f"business telemetry policy generator omits {required}")
    if "secret/data/" in generator or "pki_observability/" in generator:
        fail("business telemetry generator still uses legacy mounts")


def validate_upstream_import_governance() -> None:
    manifest = load_json(UPSTREAM_MANIFEST)
    if manifest.get("deployment_enabled") is not False:
        fail("OpenBao upstream manifest may not enable deployment")
    if manifest.get("secret_material_allowed_in_git") is not False:
        fail("OpenBao upstream manifest may not allow secret material")
    if manifest.get("import_path") != "upstream":
        fail("OpenBao upstream import path mismatch")
    if manifest.get("branch_promotion") != [
        "development",
        "test",
        "staging",
        "production",
        "main",
    ]:
        fail("OpenBao branch promotion order mismatch")

    workflow_text = require_file(UPSTREAM_WORKFLOW)
    try:
        yaml.safe_load(workflow_text)
    except Exception as exc:
        fail(f"invalid OpenBao upstream workflow YAML: {exc}")
    for fragment in (
        "CODESTRA_UPSTREAM_SANITIZATION.json",
        "original_block_sha256",
        "PRIVATE_KEY_TEST_FIXTURE_REMOVED",
        "--base development",
        "gh pr create",
        "pull-requests: write",
    ):
        if fragment not in workflow_text:
            fail(f"OpenBao upstream importer omits governance control: {fragment}")
    for forbidden in (
        "git push origin HEAD:main",
        "git push origin HEAD:staging",
        "git push origin HEAD:production",
        "--base production",
        "--base staging",
    ):
        if forbidden in workflow_text:
            fail(f"OpenBao upstream importer contains direct environment push: {forbidden}")


def validate_docs_and_secret_safety() -> None:
    for path in (OPERATING_MODEL, CORPORATE_FEATURES):
        text = require_file(path).lower()
        for token in ("keycloak", "business", "rotation", "audit", "beyvra"):
            if token not in text:
                fail(f"OpenBao documentation {path.name} omits {token}")

    private_key_pattern = re.compile(
        r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
    )
    for path in CODESTRA.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if private_key_pattern.search(text):
            fail(f"private-key material found in {path.relative_to(ROOT)}")
        for signature in ("AKIA", "hvs.", "hvr.", "hvb.", "hvp."):
            if signature in text:
                fail(f"secret-shaped material found in {path.relative_to(ROOT)}")


def main() -> None:
    validate_runtime()
    validate_control_plane()
    validate_desired_state()
    validate_hcl_configs()
    validate_policies()
    validate_upstream_import_governance()
    validate_docs_and_secret_safety()
    print("Codestra OpenBao corporate configuration validation PASS")


if __name__ == "__main__":
    main()
