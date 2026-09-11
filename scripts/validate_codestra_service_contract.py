#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao native service API contract.

The contract (``codestra/api/service-contract.v1.json``) is validated against the
canonical Codestra-Telemetry schema by a reusable workflow. This validator runs
the same structural rules locally, then proves that the repository-owned
authority map (``codestra/api/native-api-authority.v1.json``) agrees with the
contract, the secret-engine and auth-method sources, the generated workload
policies and the human-readable documentation.

Nothing here contacts OpenBao. A passing run only proves that the source
describes one consistent, fail-closed API surface.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "codestra" / "api" / "service-contract.v1.json"
AUTHORITY_PATH = ROOT / "codestra" / "api" / "native-api-authority.v1.json"
DOCUMENT_PATH = ROOT / "docs" / "CODESTRA-SERVICE-API.md"
ENGINES_PATH = ROOT / "config" / "secrets" / "engines.v1.json"
JWT_AUTH_PATH = ROOT / "config" / "auth" / "keycloak-jwt.v1.json"
OIDC_PLAN_PATH = ROOT / "codestra" / "runtime-v1" / "oidc-plan.v1.json"
POLICY_GENERATOR_PATH = ROOT / "scripts" / "generate_workload_policies.py"

EXPECTED_REPOSITORY = "appolon1908-hue/Codestra-OpenBao"
EXPECTED_COMPONENT = "openbao"
EXPECTED_CONTRACT_ID = "codestra.observability.openbao.v1"
EXPECTED_HOSTNAME = "bao.codestra.media"
SCHEMA_AUTHORITY = {
    "repository": "appolon1908-hue/Codestra-Telemetry",
    "path": "codestra/api/service-contract.schema.json",
    "sourceRevision": "c35d880a730ca5206d445e8a9a688cb465ae2ad4",
    "version": "1.0.0",
}

# Mirrors the canonical schema so violations surface before the external check.
CONTRACT_KEYS = {
    "schemaVersion", "contractId", "component", "displayName", "repository",
    "canonicalHostname", "authorityRole", "deploymentClass", "nativeExposure",
    "schemaAuthority", "signals", "nativeApi", "managementReadback", "integrations",
    "release", "correlation", "safety",
}
OPERATION_KEYS = {
    "id", "method", "path", "category", "access", "acceptedStatuses", "timeoutMs",
    "controlPlaneProxyAllowed", "responseBodyPolicy",
}
OPERATION_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
OPERATION_ACCESS = {"read_only", "query", "ingest", "mutation"}
RESPONSE_BODY_POLICIES = {"discard", "metadata_only", "native"}
OPERATION_ID = re.compile(r"^[a-z][a-z0-9-]+$")
ENVIRONMENT_NAME = re.compile(r"^CODESTRA_[A-Z0-9_]+$")

AUTHORITY_OPERATION_KEYS = {
    "operationId", "mount", "callerClasses", "policyPaths", "capabilities",
    "grantedToWorkloads", "secretBearingResponse", "controlPlaneVisibility",
    "runtimeEntryPoints", "evidence",
}
AUTHORITY_OPTIONAL_KEYS = {"workloadIdentityScope", "note", "unauthenticatedPath"}
UNAUTHENTICATED_PATH = re.compile(r"^auth/[a-z0-9-]+/(login|oidc/(auth_url|callback))$")
ACL_CAPABILITIES = {"create", "read", "update", "patch", "delete", "list", "sudo"}
CONTROL_PLANE = "control-plane-readback"
WORKLOAD = "workload"
PLACEHOLDER = re.compile(r"<[a-z]+>")
SECRET_SIGNATURES = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|hv[sbrp]\.[A-Za-z0-9]{20,}")
PRIVATE_KEY = "BEGIN " + "PRIVATE KEY"
DOCUMENT_ROW = re.compile(
    r"^\| `(?P<method>[A-Z]+)` \| `(?P<path>[^`]+)` \| (?P<category>[a-z_]+) \| (?P<access>[a-z_]+) \|"
)
DOCUMENT_CALLER_ROW = re.compile(r"^\| `(?P<caller>[a-z-]+)` \|")
HCL_STANZA = re.compile(r'path "(?P<path>[^"]+)" \{\s*capabilities = \[(?P<caps>[^\]]*)\]\s*\}')


class ContractError(Exception):
    """Raised for every validation failure; the message names the rule."""


class Inputs:
    """Every source the validator reasons about, loaded once so tests can mutate copies."""

    def __init__(
        self,
        *,
        contract: dict[str, Any],
        authority: dict[str, Any],
        document: str,
        engines: dict[str, Any],
        jwt_auth: dict[str, Any],
        oidc_plan: dict[str, Any],
        rendered_policies: dict[str, str],
        existing_files: set[str],
    ) -> None:
        self.contract = contract
        self.authority = authority
        self.document = document
        self.engines = engines
        self.jwt_auth = jwt_auth
        self.oidc_plan = oidc_plan
        self.rendered_policies = rendered_policies
        self.existing_files = existing_files


def fail(message: str) -> None:
    raise ContractError(message)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT).as_posix()}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT).as_posix()} must contain an object")
    return value


def render_workload_policies() -> dict[str, str]:
    spec = importlib.util.spec_from_file_location("generate_workload_policies", POLICY_GENERATOR_PATH)
    if spec is None or spec.loader is None:
        fail("cannot import scripts/generate_workload_policies.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    authority = json.loads(module.AUTHORITY.read_text(encoding="utf-8"))
    rendered, _ = module.build(authority)
    return {pathlib.Path(relative).as_posix(): source for relative, source in rendered.items()}


def repository_files(root: pathlib.Path = ROOT) -> set[str]:
    """Relative paths of every tracked-style source file, ignoring Git internals and the vendored upstream."""
    existing: set[str] = set()
    for entry in root.iterdir():
        if entry.name in {".git", "upstream"}:
            continue
        candidates = entry.rglob("*") if entry.is_dir() else [entry]
        for path in candidates:
            if path.is_file() and "__pycache__" not in path.parts:
                existing.add(path.relative_to(root).as_posix())
    return existing


def load_inputs(root: pathlib.Path = ROOT) -> Inputs:
    existing = repository_files(root)
    return Inputs(
        contract=load_json(CONTRACT_PATH),
        authority=load_json(AUTHORITY_PATH),
        document=DOCUMENT_PATH.read_text(encoding="utf-8"),
        engines=load_json(ENGINES_PATH),
        jwt_auth=load_json(JWT_AUTH_PATH),
        oidc_plan=load_json(OIDC_PLAN_PATH),
        rendered_policies=render_workload_policies(),
        existing_files=existing,
    )


# --- contract structure -------------------------------------------------------

def validate_contract_structure(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    extra = set(contract) - CONTRACT_KEYS
    missing = CONTRACT_KEYS - set(contract)
    if extra or missing:
        fail(f"contract keys must match the canonical schema exactly (extra={sorted(extra)}, missing={sorted(missing)})")
    if contract["schemaVersion"] != "1.0.0":
        fail("contract schemaVersion must be 1.0.0")
    if contract["component"] != EXPECTED_COMPONENT:
        fail("contract component must be openbao")
    if contract["contractId"] != EXPECTED_CONTRACT_ID:
        fail(f"contract contractId must be {EXPECTED_CONTRACT_ID}")
    if contract["repository"] != EXPECTED_REPOSITORY:
        fail(f"contract repository must be {EXPECTED_REPOSITORY}")
    if contract["authorityRole"] != "secrets-pki-workload-identity-authority":
        fail("contract authorityRole is not the secrets/PKI/workload-identity authority")
    if contract["canonicalHostname"] != EXPECTED_HOSTNAME:
        fail(f"contract canonicalHostname must be {EXPECTED_HOSTNAME}")
    if contract["nativeExposure"] != "private_strong_auth":
        fail("contract nativeExposure must remain private_strong_auth")
    if contract["schemaAuthority"] != SCHEMA_AUTHORITY:
        fail("contract schemaAuthority does not match the pinned Codestra-Telemetry schema revision")

    native_api = contract["nativeApi"]
    if set(native_api) != {"baseUrlEnvironment", "authentication", "operations"}:
        fail("nativeApi keys must be exactly baseUrlEnvironment, authentication and operations")
    if not ENVIRONMENT_NAME.fullmatch(native_api["baseUrlEnvironment"]):
        fail("nativeApi.baseUrlEnvironment must be a CODESTRA_* environment variable name")
    if native_api["authentication"] != {
        "callerControlledBusinessAllowed": False,
        "credentialSource": "secret_file",
        "requiredScopes": [],
        "tenantHeader": None,
        "transport": "private_mtls",
    }:
        fail("nativeApi.authentication must remain private mTLS from a secret file with no caller-controlled business")

    operations_list = native_api["operations"]
    if not isinstance(operations_list, list) or len(operations_list) < 2:
        fail("nativeApi.operations must list at least two operations")
    operations: dict[str, dict[str, Any]] = {}
    for operation in operations_list:
        if not isinstance(operation, dict) or set(operation) != OPERATION_KEYS:
            fail(f"operation {operation.get('id') if isinstance(operation, dict) else operation!r} must carry exactly the schema fields")
        identifier = operation["id"]
        if not isinstance(identifier, str) or not OPERATION_ID.fullmatch(identifier):
            fail(f"operation id {identifier!r} must match ^[a-z][a-z0-9-]+$")
        if identifier in operations:
            fail(f"operation id {identifier} is duplicated")
        if operation["method"] not in OPERATION_METHODS:
            fail(f"operation {identifier} uses unsupported method {operation['method']!r}")
        path = operation["path"]
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            fail(f"operation {identifier} path must be absolute")
        if "\r" in path or "\n" in path or " " in path:
            fail(f"operation {identifier} path contains whitespace")
        if not path.startswith("/v1/"):
            fail(f"operation {identifier} path must live beneath /v1/")
        category = operation["category"]
        if not isinstance(category, str) or not 1 <= len(category) <= 64:
            fail(f"operation {identifier} category must be 1-64 characters")
        if operation["access"] not in OPERATION_ACCESS:
            fail(f"operation {identifier} access {operation['access']!r} is not a schema value")
        if operation["controlPlaneProxyAllowed"] is not False:
            fail(f"operation {identifier} must never be proxied by the control plane")
        if operation["responseBodyPolicy"] not in RESPONSE_BODY_POLICIES:
            fail(f"operation {identifier} responseBodyPolicy {operation['responseBodyPolicy']!r} is not a schema value")
        timeout = operation["timeoutMs"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 250 <= timeout <= 10000:
            fail(f"operation {identifier} timeoutMs must be an integer between 250 and 10000")
        statuses = operation["acceptedStatuses"]
        if not isinstance(statuses, list) or not statuses or len(set(statuses)) != len(statuses):
            fail(f"operation {identifier} acceptedStatuses must be a non-empty unique list")
        for status in statuses:
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                fail(f"operation {identifier} acceptedStatuses contains {status!r}")
        operations[identifier] = operation

    management = contract["managementReadback"]
    if management["controlApiOwner"] != SCHEMA_AUTHORITY["repository"]:
        fail("managementReadback.controlApiOwner must be Codestra-Telemetry")
    if management["registryServiceId"] != EXPECTED_COMPONENT:
        fail("managementReadback.registryServiceId must be openbao")
    if management["responseBodyPolicy"] != "discard":
        fail("managementReadback.responseBodyPolicy must discard native bodies")
    if management["exposesSecretValues"] is not False or management["allowsMutation"] is not False:
        fail("managementReadback must neither expose secret values nor allow mutation")
    for key in ("healthOperationId", "readinessOperationId"):
        operation = operations.get(management[key])
        if operation is None:
            fail(f"managementReadback.{key} references an unknown operation")
        if operation["method"] not in {"GET", "HEAD"} or operation["access"] != "read_only":
            fail(f"managementReadback.{key} must reference a read-only GET/HEAD operation")
        if operation["responseBodyPolicy"] != "discard":
            fail(f"managementReadback.{key} must discard the native response body")
    for identifier in ("health", "readiness"):
        operation = operations.get(identifier)
        if operation is None or operation["path"] != "/v1/sys/health":
            fail(f"operation {identifier} must probe /v1/sys/health")
        if operation["acceptedStatuses"] != [200, 429, 472, 473]:
            fail(f"operation {identifier} must accept the documented active/standby/DR/performance-standby statuses")
    pki_issue = operations.get("pki-issue")
    if pki_issue is None or pki_issue["access"] != "mutation":
        fail("operation pki-issue must exist and be classified as a mutation")

    if any(item["mutating"] is not False for item in contract["integrations"]):
        fail("every suite integration must be non-mutating")
    release = contract["release"]
    if release["immutableImageRequired"] is not True:
        fail("release.immutableImageRequired must remain true")
    for key in ("sourceRevisionEnvironment", "imageDigestEnvironment"):
        if not ENVIRONMENT_NAME.fullmatch(release[key]):
            fail(f"release.{key} must be a CODESTRA_* environment variable name")
    correlation = contract["correlation"]
    if correlation["indexedFields"] != [
        "codestra_business", "application", "service", "environment", "server", "region", "deployment"
    ]:
        fail("correlation.indexedFields must be the bounded metric dimensions")
    if not {"request_id", "trace_id", "tenant_id"} <= set(correlation["protectedNonIndexedFields"]):
        fail("correlation.protectedNonIndexedFields must protect request_id, trace_id and tenant_id")
    if any(value is not False for value in contract["safety"].values()):
        fail("every contract safety flag must remain false")

    serialized = json.dumps(contract, sort_keys=True)
    if PRIVATE_KEY in serialized or SECRET_SIGNATURES.search(serialized):
        fail("contract source contains secret-shaped material")
    return operations


# --- authority map ------------------------------------------------------------

def mount_prefix(mount: str) -> str:
    """HTTP prefix of a mount: ``sys`` and ``auth/*`` are addressed like any secret mount."""
    return f"/v1/{mount}/"


def acl_pattern(path: str) -> re.Pattern[str]:
    """Translate an OpenBao ACL path (trailing * glob, + segment) into a regex."""
    escaped = re.escape(path)
    if escaped.endswith(r"\*"):
        escaped = escaped[:-2] + ".*"
    escaped = escaped.replace(r"\+", "[^/]+")
    return re.compile(f"^{escaped}$")


def concrete_path(template: str) -> str:
    return PLACEHOLDER.sub("sample", template).replace("*", "sample")


def template_pattern(template: str) -> re.Pattern[str]:
    """Match generated policy paths against an authority policy-path template."""
    parts = []
    for token in re.split(r"(<[a-z]+>|\*)", template):
        if token == "<environment>":
            parts.append("(development|test|staging|production)")
        elif PLACEHOLDER.fullmatch(token or ""):
            parts.append(".+")
        elif token == "*":
            parts.append(r"\*")
        else:
            parts.append(re.escape(token))
    return re.compile("^" + "".join(parts) + "$")


def parse_stanzas(source: str) -> list[tuple[str, set[str]]]:
    stanzas = []
    for match in HCL_STANZA.finditer(source):
        capabilities = {item.strip().strip('"') for item in match.group("caps").split(",") if item.strip()}
        stanzas.append((match.group("path"), capabilities))
    return stanzas


def validate_authority(inputs: Inputs, operations: dict[str, dict[str, Any]]) -> None:
    authority = inputs.authority
    if authority.get("contract") != CONTRACT_PATH.relative_to(ROOT).as_posix():
        fail("authority map must reference codestra/api/service-contract.v1.json")
    for key in ("runtimeApplyAuthorized", "controlPlaneProxyAllowed", "secretValueReadbackEnabled"):
        if authority.get(key) is not False:
            fail(f"authority map {key} must remain false")
    caller_classes = authority.get("callerClasses")
    if not isinstance(caller_classes, dict) or not caller_classes:
        fail("authority map must define caller classes")
    for name, definition in caller_classes.items():
        if not re.fullmatch(r"[a-z][a-z-]+", name):
            fail(f"caller class {name!r} must be lower-case kebab-case")
        if set(definition) != {"description", "authentication", "authority"}:
            fail(f"caller class {name} must define description, authentication and authority")
        source = definition["authority"].split("#", 1)[0]
        if source not in inputs.existing_files:
            fail(f"caller class {name} authority {source} does not exist")
    if CONTROL_PLANE not in caller_classes or WORKLOAD not in caller_classes:
        fail("authority map must define the control-plane-readback and workload caller classes")

    mounts = authority.get("mounts")
    if not isinstance(mounts, dict) or not mounts:
        fail("authority map must define mounts")
    engine_paths = {engine["path"].rstrip("/"): engine for engine in inputs.engines["engines"]}
    jwt_mount = inputs.jwt_auth["mount"]
    oidc_mount = inputs.oidc_plan["authMount"]["path"]
    for mount, definition in mounts.items():
        if mount in ("sys", "auth/token"):
            if definition.get("source") != "upstream":
                fail(f"mount {mount} is an upstream system mount")
            continue
        if mount.startswith("auth/"):
            name = mount[len("auth/"):]
            expected_source = None
            if name == jwt_mount:
                expected_source = JWT_AUTH_PATH
                if definition.get("status") != inputs.jwt_auth["status"]:
                    fail(f"mount {mount} status must match {JWT_AUTH_PATH.name}")
            elif name == oidc_mount:
                expected_source = OIDC_PLAN_PATH
                if definition.get("status") != inputs.oidc_plan["status"]:
                    fail(f"mount {mount} status must match {OIDC_PLAN_PATH.name}")
            else:
                fail(f"auth mount {mount} is not declared by the JWT or OIDC source")
            if definition.get("source") != expected_source.relative_to(ROOT).as_posix():
                fail(f"mount {mount} must cite {expected_source.relative_to(ROOT).as_posix()}")
            continue
        engine = engine_paths.get(mount)
        if engine is None:
            fail(f"secret mount {mount} is not declared in config/secrets/engines.v1.json")
        if definition.get("source") != ENGINES_PATH.relative_to(ROOT).as_posix():
            fail(f"mount {mount} must cite config/secrets/engines.v1.json")
        if definition.get("type") != engine["type"]:
            fail(f"mount {mount} type must be {engine['type']}")
        if definition.get("status") != inputs.engines["status"]:
            fail(f"mount {mount} status must match the engines authority")
        if "enabledByDefault" in engine and definition.get("enabledByDefault") is not engine["enabledByDefault"]:
            fail(f"mount {mount} enabledByDefault must match the engines authority")
    if inputs.engines.get("runtimeApplyAuthorized") is not False:
        fail("config/secrets/engines.v1.json must keep runtimeApplyAuthorized false")
    validate_oidc_redirects(inputs, operations, oidc_mount)

    rows = authority.get("operations")
    if not isinstance(rows, list) or not rows:
        fail("authority map must list operations")
    seen: set[str] = set()
    stanzas_by_policy = {name: parse_stanzas(source) for name, source in inputs.rendered_policies.items()}
    if not stanzas_by_policy:
        fail("no generated workload policies are available for cross-checking")
    management = inputs.contract["managementReadback"]
    readback_ids = {management["healthOperationId"], management["readinessOperationId"]}

    for row in rows:
        if not isinstance(row, dict):
            fail("authority operations must be objects")
        keys = set(row)
        if not AUTHORITY_OPERATION_KEYS <= keys or not keys <= AUTHORITY_OPERATION_KEYS | AUTHORITY_OPTIONAL_KEYS:
            fail(f"authority operation {row.get('operationId')!r} carries unexpected or missing fields")
        identifier = row["operationId"]
        if identifier in seen:
            fail(f"authority operation {identifier} is duplicated")
        seen.add(identifier)
        operation = operations.get(identifier)
        if operation is None:
            fail(f"authority operation {identifier} is not in the contract")

        mount = row["mount"]
        if mount not in mounts:
            fail(f"operation {identifier} references undeclared mount {mount}")
        if not operation["path"].startswith(mount_prefix(mount)):
            fail(f"operation {identifier} path {operation['path']} is outside mount {mount}")

        callers = row["callerClasses"]
        if not isinstance(callers, list) or not callers or len(set(callers)) != len(callers):
            fail(f"operation {identifier} must name at least one distinct caller class")
        unknown = set(callers) - set(caller_classes)
        if unknown:
            fail(f"operation {identifier} names undefined caller classes {sorted(unknown)}")
        if operation["access"] == "mutation" and CONTROL_PLANE in callers:
            fail(f"operation {identifier} is a mutation and can never be reached by the control plane")
        if (CONTROL_PLANE in callers) != (identifier in readback_ids):
            fail(f"operation {identifier} control-plane access must match managementReadback exactly")

        policy_paths = row["policyPaths"]
        if not isinstance(policy_paths, list) or not policy_paths:
            fail(f"operation {identifier} must name its governing policy paths")
        for policy_path in policy_paths:
            if not isinstance(policy_path, str) or policy_path.startswith("/") or "\n" in policy_path:
                fail(f"operation {identifier} policy path {policy_path!r} must be a relative ACL path")
            expected_prefix = mount_prefix(mount)[len("/v1/"):]
            if not policy_path.startswith(expected_prefix):
                fail(f"operation {identifier} policy path {policy_path} must start with {expected_prefix}")
        capabilities = row["capabilities"]
        if not isinstance(capabilities, list) or not capabilities or not set(capabilities) <= ACL_CAPABILITIES:
            fail(f"operation {identifier} capabilities must be ACL capabilities")

        if row["controlPlaneVisibility"] not in {"none", "status_only"}:
            fail(f"operation {identifier} controlPlaneVisibility must be none or status_only")
        if (row["controlPlaneVisibility"] == "status_only") != (identifier in readback_ids):
            fail(f"operation {identifier} status visibility must match managementReadback exactly")
        if identifier in readback_ids and operation["responseBodyPolicy"] != "discard":
            fail(f"operation {identifier} is read back by the control plane and must discard its body")

        if row["secretBearingResponse"] is True:
            if operation["responseBodyPolicy"] != "native":
                fail(f"operation {identifier} carries secret material and must keep the native body policy")
            if CONTROL_PLANE in callers:
                fail(f"operation {identifier} carries secret material and can never be read back by the control plane")
        elif row["secretBearingResponse"] is not False:
            fail(f"operation {identifier} secretBearingResponse must be boolean")

        granted = row["grantedToWorkloads"]
        if granted not in (True, False):
            fail(f"operation {identifier} grantedToWorkloads must be boolean")
        if granted != (WORKLOAD in callers):
            fail(f"operation {identifier} grantedToWorkloads must agree with its caller classes")
        scope = row.get("workloadIdentityScope")
        if scope is not None and (not granted or not isinstance(scope, list) or not scope):
            fail(f"operation {identifier} workloadIdentityScope requires a workload grant")
        unauthenticated = row.get("unauthenticatedPath", False)
        if unauthenticated not in (True, False):
            fail(f"operation {identifier} unauthenticatedPath must be boolean")
        if unauthenticated:
            if not mount.startswith("auth/") or not all(UNAUTHENTICATED_PATH.match(p) for p in policy_paths):
                fail(f"operation {identifier} may only be unauthenticated on an auth-method login or OIDC path")
        else:
            validate_policy_enforcement(identifier, row, stanzas_by_policy)

        for reference in list(row["runtimeEntryPoints"]) + list(row["evidence"]):
            if not evidence_exists(reference, inputs.existing_files):
                fail(f"operation {identifier} cites missing file {reference}")
        if not row["evidence"]:
            fail(f"operation {identifier} must cite repository evidence")

    if seen != set(operations):
        fail(
            "authority map and contract must describe the same operations "
            f"(missing={sorted(set(operations) - seen)}, extra={sorted(seen - set(operations))})"
        )
    pki_mount = next(engine["path"].rstrip("/") for engine in inputs.engines["engines"] if engine["type"] == "pki")
    if operations["pki-issue"]["path"] != f"/v1/{pki_mount}/issue/{{role}}":
        fail("operation pki-issue must target the declared PKI mount")


def validate_oidc_redirects(inputs: Inputs, operations: dict[str, dict[str, Any]], oidc_mount: str) -> None:
    """The plan's registered redirect URIs must target the callback the backend actually serves.

    The upstream JWT/OIDC backend registers ``oidc/callback`` beneath its mount, so the
    API redirect for the ``oidc`` mount is ``/v1/auth/oidc/oidc/callback`` and the UI
    redirect is ``/ui/vault/auth/oidc/oidc/callback``. A redirect that omits the second
    segment is silently unreachable.
    """
    callback = operations.get("oidc-callback")
    if callback is None:
        fail("contract must declare the oidc-callback operation")
    expected_api = f"https://{EXPECTED_HOSTNAME}{callback['path']}"
    expected_ui = f"https://{EXPECTED_HOSTNAME}/ui/vault/auth/{oidc_mount}/oidc/callback"
    if callback["path"] != f"/v1/auth/{oidc_mount}/oidc/callback":
        fail(f"operation oidc-callback must be served at /v1/auth/{oidc_mount}/oidc/callback")
    redirect_sets = [inputs.oidc_plan["client"]["redirectUris"]]
    redirect_sets.extend(role["allowedRedirectUris"] for role in inputs.oidc_plan["roles"])
    for redirects in redirect_sets:
        hosted = [uri for uri in redirects if uri.startswith(f"https://{EXPECTED_HOSTNAME}/")]
        if set(hosted) != {expected_api, expected_ui}:
            fail(f"OIDC plan redirect URIs on {EXPECTED_HOSTNAME} must be exactly {expected_api} and {expected_ui}")


def evidence_exists(reference: str, existing: set[str]) -> bool:
    if reference in existing:
        return True
    if "<" not in reference:
        return False
    pattern = re.compile("^" + "".join(".+" if PLACEHOLDER.fullmatch(part or "") else re.escape(part)
                                       for part in re.split(r"(<[a-z]+>)", reference)) + "$")
    return any(pattern.match(candidate) for candidate in existing)


def validate_policy_enforcement(
    identifier: str, row: dict[str, Any], stanzas_by_policy: dict[str, list[tuple[str, set[str]]]]
) -> None:
    """Prove the workload grant/deny claims against the generated HCL policies."""
    required = set(row["capabilities"])
    scope = row.get("workloadIdentityScope")
    for template in row["policyPaths"]:
        if row["grantedToWorkloads"]:
            matcher = template_pattern(template)
            granting = {
                name for name, stanzas in stanzas_by_policy.items()
                if any(matcher.match(path) and "deny" not in caps and required <= caps for path, caps in stanzas)
            }
            if not granting:
                fail(f"operation {identifier} claims a workload grant on {template} that no generated policy provides")
            if scope is not None:
                allowed = {name for name in stanzas_by_policy if pathlib.Path(name).stem in scope}
                if granting != allowed:
                    fail(f"operation {identifier} grant on {template} must be limited to identities {sorted(scope)}")
            continue
        sample = concrete_path(template)
        for name, stanzas in stanzas_by_policy.items():
            for path, caps in stanzas:
                if "deny" in caps:
                    continue
                if acl_pattern(path).match(sample) and required & caps:
                    fail(f"operation {identifier} is not granted to workloads but {name} grants {sorted(caps)} on {path}")
        mount = row["mount"]
        if mount in {"database", "pki-codestra", "transit-codestra"} or (mount == "sys"):
            for name, stanzas in stanzas_by_policy.items():
                if not any("deny" in caps and acl_pattern(path).match(sample) for path, caps in stanzas):
                    fail(f"operation {identifier} requires an explicit deny in every workload policy; {name} has none")


# --- documentation ------------------------------------------------------------

def validate_document(inputs: Inputs, operations: dict[str, dict[str, Any]]) -> None:
    document = inputs.document
    if not document.strip():
        fail("docs/CODESTRA-SERVICE-API.md is empty")
    documented = []
    for line in document.splitlines():
        match = DOCUMENT_ROW.match(line)
        if match:
            documented.append((match.group("method"), match.group("path"), match.group("category"), match.group("access")))
    expected = [(o["method"], o["path"], o["category"], o["access"]) for o in operations.values()]
    if documented != expected:
        fail("the native operations table in docs/CODESTRA-SERVICE-API.md does not match the contract (method, path, category, access, order)")
    documented_callers = {
        match.group("caller") for match in (DOCUMENT_CALLER_ROW.match(line) for line in document.splitlines()) if match
    }
    missing = set(inputs.authority["callerClasses"]) - documented_callers
    if missing:
        fail(f"docs/CODESTRA-SERVICE-API.md must describe every caller class (missing {sorted(missing)})")
    for required in (
        AUTHORITY_PATH.relative_to(ROOT).as_posix(),
        f"Canonical hostname: `{EXPECTED_HOSTNAME}`",
        "never proxied",
    ):
        if required not in document:
            fail(f"docs/CODESTRA-SERVICE-API.md must mention {required!r}")
    if PRIVATE_KEY in document or SECRET_SIGNATURES.search(document):
        fail("docs/CODESTRA-SERVICE-API.md contains secret-shaped material")


def validate_source_secret_safety(root: pathlib.Path = ROOT) -> None:
    for path in sorted((root / "codestra" / "api").glob("*")):
        if path.suffix == ".md" or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if PRIVATE_KEY in text or SECRET_SIGNATURES.search(text):
            fail(f"secret-shaped material found in {path.relative_to(root).as_posix()}")


def validate_inputs(inputs: Inputs) -> dict[str, int]:
    operations = validate_contract_structure(copy.deepcopy(inputs.contract))
    validate_authority(inputs, operations)
    validate_document(inputs, operations)
    return {
        "operations": len(operations),
        "callerClasses": len(inputs.authority["callerClasses"]),
        "workloadGranted": sum(1 for row in inputs.authority["operations"] if row["grantedToWorkloads"]),
        "mutations": sum(1 for operation in operations.values() if operation["access"] == "mutation"),
    }


def main() -> None:
    try:
        summary = validate_inputs(load_inputs())
        validate_source_secret_safety()
    except ContractError as exc:
        print(f"OPENBAO_SERVICE_CONTRACT_VALIDATION_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
    for key, value in summary.items():
        print(f"OPENBAO_SERVICE_CONTRACT_{key.upper()}={value}")
    print("OPENBAO_SERVICE_CONTRACT_VALIDATION=PASS")


if __name__ == "__main__":
    main()
