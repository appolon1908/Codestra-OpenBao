#!/usr/bin/env python3
"""Offline MCR-I reference validation and inert KV-v2 reader policy generation.

This module never authenticates, fetches secrets, or applies policies. Identity
and ownership arguments to authorize() must come from trusted server-side
sources, not from a caller's reference. Runtime registration remains separate.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "config/mcr-secret-contract.v1.json"
DEFAULT_OUTPUT = ROOT / "config/mcr/policies"
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")

# Class-specific consumer, accountable owner, pending registration, and path.
# New execution/signing identities are deliberately not policy-generatable.
PROVIDER_ADAPTER_SERVICES = {
    "email": "klyrow-email-adapter",
    "sms": "telnexa-sms-adapter",
    "whatsapp": "evolution-whatsapp-adapter",
    "voice": "vicidial-voice-adapter",
}

CLASSES = {
    "sender-smtp": (
        "klyrow-email-executor", "klyrow", True, ("sender",),
        "middleware/worker/email/klyrow/tenants/{tenant}/senders/{sender}/smtp"),
    "sender-provider-api": (
        "klyrow-email-executor", "klyrow", True, ("sender", "provider"),
        "middleware/worker/email/klyrow/tenants/{tenant}/senders/{sender}/providers/{provider}/api"),
    "sender-domain-signing": (
        "klyrow-domain-signer", "klyrow", True, ("brand", "domain"),
        "klyrow/signing/tenants/{tenant}/brands/{brand}/domains/{domain}/signing"),
    "provider-adapter": (
        None, "middleware-platform", True, ("channel", "provider"),
        "{service}/channels/{channel}/tenants/{tenant}/providers/{provider}/adapter"),
    "service-auth": (
        "n8n-automation", "automation-platform", False, ("client", "target"),
        "n8n/middleware-client/tenants/{tenant}/clients/{client}/targets/{target}/auth"),
    "callback-verification": (
        "middleware-api", "middleware-platform", False, ("provider",),
        "middleware/api/tenants/{tenant}/providers/{provider}/callback-verification"),
}

# Fixed version-1 requirements are intentionally closed and fail closed. These
# are offline assertions, not a duplicate deployable PAS-239 auth configuration.
REQUIREMENTS = {
    "authority": {
        "issue": "PAS-239", "identity_registration": "MCR-H",
        "workloads": "config/workload-secret-authority.v1.json",
        "auth": "config/auth/keycloak-jwt.v1.json",
        "engines": "config/secrets/engines.v1.json",
        "audit": "config/audit/audit.v1.json",
        "recovery": "config/recovery/backup.v1.json",
    },
    "auth": {
        "mount": "jwt-codestra", "issuer": "https://auth.codestra.co/realms/codestra",
        "audience": "openbao", "algorithm": "RS256",
        "signature_required": True, "exact_azp_required": True,
        "service_account_subject_required": True, "environment_binding_required": True,
        "tenant_binding_required": True, "iat_required": True, "exp_required": True,
        "jti_required": True, "nbf_validated_when_present": True,
        "replay_rejected": True, "replay_storage_fail_closed": True,
        "default_policy_enabled": False, "human_sessions_allowed": False,
        "static_root_token_allowed": False, "broad_token_fallback_allowed": False,
        "separate_bootstrap_required": True,
    },
    "delivery": {
        "method": "agent-rendered-file", "file_mode": "0400",
        "service_owned": True, "private_tmpfs": True, "atomic_replace": True,
        "environment_values_allowed": False, "image_values_allowed": False,
        "repository_values_allowed": False, "queue_values_allowed": False,
        "api_response_values_allowed": False, "telemetry_values_allowed": False,
        "missing_expired_revoked_fail_closed": True, "stale_cache_allowed": False,
        "static_kv_rerender_on_change": True,
    },
    "rotation": {
        "owner_required": True, "cas_next_version": True,
        "bounded_overlap": True, "atomic_reload": True,
        "metadata_only_readback": True, "effects_disabled_acceptance": True,
        "provider_revocation": True, "old_version_denial_proven": True,
        "new_version_health_proven": True, "unrelated_tenant_health_proven": True,
        "sender_identity_preserved": True, "suppression_preserved": True,
    },
    "revocation": {
        "exact_provider_or_client_disabled": True, "tokens_revoked": True,
        "dynamic_child_leases_revoked": True, "rendered_cache_invalidated": True,
        "affected_dispatch_halted": True, "subsequent_denial_verified": True,
        "kv_deletion_alone_sufficient": False, "business_authorization_implied": False,
    },
    "audit": {
        "format": "json", "file_mode": "0600", "raw_logging": False,
        "accessor_hmac": True, "availability_required": True,
        "allowlisted_metadata_only": True, "alloy_loki_redaction": True,
        "auth_and_tenant_denials": True, "rotation_and_revocation": True,
        "audit_sealed_auth_replay_expiry_rotation_backup_policy_alerts": True,
    },
    "readback": {
        "exact_artifact_hashes": True, "auth_role_verified": True,
        "kv_v2_verified": True, "admitted_consumer_resolution": True,
        "foreign_scope_denials": True, "secret_bytes_exposed": False,
        "provider_writes": False,
    },
    "recovery": {
        "encrypted_checksummed_backups": True, "off_host_immutable": True,
        "custody_verified": True, "isolated_restore": True,
        "rpo_hours": 24, "rto_hours": 4, "maximum_backup_age_hours": 26,
        "post_snapshot_revocations_reconciled": True, "retired_access_revived": False,
    },
    "rollback": {
        "exact_prior_artifacts": True, "data_and_custody_preserved": True,
        "consumer_reload_tested": True, "valid_overlap_required": True,
        "revoked_or_compromised_version_allowed": False,
        "audit_alerts_and_denials_verified": True,
    },
    "readiness": {
        "requirements": {
            "custody_ceremony_required": True, "reinitialize_existing_storage": False,
            "fresh_evidence_required": True, "separate_production_approval": True,
        },
        "evidence": {
            "existing_storage_inventory": False, "bootstrap_root_revocation_evidence": False,
            "approved_unseal_custody": False, "protected_tls_network_storage": False,
            "sealed_state_blocks_access": False, "exact_supply_chain_evidence": False,
            "current_runtime_vulnerability_gate": False,
        },
    },
    "gates": {
        "runtime_apply": False, "provider_effects": False, "initialization": False,
        "unseal": False, "production": False, "readback": False,
        "recovery": False, "rollback": False, "supply_chain": False,
    },
}
AUTH_LIMITS = {
    "token_ttl_seconds": (1, 300), "token_max_ttl_seconds": (30, 300),
    "jwt_max_ttl_seconds": (1, 300), "clock_skew_seconds": (0, 30),
}
BINDING_FIELDS = {
    "schema_version", "id", "environment", "tenant", "service", "credential_class",
    "owner", "scope", "logical_path", "reference", "field", "version",
    "registration_required", "audit_required", "lifecycle",
}
LIFECYCLE_FIELDS = {
    "rotation_days", "provider_limit_days", "overlap_seconds",
    "secret_lease_seconds", "renewable_secret",
}


class ContractError(ValueError):
    """Rejected input; error text must never include the input."""


def require(condition):
    if not condition:
        raise ContractError("MCR contract rejected")


def closed(value, fields):
    require(type(value) is dict and value.keys() == set(fields))


def exact(value, expected):
    require(type(value) is type(expected))
    if isinstance(expected, dict):
        require(value.keys() == expected.keys())
        for key in expected:
            exact(value[key], expected[key])
        return
    if isinstance(expected, list):
        require(len(value) == len(expected))
        for actual, wanted in zip(value, expected):
            exact(actual, wanted)
        return
    require(value == expected)


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)


def slug(value):
    require(type(value) is str and SLUG.fullmatch(value) is not None)


@dataclass(frozen=True)
class WorkloadIdentity:
    environment: str
    tenant: str
    service: str


@dataclass(frozen=True)
class SecretReference:
    id: str
    environment: str
    tenant: str
    service: str
    credential_class: str
    owner: str
    scope: tuple
    logical_path: str
    field: str
    version: int
    registration_required: bool

    @property
    def data_path(self):
        return "codestra/data/" + self.logical_path.removeprefix("codestra/")

    @property
    def policy_name(self):
        return "mcr-" + self.id


def validate(contract):
    """Validate a closed v1 contract and return immutable reference records."""
    closed(contract, {"schema_version", "bindings", *REQUIREMENTS})
    exact(contract["schema_version"], 1)
    for section, expected in REQUIREMENTS.items():
        value = contract[section]
        fields = set(expected) | (set(AUTH_LIMITS) if section == "auth" else set())
        closed(value, fields)
        for key, required in expected.items():
            exact(value[key], required)
    auth = contract["auth"]
    for key, bounds in AUTH_LIMITS.items():
        integer(auth[key], *bounds)
    require(auth["token_ttl_seconds"] <= auth["token_max_ttl_seconds"])
    bindings = contract["bindings"]
    require(type(bindings) is list and bool(bindings))
    refs, ids, paths = [], set(), set()
    for binding in bindings:
        closed(binding, BINDING_FIELDS)
        exact(binding["schema_version"], 1)
        for key in ("id", "tenant", "service", "owner", "field", "credential_class", "environment"):
            slug(binding[key])
        require(binding["environment"] in ("development", "test", "staging", "production"))
        require(binding["credential_class"] in CLASSES)
        service, owner, pending, scopes, template = CLASSES[binding["credential_class"]]
        if service is not None:
            exact(binding["service"], service)
        elif binding["credential_class"] == "provider-adapter":
            channel = binding["scope"].get("channel")
            require(type(channel) is str and channel in PROVIDER_ADAPTER_SERVICES)
            exact(binding["service"], PROVIDER_ADAPTER_SERVICES[channel])
        exact(binding["owner"], owner)
        exact(binding["registration_required"], pending)
        exact(binding["audit_required"], True)
        closed(binding["scope"], scopes)
        for value in binding["scope"].values():
            slug(value)
        if binding["credential_class"] == "service-auth":
            exact(binding["scope"]["client"], service)
            exact(binding["scope"]["target"], "middleware")
        integer(binding["version"], 1, 2**63 - 1)
        path = "codestra/" + binding["environment"] + "/" + template.format(
            tenant=binding["tenant"], service=binding["service"], **binding["scope"])
        exact(binding["logical_path"], path)
        # Canonical equality is a full match, including version and field;
        # it admits neither alternate mounts nor URL query/encoding tricks.
        exact(binding["reference"], f"openbao://{path}#{binding['field']}@{binding['version']}")
        lifecycle = binding["lifecycle"]
        closed(lifecycle, LIFECYCLE_FIELDS)
        integer(lifecycle["rotation_days"], 1, 90)
        integer(lifecycle["provider_limit_days"], 1, 90)
        require(lifecycle["rotation_days"] <= lifecycle["provider_limit_days"])
        integer(lifecycle["overlap_seconds"], 1, 86400)
        exact(lifecycle["secret_lease_seconds"], 0)
        exact(lifecycle["renewable_secret"], False)
        require(binding["id"] not in ids and path not in paths)
        ids.add(binding["id"])
        paths.add(path)
        refs.append(SecretReference(
            binding["id"], binding["environment"], binding["tenant"], binding["service"],
            binding["credential_class"], owner, tuple(sorted(binding["scope"].items())),
            path, binding["field"], binding["version"], pending))
    return refs


def authorize(ref, identity, ownership):
    """Offline scope/ownership check, not JWT verification or send authority.

    ownership must contain validated server-side records; identity must have
    already been verified by the accepted workload authentication authority.
    """
    require(isinstance(ref, SecretReference) and isinstance(identity, WorkloadIdentity))
    require(not ref.registration_required)
    require(identity == WorkloadIdentity(ref.environment, ref.tenant, ref.service))
    require(ref in ownership)
    return ref


def policy_grants(ref):
    require(isinstance(ref, SecretReference) and not ref.registration_required)
    return {ref.data_path: ["read"]}


def validate_policy_composition(ref, policies):
    """Require the union of all supplied ACL grants to be the exact reader ACL."""
    expected = policy_grants(ref)
    require(type(policies) is list and bool(policies))
    effective = {}
    for policy in policies:
        require(type(policy) is dict)
        for path, capabilities in policy.items():
            require(type(path) is str and path in expected)
            require(type(capabilities) is list and bool(capabilities))
            require(all(type(cap) is str and cap == "read" for cap in capabilities))
            effective.setdefault(path, set()).update(capabilities)
    require(effective == {path: set(caps) for path, caps in expected.items()})


def generate(contract):
    """Return deterministic inert HCL artifacts; pending identities get none.

    KV-v2 ACLs scope objects, not individual fields or immutable versions.
    The resolver must enforce the validated version/field during integration.
    """
    artifacts = {}
    for ref in sorted(validate(contract), key=lambda item: item.policy_name):
        if ref.registration_required:
            continue
        grants = policy_grants(ref)
        validate_policy_composition(ref, [grants])
        artifacts[ref.policy_name + ".hcl"] = (
            "# Generated by scripts/mcr_contract.py; offline source only.\n"
            "# Applying this policy requires separate runtime approval.\n"
            f'path "{ref.data_path}" {{\n  capabilities = ["read"]\n}}\n'
        )
    return artifacts


def check_generated(contract, directory):
    expected = generate(contract)
    directory = Path(directory)
    try:
        require(directory.is_dir() and not directory.is_symlink())
        require({path.name for path in directory.iterdir()} == set(expected))
        for name, content in expected.items():
            path = directory / name
            require(not path.is_symlink() and path.is_file())
            require(path.read_bytes() == content.encode("utf-8"))
    except OSError:
        raise ContractError("MCR contract rejected") from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def reject_constant(_value):
    raise ContractError("MCR contract rejected")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "generate", "check-generated"))
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_object, parse_constant=reject_constant)
        refs = validate(contract)
        if args.command == "generate":
            artifacts = generate(contract)
            require(not args.output.is_symlink())
            args.output.mkdir(parents=True, exist_ok=True)
            # Never delete unexpected files or write through output symlinks.
            require(all(p.is_file() and not p.is_symlink() and p.name in artifacts
                        for p in args.output.iterdir()))
            for name, content in artifacts.items():
                (args.output / name).write_bytes(content.encode("utf-8"))
            check_generated(contract, args.output)
        elif args.command == "check-generated":
            check_generated(contract, args.output)
    except (ContractError, ValueError, OSError, RecursionError):
        print("MCR contract rejected", file=sys.stderr)
        return 1
    print(f"MCR {args.command} OK ({len(refs)} references)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
