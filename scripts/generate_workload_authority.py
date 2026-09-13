#!/usr/bin/env python3
"""Generate the canonical fail-closed workload authority from reviewed inventory."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "config/policies/workload-identities.v1.json"
OUTPUT = ROOT / "config/workload-secret-authority.v1.json"


def build_authority(inventory: dict) -> dict:
    defaults = inventory["defaults"]
    roles = []
    for identity in inventory["identities"]:
        name = identity["serviceIdentity"]
        for environment in identity["environments"]:
            roles.append(
                {
                    "environment": environment,
                    "serviceIdentity": name,
                    "owner": identity["owner"],
                    "purpose": identity["purpose"],
                    "authenticationMethod": defaults["authenticationMethod"],
                    "boundClaims": {
                        "azp": name,
                        "codestra_environment": environment,
                    },
                    "pathPrefixes": [
                        f"codestra/{environment}/{prefix}"
                        for prefix in identity["namespacePrefixes"]
                    ],
                    "operations": defaults["operations"],
                    "tokenTtlSeconds": defaults["tokenTtlSeconds"],
                    "tokenMaximumTtlSeconds": defaults["tokenMaximumTtlSeconds"],
                    "rotationPolicy": defaults["rotationPolicy"],
                    "revocationProcedure": defaults["revocationProcedure"],
                    "auditRequired": defaults["auditRequired"],
                    "runtimeBindingAuthorized": defaults["runtimeBindingAuthorized"],
                    "providerBusinessEffectsEnabled": identity["providerBusinessEffectsEnabled"],
                }
            )
    roles.sort(key=lambda role: (role["environment"], role["serviceIdentity"]))
    environment_roots = [
        f"codestra/{environment}/"
        for environment in ("development", "test", "staging", "production")
    ]
    return {
        "schemaVersion": 2,
        "status": "PREPARED_DISABLED",
        "runtimeApplyAuthorized": False,
        "identitySource": "config/policies/workload-identities.v1.json",
        "issuer": "https://auth.codestra.co/realms/codestra",
        "authMethod": "jwt",
        "audience": "openbao",
        "requiredClaims": [
            "iss", "sub", "aud", "azp", "iat", "exp", "jti", "codestra_environment"
        ],
        "maximumTokenLifetimeSeconds": 300,
        "clockSkewLeewaySeconds": 30,
        "defaultPolicy": "deny",
        "secretInjection": {
            "method": "agent-rendered-file",
            "environmentVariablesAllowed": False,
            "containerImageBakeAllowed": False,
            "gitMaterializationAllowed": False,
            "fileMode": "0400",
            "atomicReplacementRequired": True,
            "missingSecretFailsStartup": True,
            "staticKvSecretLeaseRenewalRequired": False,
            "staticKvRerenderOnChangeRequired": True,
            "agentAuthTokenRenewalRequired": True,
            "dynamicSecretLeaseRenewalRequired": True,
            "dynamicSecretRevocationOnShutdownRequired": True,
        },
        "rotation": {
            "ownerRequired": True,
            "maximumAgeDays": 90,
            "overlapRequired": True,
            "revocationTestRequired": True,
            "auditEventRequired": True,
        },
        "roles": roles,
        "explicitDeny": {
            "n8n-automation": [
                root + suffix
                for root in environment_roots
                for suffix in (
                    "middleware/worker/", "klyrow/", "telnexa/", "vicidial/", "beyvra/"
                )
            ],
            "observability-general": environment_roots,
        },
        "businessEffectGates": {
            "liveEmailDelivery": False,
            "liveSmsDelivery": False,
            "productionDialing": False,
            "callbackDispatch": False,
            "odooWrite": False,
            "n8nExternalEffects": False,
            "socialPublishing": False,
            "advertisingSpend": False,
            "aiProviderMutations": False,
            "tradingActions": False,
            "payments": False,
        },
        "requiredEvidence": sorted(
            {
                "agent_auth_token_accessor_hash",
                "audit_event",
                "dynamic_lease_id_hash_if_applicable",
                "policy_name",
                "role_name",
                "sanitized_path_prefix",
                "secret_version",
                "service_identity",
            }
        ),
    }


def main() -> None:
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    OUTPUT.write_text(json.dumps(build_authority(inventory), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
