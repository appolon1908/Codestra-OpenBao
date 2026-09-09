#!/usr/bin/env python3
"""Fail-closed validation for workload inventory and generated authority."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config/workload-secret-authority.v1.json"
INVENTORY = ROOT / "config/policies/workload-identities.v1.json"
GENERATOR_PATH = ROOT / "scripts/generate_workload_authority.py"
SPEC = importlib.util.spec_from_file_location("generate_workload_authority", GENERATOR_PATH)
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)

IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")
ENVIRONMENTS = {"development", "test", "staging", "production"}
EXPECTED_IDENTITIES = {
    "kong-gateway": ("platform-edge", ["kong/"]),
    "middleware-api": ("middleware-platform", ["middleware/api/"]),
    "middleware-worker": (
        "middleware-platform",
        [
            "middleware/worker/email/",
            "middleware/worker/sms/",
            "middleware/worker/social/",
            "middleware/worker/advertising/",
            "middleware/worker/ai/",
            "middleware/worker/telephony/",
            "middleware/worker/crawler/",
        ],
    ),
    "n8n-automation": ("automation-platform", ["n8n/middleware-client/"]),
    "odoo-integration": ("business-integrations", ["odoo/integration/"]),
    "klyrow-email-adapter": ("klyrow-platform", ["middleware/worker/email/klyrow/"]),
    "telnexa-sms-adapter": ("telnexa-platform", ["middleware/worker/sms/telnexa/"]),
    "vicidial-adapter": ("communications-platform", ["middleware/worker/telephony/vicidial/"]),
    "crawler-adapter": ("kyqra-platform", ["middleware/worker/crawler/kyqra/"]),
    "prometheus-openbao": ("observability-platform", ["observability/openbao/metrics-client/"]),
}


def fail(message: str) -> None:
    raise SystemExit(f"OPENBAO_SOURCE_AUTHORITY=FAIL: {message}")


def validate_inventory(inventory: dict) -> None:
    if set(inventory) != {"schemaVersion", "runtimeBindingsAuthorized", "identities", "defaults"}:
        fail("inventory fields drifted")
    if type(inventory["schemaVersion"]) is not int or inventory["schemaVersion"] != 1:
        fail("inventory schema must be integer 1")
    if inventory["runtimeBindingsAuthorized"] is not False:
        fail("inventory runtime bindings must remain unauthorized")
    expected_defaults = {
        "authenticationMethod": "keycloak-jwt",
        "operations": ["read"],
        "tokenTtlSeconds": 300,
        "tokenMaximumTtlSeconds": 300,
        "rotationPolicy": "owner-managed maximum 90 days with tested overlap",
        "revocationProcedure": "revoke auth token accessor and every dynamic child lease; verify subsequent access denial",
        "auditRequired": True,
        "runtimeBindingAuthorized": False,
    }
    if inventory["defaults"] != expected_defaults:
        fail("identity defaults drifted")
    identities = inventory["identities"]
    if not isinstance(identities, list):
        fail("identity list missing")
    by_name = {}
    for identity in identities:
        if set(identity) != {
            "serviceIdentity", "owner", "environments", "namespacePrefixes",
            "purpose", "providerBusinessEffectsEnabled",
        }:
            fail("identity fields drifted")
        name = identity["serviceIdentity"]
        if not isinstance(name, str) or not IDENTITY.fullmatch(name) or name in by_name:
            fail("invalid or duplicate identity")
        by_name[name] = identity
        if identity["providerBusinessEffectsEnabled"] is not False:
            fail("secret authority must not enable business effects")
        environments = identity["environments"]
        if not isinstance(environments, list) or not environments or not set(environments) <= ENVIRONMENTS:
            fail("invalid identity environments")
        if len(environments) != len(set(environments)):
            fail("duplicate identity environment")
        prefixes = identity["namespacePrefixes"]
        if not isinstance(prefixes, list) or not prefixes:
            fail("identity namespace missing")
        for prefix in prefixes:
            if (
                not isinstance(prefix, str)
                or not prefix.endswith("/")
                or prefix.startswith("/")
                or "*" in prefix
                or ".." in prefix
                or "//" in prefix
            ):
                fail("unsafe identity namespace")
    if set(by_name) != set(EXPECTED_IDENTITIES):
        fail("identity coverage drifted")
    for name, (owner, prefixes) in EXPECTED_IDENTITIES.items():
        if by_name[name]["owner"] != owner or by_name[name]["namespacePrefixes"] != prefixes:
            fail(f"identity scope drifted:{name}")


def validate(policy: dict, inventory: dict | None = None) -> None:
    if inventory is None:
        try:
            inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(str(exc))
    validate_inventory(inventory)
    expected = GENERATOR.build_authority(inventory)
    if policy != expected:
        fail("generated workload authority drifted")
    if type(policy.get("schemaVersion")) is not int or policy["schemaVersion"] != 2:
        fail("authority schema must be integer 2")
    if policy["runtimeApplyAuthorized"] is not False or policy["status"] != "PREPARED_DISABLED":
        fail("runtime apply must remain disabled")
    if policy["issuer"] != "https://auth.codestra.co/realms/codestra":
        fail("issuer drift")
    if policy["audience"] != "openbao" or policy["maximumTokenLifetimeSeconds"] > 300:
        fail("workload JWT boundary drift")
    seen = set()
    for role in policy["roles"]:
        key = (role["environment"], role["serviceIdentity"])
        if key in seen:
            fail("duplicate generated role")
        seen.add(key)
        if role["boundClaims"] != {
            "azp": role["serviceIdentity"],
            "codestra_environment": role["environment"],
        }:
            fail("role claim boundary drift")
        if role["operations"] != ["read"] or role["runtimeBindingAuthorized"] is not False:
            fail("role privilege drift")
        if role["providerBusinessEffectsEnabled"] is not False:
            fail("role enables a business effect")
        root = f"codestra/{role['environment']}/"
        if any(not prefix.startswith(root) for prefix in role["pathPrefixes"]):
            fail("cross-environment role path")


def main() -> int:
    try:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))
    validate(policy, inventory)
    print("OPENBAO_SOURCE_AUTHORITY=PASS")
    print("OPENBAO_RUNTIME_APPLY_AUTHORIZED=NO")
    print("PLAINTEXT_SECRET_INJECTION=DISALLOWED")
    print("PROVIDER_BUSINESS_EFFECTS_ENABLED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
