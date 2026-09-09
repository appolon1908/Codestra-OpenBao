#!/usr/bin/env python3
"""Generate CEL JWT roles with exact claims, lifetime and least-privilege policy."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = ROOT / "config/workload-secret-authority.v1.json"
AUTH_CONFIG = ROOT / "config/auth/keycloak-jwt.v1.json"
OUTPUT = ROOT / "openbao/auth/jwt-roles.v1.json"


def expression(role: dict) -> str:
    identity = role["serviceIdentity"]
    environment = role["environment"]
    policy = f"workload-{identity}-{environment}"
    conditions = [
        "'iss' in claims",
        "'sub' in claims",
        "'aud' in claims",
        "'azp' in claims",
        "'iat' in claims",
        "'exp' in claims",
        "'jti' in claims",
        "'codestra_environment' in claims",
        "claims.iss == 'https://auth.codestra.co/realms/codestra'",
        f"claims.azp == '{identity}'",
        f"claims.codestra_environment == '{environment}'",
        "(claims.aud == 'openbao' || (type(claims.aud) == list && 'openbao' in claims.aud))",
        "string(claims.sub).size() > 0",
        "string(claims.jti).size() > 0",
        "int(claims.iat) > 0",
        "int(claims.exp) > int(claims.iat)",
        "int(claims.exp) - int(claims.iat) <= 300",
    ]
    auth = (
        "pb.Auth{"
        f"display_name: '{identity}-{environment}', "
        f"policies: ['{policy}'], "
        "lease_options: pb.LeaseOptions{TTL: 300000000000, renewable: true, "
        "issue_time: now, MaxTTL: 300000000000}, "
        "explicit_max_ttl: 300000000000, "
        "no_default_policy: true"
        "}"
    )
    return " && ".join(conditions) + f" ? {auth} : false"


def build(authority: dict, auth_config: dict) -> dict:
    roles = []
    for role in authority["roles"]:
        name = f"{role['serviceIdentity']}-{role['environment']}"
        roles.append(
            {
                "name": name,
                "endpoint": f"auth/{auth_config['mount']}/cel/role/{name}",
                "payload": {
                    "cel_program": {"expression": expression(role)},
                    "message": "Codestra workload JWT rejected",
                    "clock_skew_leeway": auth_config["clockSkewLeewaySeconds"],
                    "expiration_leeway": auth_config["expirationLeewaySeconds"],
                    "not_before_leeway": auth_config["notBeforeLeewaySeconds"],
                    "bound_audiences": [auth_config["boundAudience"]],
                },
                "runtimeApplyAuthorized": False,
            }
        )
    return {
        "schemaVersion": 1,
        "status": "PREPARED_DISABLED",
        "mount": auth_config["mount"],
        "authPlugin": auth_config["authPluginManifest"],
        "mountConfiguration": {
            "oidc_discovery_url": auth_config["discoveryUrl"],
            "bound_issuer": auth_config["boundIssuer"],
            "default_role": "",
            "jwt_supported_algs": ["RS256"],
        },
        "requiredClaims": auth_config["requiredClaims"],
        "maximumJwtLifetimeSeconds": auth_config["maximumJwtLifetimeSeconds"],
        "jtiReplayCacheRequired": auth_config["jtiReplayCacheRequired"],
        "jtiReplayCacheImplemented": auth_config["jtiReplayCacheImplemented"],
        "runtimeApplyAuthorized": False,
        "roles": sorted(roles, key=lambda role: role["name"]),
    }


def main() -> None:
    authority = json.loads(AUTHORITY.read_text(encoding="utf-8"))
    auth_config = json.loads(AUTH_CONFIG.read_text(encoding="utf-8"))
    OUTPUT.write_text(json.dumps(build(authority, auth_config), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
