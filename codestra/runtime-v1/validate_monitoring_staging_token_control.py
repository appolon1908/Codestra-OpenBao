#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUSINESSES = (
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
)


def main() -> None:
    data = json.loads((ROOT / "monitoring-staging-token-control.v1.json").read_text())
    assert data["schema_version"] == "1.1"
    assert data["status"] == "SOURCE_PREPARED_NOT_APPLIED"
    assert data["environment"] == "staging"
    assert data["secret_authority"] == "OpenBao"
    assert data["identity_authority"] == "Keycloak"
    client = data["client"]
    assert client == {
        "client_id": "monitoring-readonly",
        "audience": "middleware-api",
        "client_secret_path": "kv-platform/data/observability/middleware/staging/keycloak-client",
        "client_secret_committed_to_git": False,
        "keycloak_source_path": "config/clients/monitoring-readonly.json",
        "scope_claim_mapper": "reviewed-service-scopes",
        "required_returned_scopes": ["health.read", "metrics.read"],
    }
    tokens = data["runtime_tokens"]
    assert len(tokens) == 2
    assert {(item["required_scope"], item["endpoint"]) for item in tokens} == {
        ("metrics.read", "/metrics"),
        ("health.read", "/v1/runtime/safety"),
    }
    assert all(item["maximum_ttl_seconds"] == 300 and item["file_mode"] == "0600" and item["persist_after_evidence"] is False for item in tokens)
    oauth = data["prometheus_oauth2"]
    assert oauth == {
        "uses_client_secret_file": True,
        "requested_scopes": [],
        "scope_claim_authority": "Keycloak hardcoded reviewed-service-scopes mapper",
        "required_returned_scope": "metrics.read",
        "stores_access_token": False,
        "automatic_short_lived_token_refresh": True,
    }
    assert data["evidence_rules"]["returned_scopes_must_be_validated"] is True
    assert all(value is False for value in data["activation"].values())

    policy_path = ROOT / "staging-policies/monitoring-staging-evidence.hcl"
    assert policy_path.is_file()
    assert not (ROOT / "policies/monitoring-staging-evidence.hcl").exists()
    policy = policy_path.read_text()
    assert 'kv-platform/data/observability/middleware/staging/keycloak-client' in policy
    assert 'kv-platform/metadata/observability/middleware/staging/keycloak-client' in policy
    assert policy.count('capabilities = ["read"]') == 3
    assert 'path "kv-*' not in policy

    expected_denies = {
        f"kv-{business}/data/{suffix}"
        for business in BUSINESSES
        for suffix in (
            "providers/*",
            "communications/delivery/*",
            "marketing/provider-write/*",
        )
    }
    expected_denies.add("kv-beyvra/data/execution/*")
    for denied in expected_denies:
        assert f'path "{denied}"' in policy, denied
    assert policy.count('capabilities = ["deny"]') == len(expected_denies) == 40
    print("OPENBAO_MONITORING_STAGING_TOKEN_CONTROL=PASS")


if __name__ == "__main__":
    main()
