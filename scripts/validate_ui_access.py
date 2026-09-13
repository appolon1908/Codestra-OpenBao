#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config/ui-access.v1.json"


def main() -> None:
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert data["schema"] == "codestra.ui-access.v1"
    assert data["service"] == "openbao"
    assert data["canonical_host"] == "bao.codestra.media"

    human = data["human_access"]
    assert human["mode"] == "native-openbao-oidc"
    assert human["identity_provider"] == "Keycloak"
    assert human["oidc_client_id"] == "openbao-secrets"
    assert human["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert human["login_theme"] == "codestra-identity"
    assert human["visual_base"] == "codestra"
    assert human["credentials_collected_by"] == "Keycloak"
    assert human["local_password_form"] is False
    assert human["mfa_required"] is True
    assert human["required_roles"] == ["secrets-operator", "secrets-admin"]
    assert human["network_gate"] == "source-network-allowlist"

    machine = data["machine_access"]
    assert machine["mode"] == "scoped-workload-identity"
    assert machine["browser_tokens"] is False
    assert machine["native_api_public"] is False

    runtime = data["runtime"]
    assert runtime["activation_authorized"] is False
    assert runtime["native_port_public"] is False

    print("CODESTRA_OPENBAO_UI_ACCESS=PASS")


if __name__ == "__main__":
    main()
