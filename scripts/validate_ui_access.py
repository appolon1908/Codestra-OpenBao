import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "config/ui-access.v1.json").read_text())
assert data["schema"] == "codestra.ui-access.v1"
assert data["human_access"]["identity_provider"] == "Keycloak"
assert data["human_access"]["login_theme"] == "codestra"
assert data["human_access"]["local_password_form"] is False
assert data["machine_access"]["native_api_public"] is False
assert data["human_access"]["required_roles"] == ["secrets-operator", "secrets-auditor"]
print("CODESTRA_OPENBAO_UI_ACCESS=PASS")
