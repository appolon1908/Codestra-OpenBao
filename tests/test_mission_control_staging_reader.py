"""No secret values, no write capability and no ungoverned activation."""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_policy_is_exact_read_only_staging():
    item=json.loads((ROOT/"config/staging/mission-control-reader.v1.json").read_text())
    policy=(ROOT/item["policy_file"]).read_text()
    assert item["environment"]=="staging"
    assert item["runtime_apply_authorized"] is False
    assert item["production_go"] is False and item["external_effects_enabled"] is False
    assert item["identity"]["token_max_ttl_seconds"]<=900
    assert item["database_access"]["read_only_transaction"] is True
    assert item["database_access"]["permissions"] == ["CONNECT","SELECT"]
    assert item["activation"]["staging_go"] is False
    assert item["activation"]["requires_approval"] is True
    assert policy.count('path "')==1
    assert item["secret_path"] in policy
    assert 'capabilities = ["read"]' in policy
    assert 'capabilities = ["create"' not in policy
    assert 'capabilities = ["update"' not in policy
    assert '"token":' not in json.dumps(item)
    assert '"password":' not in json.dumps(item)
