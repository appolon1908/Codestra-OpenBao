from __future__ import annotations
import copy, importlib.util, json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("validate_mcr",ROOT/"scripts/validate_mcr_secrets.py")
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
BASE=json.loads((ROOT/"config/contracts/mcr-secrets.v1.json").read_text())

def test_canonical_contract_passes():
    mod.validate(copy.deepcopy(BASE))

def test_production_grant_activation_fails():
    data=copy.deepcopy(BASE)
    data["grants"]["production"]["middleware-api"]=[data["paths"]["production"]["middleware_cursor_signing_key"]]
    with pytest.raises(ValueError,match="production MCR grants"):
        mod.validate(data)

def test_cross_producer_secret_access_fails():
    data=copy.deepcopy(BASE)
    data["grants"]["staging"]["klyrow-gateway"]=[data["paths"]["staging"]["telnexa_webhook_hmac"]]
    with pytest.raises(ValueError,match="klyrow-gateway"):
        mod.validate(data)

def test_n8n_secret_access_fails():
    data=copy.deepcopy(BASE)
    data["grants"]["staging"]["n8n-automation"]=[data["paths"]["staging"]["middleware_cursor_signing_key"]]
    with pytest.raises(ValueError,match="n8n"):
        mod.validate(data)

def test_wildcard_path_fails():
    data=copy.deepcopy(BASE)
    data["paths"]["staging"]["middleware_cursor_signing_key"]="codestra/staging/middleware/mcr/*"
    with pytest.raises(ValueError,match="wildcard"):
        mod.validate(data)
