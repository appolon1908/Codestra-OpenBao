#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CONTRACT=ROOT/"config/contracts/mcr-secrets.v1.json"
PRODUCERS={"klyrow-gateway","telnexa-gateway","odoo-integration","vicidial-adapter"}

def validate(data: dict) -> None:
    if data.get("schema_version")!="1.0" or data.get("mission")!="MCR-I":
        raise ValueError("MCR secret contract identity drift")
    if data.get("production_authorized") is not False:
        raise ValueError("production MCR secret access must remain disabled")
    if data.get("provider_effects_enabled") is not False:
        raise ValueError("provider effects must remain disabled")
    if data.get("secret_values_in_git") is not False:
        raise ValueError("Git may not contain MCR secret values")
    paths=data.get("paths",{})
    grants=data.get("grants",{})
    for env in ("staging","production"):
        prefix=f"codestra/{env}/"
        env_paths=set(paths.get(env,{}).values())
        if not env_paths or any(not p.startswith(prefix) for p in env_paths):
            raise ValueError(f"{env}: invalid environment path")
        if any("*" in p for p in env_paths):
            raise ValueError(f"{env}: wildcard secret path forbidden")
        for identity, refs in grants.get(env,{}).items():
            if any(ref not in env_paths for ref in refs):
                raise ValueError(f"{env}:{identity}: unknown secret ref")
    if any(grants["production"].values()):
        raise ValueError("production MCR grants must remain empty")
    if grants["staging"].get("n8n-automation") != []:
        raise ValueError("n8n must not receive MCR signing secrets")
    for producer in PRODUCERS:
        refs=grants["staging"].get(producer)
        expected=f"codestra/staging/middleware/mcr/webhooks/{producer}"
        if refs != [expected]:
            raise ValueError(f"{producer}: producer must read only its own webhook key")
    middleware=set(grants["staging"].get("middleware-api",[]))
    if set(paths["staging"].values()) != middleware:
        raise ValueError("middleware-api must read exactly the staging MCR verifier/cursor refs")
    req=data.get("requirements",{})
    if req.get("cursor_key_minimum_bytes",0) < 32 or req.get("webhook_hmac_minimum_bytes",0) < 32:
        raise ValueError("MCR signing material minimum length drift")

def main() -> int:
    validate(json.loads(CONTRACT.read_text()))
    print("MCR_OPENBAO_SECRET_CONTRACT=PASS")
    print("MCR_PRODUCTION_SECRET_GRANTS=0")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
