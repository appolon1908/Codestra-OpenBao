#!/usr/bin/env python3
"""Restore sanitized JWT test fixtures only in an isolated source-build copy."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/go/jwtfixture/keys_test.go.fixture"
BASELINES = {"builtin/credential/jwt/path_login_test.go":"e6a8b4079061ca0cdb4de44493d0a7f1fe30d6f2cd743f9fedc29ae53c348965","builtin/credential/jwt/path_config_test.go":"4f8647b54a0a6f93fbe6136eb0e5639aa67b7cf29acf60aed29a34e3553a269b"}
LOGIN = "builtin/credential/jwt/path_login_test.go"
CONFIG = "builtin/credential/jwt/path_config_test.go"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def apply(source_root):
    source_root = Path(source_root)
    prepared = {}
    for name, expected in BASELINES.items():
        path = source_root / name
        if any(p.is_symlink() for p in (path,*path.parents)):
            raise ValueError("symlink in isolated test source")
        if path.stat().st_nlink!=1 or sha(path)!=expected:
            raise ValueError("unexpected sanitized test baseline: "+name)
        prepared[name] = path.read_text()
    login = prepared[LOGIN]
    start = login.index("const (\n\tecdsaPrivKey string = ")
    old = login[start:]
    if (old.count("PRIVATE_KEY_TEST_FIXTURE_REMOVED")!=2 or not old.endswith(")\n") or
        "ecdsaPubKey string" not in old or "badPrivKey string" not in old):
        raise ValueError("unexpected sanitized JWT key fixture block")
    prepared[LOGIN] = login[:start] + "var ecdsaPrivKey, ecdsaPubKey, badPrivKey = codestraGeneratedJWTFixtureKeys()\n"
    expected = 'OIDCClientSecret:           "def",'
    if prepared[CONFIG].count(expected)!=1:
        raise ValueError("unexpected sanitized OIDC expected-secret fixture")
    prepared[CONFIG] = prepared[CONFIG].replace(expected,
        'OIDCClientSecret:           "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>",',1)
    target = source_root / "builtin/credential/jwt/codestra_generated_keys_test.go"
    if target.exists() or target.is_symlink():
        raise ValueError("generated test fixture already exists")
    for name, text in prepared.items():
        (source_root/name).write_text(text)
    target.write_bytes(FIXTURE.read_bytes())
    return {"schema_version":1,"test_only":True,"assertions_removed":False,
            "reusable_private_key_material_stored":False,
            "files":{name:{"before":BASELINES[name],"after":sha(source_root/name)} for name in BASELINES},
            "generated_test_helper_sha256":sha(target),"runtime_authorized":False}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source-root",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    args.report.write_text(json.dumps(apply(args.source_root),indent=2,sort_keys=True)+"\n")
    print("OPENBAO_SANITIZED_JWT_TEST_FIXTURES=PASS")

if __name__=="__main__":
    main()
