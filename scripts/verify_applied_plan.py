#!/usr/bin/env python3
"""Read back every applied plan operation without reading secret values."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

DURATION = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?")


def command(*args: str) -> str:
    result = subprocess.run(["bao", *args], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError("readback_command_failed:" + args[0])
    return result.stdout


def json_command(*args: str):
    return json.loads(command(*args, "-format=json"))


def data(value):
    return value.get("data", value) if isinstance(value, dict) else value


def semantic(value):
    """OpenBao stores durations normalized ("2160h" reads back as "2160h0m0s")."""
    if isinstance(value, str) and value:
        match = DURATION.fullmatch(value)
        if match and any(match.groups()):
            hours, minutes, seconds = match.groups()
            return ("duration", int(hours or 0) * 3600 + int(minutes or 0) * 60 + float(seconds or 0))
    return value


def selected(mapping: dict, keys) -> dict:
    return {key: semantic(mapping.get(key)) for key in keys}


def verify(operation: dict) -> None:
    kind = operation["kind"]
    name = operation["name"]
    payload = operation["payload"]
    if kind == "auth_plugin":
        item = data(json_command(
            "plugin", "info", f"-version={payload['version']}", "auth", payload["name"]
        ))
        expected = selected(payload, ("name", "command", "version", "sha256"))
        if selected(item, tuple(expected)) != expected or item.get("builtin") is not False:
            raise ValueError("auth_plugin_readback_mismatch")
    elif kind == "secret_engine":
        mounts = data(json_command("secrets", "list"))
        item = mounts.get(name)
        if not item or item.get("type") != "kv" or (item.get("options") or {}).get("version") != "2":
            raise ValueError("secret_engine_readback_mismatch")
    elif kind == "secret_engine_config":
        actual = data(json_command("read", name))
        keys = tuple(payload)
        if selected(actual, keys) != selected(payload, keys):
            raise ValueError("secret_engine_config_readback_mismatch:" + name)
    elif kind == "auth_method":
        auths = data(json_command("auth", "list"))
        item = auths.get(name)
        if (
            not item
            or item.get("type") != payload["plugin_name"]
            or item.get("plugin_version") != payload["plugin_version"]
            or item.get("running_plugin_version") != payload["plugin_version"]
            or item.get("running_sha256") != payload["plugin_sha256"]
        ):
            raise ValueError("auth_method_readback_mismatch")
    elif kind == "policy":
        if command("policy", "read", name).strip() != payload["policy"].strip():
            raise ValueError("policy_readback_mismatch:" + name)
    elif kind in {"auth_config", "jwt_role"}:
        actual = data(json_command("read", name))
        keys = tuple(payload)
        if selected(actual, keys) != selected(payload, keys):
            raise ValueError(kind + "_readback_mismatch:" + name)
    else:
        raise ValueError("unknown_plan_kind:" + str(kind))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_applied_plan.py PLAN.json")
    try:
        plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        for operation in plan["operations"]:
            verify(operation)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"PLAN_APPLIED_EXACTLY=false ERROR={exc}") from exc
    print("PLAN_APPLIED_EXACTLY=true")
    print(f"PLAN_DESTROY_COUNT={plan['counts']['destroy']}")


if __name__ == "__main__":
    main()
