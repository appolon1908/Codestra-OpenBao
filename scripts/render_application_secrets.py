#!/usr/bin/env python3
"""Render reviewed application bindings as one file-only OpenBao Agent bundle."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config/application-secret-catalog.v1.json"
SPEC = importlib.util.spec_from_file_location("agent_renderer", ROOT / "scripts/render_agent_config.py")
assert SPEC and SPEC.loader
AGENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGENT)


def render(identity: str, environment: str, optional: list[str], uid: int, gid: int) -> dict[str, str]:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if catalog["runtimeApplyAuthorized"] is not False or catalog["browserSecretAccess"] is not False:
        raise ValueError("catalog_activation_or_browser_access_forbidden")
    matches = [w for w in catalog["workloads"] if w["serviceIdentity"] == identity]
    if len(matches) != 1:
        raise ValueError("unknown_application_identity")
    workload = matches[0]
    known = {binding["setting"] for binding in workload["bindings"]}
    if len(known) != len(workload["bindings"]) or len(optional) != len(set(optional)):
        raise ValueError("duplicate_binding")
    if set(optional) - known:
        raise ValueError("unregistered_secret_binding")
    selected = [b for b in workload["bindings"] if b["required"] or b["setting"] in optional]
    files, templates, bindings = {}, [], []
    common_config = None
    for binding in selected:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*_FILE", binding["fileEnvironment"]):
            raise ValueError("invalid_file_environment_name")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", binding["secretName"]):
            raise ValueError("invalid_secret_name")
        name = binding["secretName"]
        destination = f"/run/codestra-secrets/{identity}/{name}"
        logical_path = f"codestra/{environment}/{workload['namespacePrefix']}{name}"
        bundle = AGENT.render(environment, identity, logical_path, destination, uid, gid)
        preamble, block = bundle["agent.hcl"].split("\ntemplate {", 1)
        if common_config is not None and common_config != preamble:
            raise ValueError("agent_authentication_drift")
        common_config = preamble
        templates.append("\ntemplate {" + block)
        files.update({key: value for key, value in bundle.items() if key.endswith(".ctmpl")})
        bindings.append({**binding, "logicalSecretPath": logical_path, "destination": destination,
                         "templateInstallPath": json.loads(bundle["manifest.json"])["templateInstallPath"]})
    if not bindings:
        raise ValueError("no_secret_bindings_selected")
    files["agent.hcl"] = common_config + "".join(templates)
    files["consumer.env.example"] = "# File paths only; never place secret values here.\n" + "".join(
        f"{b['fileEnvironment']}={b['destination']}\n" for b in bindings
    )
    files["manifest.json"] = json.dumps({
        "schemaVersion": 1, "serviceIdentity": identity, "environment": environment,
        "repository": workload["repository"], "bindings": bindings,
        "requiredAgentUid": uid, "requiredAgentGid": gid, "fileMode": "0400",
        "destinationDirectoryPrecreatedAndOwnedByServiceRequired": True,
        "secretValuesIncluded": False, "runtimeApplyAuthorized": False,
        "consumerRestartAfterRotationRequired": True,
    }, indent=2) + "\n"
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--environment", required=True, choices=sorted(AGENT.ENVIRONMENTS))
    parser.add_argument("--include", action="append", default=[], help="Optional setting name")
    parser.add_argument("--service-uid", required=True, type=int)
    parser.add_argument("--service-gid", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        bundle = render(args.identity, args.environment, args.include, args.service_uid, args.service_gid)
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, content in bundle.items():
            path = args.output_dir / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o400)
    except (OSError, ValueError, KeyError):
        raise SystemExit("APPLICATION_SECRET_BUNDLE=FAIL") from None
    print("APPLICATION_SECRET_BUNDLE=PASS SECRET_VALUES_INCLUDED=NO RUNTIME_APPLIED=NO")


if __name__ == "__main__":
    main()
