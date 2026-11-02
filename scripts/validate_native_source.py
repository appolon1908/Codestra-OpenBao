"""Offline checks for the governance-only main tree; never runtime certification."""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate object key")
        value[key] = item
    return value


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    return unique_object((loader.construct_object(k), loader.construct_object(v))
                         for k, v in node.value)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def invalid_constant(_value):
    raise ValueError("nonfinite JSON value")


def validate_file(path):
    require(path.is_file() and not path.is_symlink(), "nonregular source file")
    if path.suffix == ".json":
        return json.loads(path.read_text(), object_pairs_hook=unique_object,
                          parse_constant=invalid_constant)
    if path.suffix in {".yml", ".yaml"}:
        return yaml.load(path.read_text(), Loader=UniqueLoader)
    if path.suffix == ".py":
        ast.parse(path.read_text(), filename=str(path))
    if path.suffix == ".sh":
        subprocess.run(["bash", "-n", str(path)], check=True, capture_output=True)


def validate_identity(root, base, head):
    require(SHA.fullmatch(base) and SHA.fullmatch(head), "full commit identities required")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(actual == head, "checkout differs from candidate")
    subprocess.run(["git", "cat-file", "-e", base + "^{commit}"], cwd=root,
                   check=True, capture_output=True)
    subprocess.run(["git", "diff", "--check", base, head, "--"], cwd=root,
                   check=True, capture_output=True)
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--"], cwd=root,
                   check=True, capture_output=True)


def validate_workflow(workflow):
    require(isinstance(workflow, dict), "workflow must be an object")
    require(workflow.get("permissions") == {"contents": "read"}, "source workflow must be read-only")
    require(not re.search(r"\bsecrets(?:\.|\s*\[)", json.dumps(workflow)),
            "source workflow must not consume secrets")
    events = workflow.get("on", workflow.get(True))
    require(isinstance(events, dict) and events and
            set(events) <= {"pull_request", "push", "workflow_dispatch"}, "unsafe source event")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict) and jobs, "missing source jobs")
    for job in jobs.values():
        require(job.get("runs-on") == "ubuntu-24.04", "source job must use hosted runner")
        require(not any(k in job for k in ("environment", "permissions", "continue-on-error", "if")),
                "source job changes authority")
        for step in job.get("steps", []):
            require(not any(k in step for k in ("continue-on-error", "if")), "source failure suppression")
            action = step.get("uses")
            if action:
                require(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", action), "unpinned source action")
            if action and action.startswith("actions/checkout@"):
                require(step.get("with", {}).get("persist-credentials") is False,
                        "checkout credentials must not persist")
            command = step.get("run", "")
            require(not re.search(r"\bgit\s+(?:[^\n]*\s)?push\b|--force\b|codestra-github-check", command),
                    "source workflow cannot push refs or call installed controller")


SAFETY_PATHS = ("CODESTRA_UPSTREAM.json", ".governance/authority.json",
                ".governance/repository.yaml", ".governance/workstation-policy.yaml",
                ".codestra/workstation-policy.json", "governance/promotion-policy.json",
                "monitoring-integration.v1.json")


def safety_documents(root):
    return {name: validate_file(root / name) for name in SAFETY_PATHS}


def validate_safety(documents):
    disabled = {
        "CODESTRA_UPSTREAM.json": ("deployment_enabled", "secret_material_allowed_in_git"),
        ".governance/authority.json": ("allow_force_push", "allow_production_effects"),
        ".governance/repository.yaml": ("production_effects_allowed",),
        ".governance/workstation-policy.yaml": ("allow_force_push", "allow_direct_protected_branch_development", "allow_production_effects"),
        "monitoring-integration.v1.json": ("activation_enabled",),
    }
    for path, fields in disabled.items():
        require(all(documents[path].get(key) is False for key in fields), "production or source-write safeguard changed")
    expected = {"PRODUCTION_GO": "NO", "LIVE_CAPABILITIES_ENABLED": "NO", "EXTERNAL_EFFECTS": False}
    require(documents[".codestra/workstation-policy.json"].get("production_defaults") == expected,
            "workstation production defaults changed")
    expected["EXTERNAL_EFFECTS"] = "false"
    require(documents["governance/promotion-policy.json"].get("production_defaults") == expected,
            "promotion production defaults changed")
    record = documents["monitoring-integration.v1.json"]
    require(record.get("repository") == "appolon1908/Codestra-OpenBao" and
            record.get("repository_id") == 1350795432 and record.get("runtime_coverage") == "unverified",
            "monitoring identity or runtime claim changed")


def validate_source(root):
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    for relative in filter(None, paths):
        path = root / relative
        if path.suffix in {".json", ".yaml", ".yml", ".py", ".sh"}:
            value = validate_file(path)
            if relative.startswith(".github/workflows/"):
                validate_workflow(value)
    validate_safety(safety_documents(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()
    validate_identity(ROOT, args.base_sha, args.head_sha)
    validate_source(ROOT)
    print("OPENBAO_GOVERNANCE_SOURCE=PASS")
    print("RUNTIME_CERTIFICATION=NOT_PERFORMED")


if __name__ == "__main__":
    main()
