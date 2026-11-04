"""Read the declared upstream commit identity; never import, commit, push or deploy."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def parse_remote_oid(output, expected_ref):
    lines = output.strip().splitlines()
    if len(lines) != 1:
        raise ValueError("upstream identity must resolve exactly once")
    fields = lines[0].split()
    if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{40}", fields[0]) or fields[1] != expected_ref:
        raise ValueError("unexpected upstream identity")
    return fields[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if source != os.environ.get("EXPECTED_SHA") or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("unexpected source checkout")
    manifest = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
    url = "https://github.com/openbao/openbao.git"
    if (manifest.get("upstream_clone_url") != url or manifest.get("upstream_ref") != "main" or
            manifest.get("deployment_enabled") is not False or
            manifest.get("secret_material_allowed_in_git") is not False):
        raise ValueError("unexpected upstream authority")
    ref = "refs/heads/main"
    output = subprocess.check_output(["git", "ls-remote", "--exit-code", url, ref],
                                     cwd=ROOT, text=True, timeout=60)
    upstream = parse_remote_oid(output, ref)
    report = {"schema_version": 1, "evidence_type": "upstream_identity_inspection",
              "source_sha": source, "upstream_repository": url, "upstream_ref": ref,
              "upstream_commit": upstream, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source_imported": False, "security_verified": False,
              "protected_ref_updated": False, "runtime_authorized": False,
              "next_step": "Prepare an independently reviewed, signed source PR; inspection is not acceptance."}
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
