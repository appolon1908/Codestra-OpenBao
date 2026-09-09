#!/usr/bin/env python3
"""Apply the reviewed deterministic OpenBao source-build dependency overlay.

The imported upstream tree remains byte-for-byte provenance evidence. Builds use this
small, source-controlled transform to replace the vulnerable indirect archive module.
The transform fails unless the exact reviewed old module and checksum records exist.
When the command-line build path is used, Go may reconcile only the reviewed archive
and grpc-go module families; any unrelated module or Go-directive change fails closed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

OLD_VERSION = "v0.2.0"
NEW_VERSION = "v0.3.2"
MODULE = "github.com/moby/go-archive"
OLD_MOD_LINE = f"\t{MODULE} {OLD_VERSION} // indirect"
NEW_MOD_LINE = f"\t{MODULE} {NEW_VERSION} // indirect"
OLD_SUM_LINES = (
    f"{MODULE} {OLD_VERSION} h1:zg5QDUM2mi0JIM9fdQZWC7U8+2ZfixfTYoHL7rWUcP8=",
    f"{MODULE} {OLD_VERSION}/go.mod h1:mNeivT14o8xU+5q1YnNrkQVpK+dnNe/K6fHqnTg4qPU=",
)
NEW_SUM_LINES = (
    f"{MODULE} {NEW_VERSION} h1:x893kC3zRygv2C+k4Y9kMxYRPLCj4XEJB0srbAP06Hw=",
    f"{MODULE} {NEW_VERSION}/go.mod h1:Npdv43fFqlhZW7Xo8fbm3ZMYFvAGNviUPqX21VERbcE=",
)

REVIEWED_TRANSITIVE_VERSIONS = {
    "github.com/moby/patternmatcher": "v0.6.1",
    "github.com/moby/sys/sequential": "v0.7.0",
    "github.com/moby/sys/user": "v0.4.1",
}
REVIEWED_GRPC_GRAPH_VERSIONS = {
    "cel.dev/expr": "v0.25.2",
    "golang.org/x/crypto": "v0.55.0",
    "golang.org/x/mod": "v0.38.0",
    "golang.org/x/net": "v0.58.0",
    "golang.org/x/sync": "v0.22.0",
    "golang.org/x/sys": "v0.47.0",
    "golang.org/x/term": "v0.45.0",
    "golang.org/x/text": "v0.41.0",
    "golang.org/x/tools": "v0.48.0",
    "google.golang.org/genproto/googleapis/api": "v0.0.0-20260526163538-3dc84a4a5aaa",
    "google.golang.org/genproto/googleapis/rpc": "v0.0.0-20260526163538-3dc84a4a5aaa",
    "google.golang.org/grpc": "v1.83.2",
}
REVIEWED_TRANSITIVE_SUM_LINES = {
    "github.com/moby/patternmatcher": (
        "github.com/moby/patternmatcher v0.6.1 h1:qlhtafmr6kgMIJjKJMDmMWq7WLkKIo23hsrpR3x084U=",
        "github.com/moby/patternmatcher v0.6.1/go.mod h1:hDPoyOpDY7OrrMDLaYoY3hf52gNCR/YOUYxkhApJIxc=",
    ),
    "github.com/moby/sys/sequential": (
        "github.com/moby/sys/sequential v0.7.0 h1:ASQNGNROJSuOO6LL6bPHbKvuZu6NU8P4ldPWk31zj/8=",
        "github.com/moby/sys/sequential v0.7.0/go.mod h1:NfSTAp6V3fw4tmkD62PEcOKeZKquXT8VKCkf7aVR79o=",
    ),
    "github.com/moby/sys/user": (
        "github.com/moby/sys/user v0.4.1 h1:RgjRlaDKi/Xmyrz4t8lyzXT6v2ooFeO/7xtchmhVWE0=",
        "github.com/moby/sys/user v0.4.1/go.mod h1:E9QsW5WRe1kUAf7kW8hXKwu1uhsZEAdPLYHYSDudF4Y=",
    ),
}
REVIEWED_TIDY_MODULES = frozenset(
    {
        MODULE,
        "github.com/klauspost/compress",
        "github.com/moby/patternmatcher",
        "github.com/moby/sys/mount",
        "github.com/moby/sys/mountinfo",
        "github.com/moby/sys/reexec",
        "github.com/moby/sys/sequential",
        "github.com/moby/sys/user",
        "github.com/moby/sys/userns",
        "github.com/sirupsen/logrus",
        *REVIEWED_GRPC_GRAPH_VERSIONS.keys(),
    }
)
MODULE_VERSION_RE = re.compile(r"^\s*([^\s]+)\s+(v[^\s]+)(?:\s+//\s+indirect)?\s*$")
GO_DIRECTIVE_RE = re.compile(r"^go\s+(\S+)\s*$", re.MULTILINE)


def fail(message: str) -> None:
    print(f"OPENBAO_SOURCE_BUILD_PATCH_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def replace_exactly_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"{label} expected exactly once, found {count}")
    return text.replace(old, new, 1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def go_directive(text: str) -> str:
    match = GO_DIRECTIVE_RE.search(text)
    if match is None or len(GO_DIRECTIVE_RE.findall(text)) != 1:
        fail("go.mod must contain exactly one Go version directive")
    return match.group(1)


def module_versions(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in text.splitlines():
        match = MODULE_VERSION_RE.match(raw)
        if match is None:
            continue
        module, version = match.groups()
        if module in result and result[module] != version:
            fail(f"go.mod contains conflicting versions for {module}")
        result[module] = version
    return result


def sum_records(text: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for raw in text.splitlines():
        fields = raw.split()
        if len(fields) != 3 or not fields[1].startswith("v") or not fields[2].startswith("h1:"):
            continue
        result.setdefault(fields[0], set()).add(raw)
    return result


def changed_keys(before: dict[str, object], after: dict[str, object]) -> set[str]:
    return {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}


def validate_tidy_result(
    original_mod: str,
    original_sum: str,
    final_mod: str,
    final_sum: str,
) -> dict[str, list[str]]:
    if go_directive(final_mod) != go_directive(original_mod):
        fail("go mod tidy changed the reviewed Go version directive")

    original_versions = module_versions(original_mod)
    final_versions = module_versions(final_mod)
    changed_mod_modules = changed_keys(original_versions, final_versions)
    changed_sum_modules = changed_keys(sum_records(original_sum), sum_records(final_sum))
    unexpected = (changed_mod_modules | changed_sum_modules) - REVIEWED_TIDY_MODULES
    if unexpected:
        fail("go mod tidy changed unreviewed modules: " + ",".join(sorted(unexpected)))

    if final_versions.get(MODULE) != NEW_VERSION:
        fail(f"tidied go.mod does not select {MODULE} {NEW_VERSION}")
    for module, version in {
        **REVIEWED_TRANSITIVE_VERSIONS,
        **REVIEWED_GRPC_GRAPH_VERSIONS,
    }.items():
        if module in original_versions or module in final_versions:
            if final_versions.get(module) != version:
                fail(f"tidied go.mod does not select {module} {version}")

    required_sums = [*NEW_SUM_LINES]
    for lines in REVIEWED_TRANSITIVE_SUM_LINES.values():
        required_sums.extend(lines)
    final_sum_lines = set(final_sum.splitlines())
    missing_sums = [line for line in required_sums if line not in final_sum_lines]
    if missing_sums:
        fail("tidied go.sum is missing reviewed checksums: " + ",".join(missing_sums))

    return {
        "go_mod_changed_modules": sorted(changed_mod_modules),
        "go_sum_changed_modules": sorted(changed_sum_modules),
    }


def run_tidy(source_root: Path, original_mod: str, original_sum: str) -> dict[str, list[str]]:
    version = go_directive(original_mod)
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOWORK": "off"})
    completed = subprocess.run(
        ["go", "mod", "tidy", f"-go={version}"],
        cwd=source_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=900,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        detail = " | ".join(detail.splitlines())[:2000]
        fail(f"go mod tidy failed with exit code {completed.returncode}: {detail}")
    return validate_tidy_result(
        original_mod,
        original_sum,
        source_root.joinpath("go.mod").read_text(encoding="utf-8"),
        source_root.joinpath("go.sum").read_text(encoding="utf-8"),
    )


def apply(
    source_root: Path,
    report: Path | None = None,
    *,
    tidy: bool = False,
) -> dict[str, object]:
    go_mod = source_root / "go.mod"
    go_sum = source_root / "go.sum"
    if not go_mod.is_file() or not go_sum.is_file():
        fail("source root must contain go.mod and go.sum")

    original_mod = go_mod.read_text(encoding="utf-8")
    original_sum = go_sum.read_text(encoding="utf-8")
    if NEW_MOD_LINE in original_mod or any(line in original_sum for line in NEW_SUM_LINES):
        fail("build overlay appears to have been applied already")

    updated_mod = replace_exactly_once(
        original_mod, OLD_MOD_LINE, NEW_MOD_LINE, "go.mod archive requirement"
    )
    updated_sum = original_sum
    for old, new in zip(OLD_SUM_LINES, NEW_SUM_LINES, strict=True):
        updated_sum = replace_exactly_once(updated_sum, old, new, "go.sum archive checksum")

    go_mod.write_text(updated_mod, encoding="utf-8")
    go_sum.write_text(updated_sum, encoding="utf-8")

    if updated_mod.count(NEW_MOD_LINE) != 1:
        fail("updated go.mod does not contain the exact security-fixed requirement")
    if any(updated_sum.count(line) != 1 for line in NEW_SUM_LINES):
        fail("updated go.sum does not contain exact security-fixed checksums")
    if OLD_MOD_LINE in updated_mod or any(line in updated_sum for line in OLD_SUM_LINES):
        fail("vulnerable archive module records remain after transform")

    overlay_mod_sha256 = sha256(go_mod)
    overlay_sum_sha256 = sha256(go_sum)
    tidy_changes: dict[str, list[str]] = {
        "go_mod_changed_modules": [],
        "go_sum_changed_modules": [],
    }
    if tidy:
        tidy_changes = run_tidy(source_root, original_mod, original_sum)

    evidence: dict[str, object] = {
        "schema_version": 2,
        "status": "PASS",
        "module": MODULE,
        "old_version": OLD_VERSION.removeprefix("v"),
        "new_version": NEW_VERSION.removeprefix("v"),
        "go_version": go_directive(original_mod),
        "go_mod_sha256_before": hashlib.sha256(original_mod.encode()).hexdigest(),
        "go_mod_sha256_after_overlay": overlay_mod_sha256,
        "go_mod_sha256_after": sha256(go_mod),
        "go_sum_sha256_before": hashlib.sha256(original_sum.encode()).hexdigest(),
        "go_sum_sha256_after_overlay": overlay_sum_sha256,
        "go_sum_sha256_after": sha256(go_sum),
        "go_mod_tidy_performed": tidy,
        "tidy_changed_go_mod_modules": tidy_changes["go_mod_changed_modules"],
        "tidy_changed_go_sum_modules": tidy_changes["go_sum_changed_modules"],
        "tidy_allowed_modules": sorted(REVIEWED_TIDY_MODULES),
        "source_tree_modified_for_build_only": True,
        "repository_source_mutated": False,
    }
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path("upstream"))
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--skip-tidy",
        action="store_true",
        help="Unit-test/debug only: skip the build-only module reconciliation",
    )
    args = parser.parse_args()
    evidence = apply(args.source_root, args.report, tidy=not args.skip_tidy)
    print(f"OPENBAO_ARCHIVE_MODULE={evidence['module']}")
    print(f"OPENBAO_ARCHIVE_VERSION={evidence['new_version']}")
    print(f"OPENBAO_BUILD_ONLY_TIDY={'PASS' if evidence['go_mod_tidy_performed'] else 'SKIPPED'}")
    print("OPENBAO_SOURCE_BUILD_PATCH=PASS")
    return 0


if __name__ == "__main__":
    main()
