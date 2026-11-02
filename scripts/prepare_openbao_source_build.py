#!/usr/bin/env python3
"""Apply the reviewed deterministic OpenBao source-build dependency overlay.

The imported upstream tree remains byte-for-byte provenance evidence. Builds use this
small, source-controlled transform to replace the vulnerable indirect archive module.
The transform fails unless the exact reviewed old module and checksum records exist.
When the command-line build path is used, Go may reconcile only the reviewed archive,
grpc-go, go-jose, CEL and OpenTelemetry module families; unrelated module or Go-directive changes fail closed.
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

JOSE_MODULE = "github.com/go-jose/go-jose/v4"
JOSE_OLD_SUM_LINES = (
    JOSE_MODULE + " v4.1.4 h1:moDMcTHmvE6Groj34emNPLs/qtYXRVcd6S7NHbHz3kA=",
    JOSE_MODULE + " v4.1.4/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=",
)
JOSE_NEW_SUM_LINES = (
    JOSE_MODULE + " v4.1.6 h1:sNRkftxFJxwsILiQukqp5z83QBSmntVwmgRY7AqBDO4=",
    JOSE_MODULE + " v4.1.6/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=",
)
CAP_MODULE = "github.com/hashicorp/cap"
CAP_OLD_SUM_LINES = (
    CAP_MODULE + " v0.13.0 h1:bzLS1er9am6hOiw//TEjmwZ3t975iFfRfvXY6VRLKEw=",
    CAP_MODULE + " v0.13.0/go.mod h1:Kbu5owAOJzQ/HH4Ba/76wsIXN2tRiJgToJKBO2MAEFE=",
)
CAP_NEW_SUM_LINES = (
    CAP_MODULE + " v0.14.0 h1:IPWX/ewgw8tQPl0qpnCuNf6BFXOCz7ijSM5ikX27cNg=",
    CAP_MODULE + " v0.14.0/go.mod h1:Kbu5owAOJzQ/HH4Ba/76wsIXN2tRiJgToJKBO2MAEFE=",
)
REVIEWED_JOSE_GRAPH_VERSIONS = {JOSE_MODULE: "v4.1.6", CAP_MODULE: "v0.14.0"}

REVIEWED_TRANSITIVE_VERSIONS = {
    "github.com/moby/patternmatcher": "v0.6.1",
    "github.com/moby/sys/sequential": "v0.7.0",
    "github.com/moby/sys/user": "v0.4.1",
}
REVIEWED_GRPC_GRAPH_VERSIONS = {
    "cel.dev/expr": "v0.25.2",
    "golang.org/x/crypto": "v0.58.0",
    "golang.org/x/mod": "v0.41.0",
    "golang.org/x/net": "v0.62.0",
    "golang.org/x/sync": "v0.24.0",
    "golang.org/x/sys": "v0.49.0",
    "golang.org/x/term": "v0.47.0",
    "golang.org/x/text": "v0.43.0",
    "golang.org/x/tools": "v0.51.0",
    "google.golang.org/genproto/googleapis/api": "v0.0.0-20260526163538-3dc84a4a5aaa",
    "google.golang.org/genproto/googleapis/rpc": "v0.0.0-20260526163538-3dc84a4a5aaa",
    "google.golang.org/grpc": "v1.83.2",
}
SOURCE_GO_DIRECTIVE = "1.25.8"
BUILD_GO_DIRECTIVE = "1.26.0"
# Exact reviewed MVS dependency graph from the Go module checksum database.
# This is a build-only transformation: imported upstream source stays byte-identical.
SECURITY_GRAPH_UPGRADES = {
    CAP_MODULE: ("v0.13.0", "v0.14.0"),
    'github.com/google/cel-go': ('v0.28.1', 'v0.30.0'),
    'github.com/go-logr/logr': ('v1.4.3', 'v1.4.4'),
    'go.opentelemetry.io/otel': ('v1.44.0', 'v1.45.0'),
    'go.opentelemetry.io/otel/sdk': ('v1.44.0', 'v1.45.0'),
    'go.opentelemetry.io/otel/trace': ('v1.44.0', 'v1.45.0'),
    'go.opentelemetry.io/otel/metric': ('v1.44.0', 'v1.45.0'),

    JOSE_MODULE: ("v4.1.4", "v4.1.6"),
    "golang.org/x/crypto": ("v0.55.0", "v0.58.0"),
    "golang.org/x/mod": ("v0.38.0", "v0.41.0"),
    "golang.org/x/net": ("v0.58.0", "v0.62.0"),
    "golang.org/x/sync": ("v0.22.0", "v0.24.0"),
    "golang.org/x/sys": ("v0.47.0", "v0.49.0"),
    "golang.org/x/term": ("v0.45.0", "v0.47.0"),
    "golang.org/x/text": ("v0.41.0", "v0.43.0"),
    "golang.org/x/tools": ("v0.48.0", "v0.51.0"),
}
REVIEWED_CEL_OTEL_GRAPH_VERSIONS = {
    "github.com/google/cel-go": "v0.30.0",
    "github.com/go-logr/logr": "v1.4.4",
    "go.opentelemetry.io/otel": "v1.45.0",
    "go.opentelemetry.io/otel/sdk": "v1.45.0",
    "go.opentelemetry.io/otel/trace": "v1.45.0",
    "go.opentelemetry.io/otel/metric": "v1.45.0",
}

CEL_OTEL_OLD_SUM_LINES = {
    "github.com/google/cel-go": (
        "github.com/google/cel-go v0.28.1 h1:YWIwi77J4xIsYUwAF/iIuS6haffzIHS8yWI8glSbLWM=",
        "github.com/google/cel-go v0.28.1/go.mod h1:X0bD6iVNR8pkROSOoHVdgTkzmRcosof7WQqCD6wcMc8=",
    ),
    "github.com/go-logr/logr": (
        "github.com/go-logr/logr v1.4.3 h1:CjnDlHq8ikf6E492q6eKboGOC0T8CDaOvkHCIg8idEI=",
        "github.com/go-logr/logr v1.4.3/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=",
    ),
    "go.opentelemetry.io/otel": (
        "go.opentelemetry.io/otel v1.44.0 h1:JjwHmHpA4iZ3wBxluu2fbbE7j4kqlE8jXyAyPXH7HqU=",
        "go.opentelemetry.io/otel v1.44.0/go.mod h1:BMgjTHL9WPRlRjL2oZCBTL4whCGtXch2H4BhOPIAyYc=",
    ),
    "go.opentelemetry.io/otel/sdk": (
        "go.opentelemetry.io/otel/sdk v1.44.0 h1:nHYwb9lK+fJPU/dnT6s7W7Z8itMWyqrnVfbheVYrZ58=",
        "go.opentelemetry.io/otel/sdk v1.44.0/go.mod h1:Osuydd3Se74nqjAKxid74N5eC+jfEqfTegHRnq58oK0=",
    ),
    "go.opentelemetry.io/otel/trace": (
        "go.opentelemetry.io/otel/trace v1.44.0 h1:jxF5CsGYCe74MCRx2X4g7WsY/VBKRqqpNvXlX/6gtIk=",
        "go.opentelemetry.io/otel/trace v1.44.0/go.mod h1:oLl1jrMQAVo6v3GAggN+1VH9VIz9iUSvW53sW1Q8PIE=",
    ),
    "go.opentelemetry.io/otel/metric": (
        "go.opentelemetry.io/otel/metric v1.44.0 h1:1w0gILTcHdr3YI+ixLyjemwrVnsMURbTZFrSYCdDdmc=",
        "go.opentelemetry.io/otel/metric v1.44.0/go.mod h1:8O7hanEPBNgEMmybD3s2VBKcgWOCsA6tzHBPODAiquo=",
    ),
}

REVIEWED_SECURITY_SUM_LINES = {
    CAP_MODULE: CAP_NEW_SUM_LINES,
    "github.com/google/cel-go": (
        "github.com/google/cel-go v0.30.0 h1:ll54AkzKunWkBn9wSoiUXbFZXYZTkdJGNXTBXUoolGo=",
        "github.com/google/cel-go v0.30.0/go.mod h1:X0bD6iVNR8pkROSOoHVdgTkzmRcosof7WQqCD6wcMc8=",
    ),
    "github.com/go-logr/logr": (
        "github.com/go-logr/logr v1.4.4 h1:tG4xh9yMsRCAiodLVTxyrkzSZ9+o0L1Kg/+cPVcbP/8=",
        "github.com/go-logr/logr v1.4.4/go.mod h1:9T104GzyrTigFIr8wt5mBrctHMim0Nb2HLGrmQ40KvY=",
    ),
    "go.opentelemetry.io/otel": (
        "go.opentelemetry.io/otel v1.45.0 h1:pdrWmLHofpubmArBv1LgFSv1Z0Ie/ppdZzu+kUN5EeU=",
        "go.opentelemetry.io/otel v1.45.0/go.mod h1:XZxIqPapzEYnhNSScF5DIqXhm/rYi0FzCe2XddAwZfQ=",
    ),
    "go.opentelemetry.io/otel/sdk": (
        "go.opentelemetry.io/otel/sdk v1.45.0 h1:4VVSMgQ83dUgW2aoX5f6JgLvHwIvzcuLnF9lUdCSpCw=",
        "go.opentelemetry.io/otel/sdk v1.45.0/go.mod h1:Sr40LgXV7DsKMMJMKOhUWOgMWTfAaqvm2kF0g7ilwuA=",
    ),
    "go.opentelemetry.io/otel/trace": (
        "go.opentelemetry.io/otel/trace v1.45.0 h1:l/mP6Uv7oNO7/TblbhpbgMidxhq1uO/rPsikOyVhxag=",
        "go.opentelemetry.io/otel/trace v1.45.0/go.mod h1:qoJJA2xNMnxRrdISU/kLtfUH2wNeQbiv+jhs/CxI8bc=",
    ),
    "go.opentelemetry.io/otel/metric": (
        "go.opentelemetry.io/otel/metric v1.45.0 h1:7Eg1uH7CJ5cXv9is6tnBe1FI6rj1nwUdbFypRm3br/M=",
        "go.opentelemetry.io/otel/metric v1.45.0/go.mod h1:HAPbm1nd3p1PmFH7v2dR+6BjXxw+Lq4a2+pndMAm08s=",
    ),

    JOSE_MODULE: JOSE_NEW_SUM_LINES,
    "golang.org/x/crypto": (
        "golang.org/x/crypto v0.58.0 h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=",
        "golang.org/x/crypto v0.58.0/go.mod h1:Xh+kl5A+M0gMiWDytH2Hhr5Z7WbNCpv/eB/EFgfSk+w=",
    ),
    "golang.org/x/mod": (
        "golang.org/x/mod v0.41.0 h1:qJmnOUb4YB+FsEuM3HcWucdZASCPGhsX6uljO6pog0c=",
        "golang.org/x/mod v0.41.0/go.mod h1:Ek9pY8RKWXwsWvd3rQiHYtMqkjSUV+s1Rj7j4H5Ur6o=",
    ),
    "golang.org/x/net": (
        "golang.org/x/net v0.62.0 h1:18ELalfM5+XNRwzM2nYqXsZQ9ByS1uhj2O/U7+5jqRY=",
        "golang.org/x/net v0.62.0/go.mod h1:WgDCOTH8iwtB66T4/GfI94AHo/hhdb7Hah9NDseQfiI=",
    ),
    "golang.org/x/sync": (
        "golang.org/x/sync v0.24.0 h1:iqiDrGoDgyuvAKrhLQthUEzU/R378N78gXbBjxed7oA=",
        "golang.org/x/sync v0.24.0/go.mod h1:sUUOizhqBxiL6pEWpqNLUiaJn1ShEbZ6BBqskPbjZm0=",
    ),
    "golang.org/x/sys": (
        "golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=",
        "golang.org/x/sys v0.49.0/go.mod h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=",
    ),
    "golang.org/x/term": (
        "golang.org/x/term v0.47.0 h1:cpyOwQkr2Nzxe2p6KnrTG7Ei2wtzjsuSjhpXXepZ/BM=",
        "golang.org/x/term v0.47.0/go.mod h1:efAfAuG6RKABvg1ArGebRkvX6LXul14SM67o2e4mUCY=",
    ),
    "golang.org/x/text": (
        "golang.org/x/text v0.43.0 h1:1QivrlhwAsnMOcqgOdl9my7s9OyZl8O5/UGUTJVXoWc=",
        "golang.org/x/text v0.43.0/go.mod h1:hbSIYA/amXcRXTFSZqh8tWHEoqRvvbKPJ2uz/KU+a+s=",
    ),
    "golang.org/x/tools": (
        "golang.org/x/tools v0.51.0 h1:k4Xc/1Om9jwkBJBo4NVLMSARBoWtK10mx+W5BnXCeAI=",
        "golang.org/x/tools v0.51.0/go.mod h1:9eEncMayCV6zRMGhR5eZEC2iBx98qWcF1HZ9Z7wJOoA=",
    ),
}

REVIEWED_OPTIONAL_GRAPH_VERSIONS = {
    'go.opentelemetry.io/otel/sdk/metric': 'v1.45.0',
    'go.opentelemetry.io/otel/metric/x': 'v0.67.0',

    "golang.org/x/telemetry": "v0.0.0-20260924152758-ed294f943157",
}
REVIEWED_OPTIONAL_SUM_LINES = {
    'go.opentelemetry.io/otel/sdk/metric': ('go.opentelemetry.io/otel/sdk/metric v1.45.0 h1:oVFszMfyj1Am6s24Vtc7wBb8BKLcwepJjNEYILuiE3o=', 'go.opentelemetry.io/otel/sdk/metric v1.45.0/go.mod h1:vUWUxDZvu1WVRj8JA8S0AdhsPrZoDpA2DdZauIh4mDA='),
    'go.opentelemetry.io/otel/metric/x': ('go.opentelemetry.io/otel/metric/x v0.67.0 h1:PcicCNZFkZ4bXfSooXdo3WN7RBOVOtjVdo1wD358Uns=', 'go.opentelemetry.io/otel/metric/x v0.67.0/go.mod h1:FBjCWZe6wgcqxcMtjdGiClDKXb2YxxXii0CXftE4QtI='),

    "golang.org/x/telemetry": (
        "golang.org/x/telemetry v0.0.0-20260924152758-ed294f943157 h1:DftxASHKl6JolFPqoN+2WrFO53JvkHwRXvFqf8gsivA=",
        "golang.org/x/telemetry v0.0.0-20260924152758-ed294f943157/go.mod h1:i+ivNqjDnTF3WTElsdk5g9V5DTSBYgdNo7xTU9SDwYA=",
    ),
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
        *REVIEWED_JOSE_GRAPH_VERSIONS.keys(),
        *REVIEWED_CEL_OTEL_GRAPH_VERSIONS.keys(),
        *REVIEWED_OPTIONAL_GRAPH_VERSIONS.keys(),
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
    if go_directive(original_mod) != SOURCE_GO_DIRECTIVE or go_directive(final_mod) != BUILD_GO_DIRECTIVE:
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
        **REVIEWED_JOSE_GRAPH_VERSIONS,
        **REVIEWED_CEL_OTEL_GRAPH_VERSIONS,
        **REVIEWED_OPTIONAL_GRAPH_VERSIONS,
    }.items():
        if module in original_versions or module in final_versions:
            if final_versions.get(module) != version:
                fail(f"tidied go.mod does not select {module} {version}")

    required_sums = [*NEW_SUM_LINES]
    for lines in REVIEWED_TRANSITIVE_SUM_LINES.values():
        required_sums.extend(lines)
    for lines in REVIEWED_SECURITY_SUM_LINES.values():
        required_sums.extend(lines)
    final_sum_lines = set(final_sum.splitlines())
    missing_sums = [line for line in required_sums if line not in final_sum_lines]
    if missing_sums:
        fail("tidied go.sum is missing reviewed checksums: " + ",".join(missing_sums))

    # x/tools selects this exact telemetry module. Lazy loading may retain
    # only its go.mod checksum; a selected package also requires its ZIP sum.
    final_records = sum_records(final_sum)
    for module, reviewed in REVIEWED_OPTIONAL_SUM_LINES.items():
        observed = final_records.get(module, set())
        selected = module in final_versions
        if not observed and not selected:
            continue
        if (observed - set(reviewed) or reviewed[1] not in observed
                or (selected and reviewed[0] not in observed)):
            fail(f"tidied go.sum has unreviewed or incomplete optional checksums: {module}")

    return {
        "go_mod_changed_modules": sorted(changed_mod_modules),
        "go_sum_changed_modules": sorted(changed_sum_modules),
    }


def run_tidy(source_root: Path, original_mod: str, original_sum: str) -> dict[str, list[str]]:
    version = BUILD_GO_DIRECTIVE
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

    # The same advisory affects v3, which remains an unresolved upstream
    # dependency. This exact v4-only replacement makes no v3 safety claim.
    for old, new in zip(JOSE_OLD_SUM_LINES, JOSE_NEW_SUM_LINES, strict=True):
        updated_sum = replace_exactly_once(updated_sum, old, new, "go.sum go-jose checksum")

    # CAP0.14 rejects aliases of registered claims; retain its honest dependency identity.
    for old, new in zip(CAP_OLD_SUM_LINES, CAP_NEW_SUM_LINES, strict=True):
        updated_sum = replace_exactly_once(updated_sum, old, new, "go.sum CAP checksum")

    # Verify every reviewed CEL/SDK baseline checksum before writing either file.
    for module, old_lines in CEL_OTEL_OLD_SUM_LINES.items():
        for old, new in zip(old_lines, REVIEWED_SECURITY_SUM_LINES[module], strict=True):
            updated_sum = replace_exactly_once(updated_sum, old, new, "go.sum CEL/SDK checksum")

    if go_directive(updated_mod) != SOURCE_GO_DIRECTIVE:
        fail("source go directive did not match reviewed imported OpenBao version")
    updated_mod = replace_exactly_once(
        updated_mod, f"go {SOURCE_GO_DIRECTIVE}\n", f"go {BUILD_GO_DIRECTIVE}\n",
        "build-only Go module directive",
    )
    # Keep the existing direct/indirect qualifiers unchanged; only replace
    # reviewed exact module versions, rejecting missing or duplicate entries.
    for module, (old_version, new_version) in SECURITY_GRAPH_UPGRADES.items():
        pattern = re.compile(
            rf"(?m)^(?P<indent>[ \t]*){re.escape(module)} {re.escape(old_version)}"
            r"(?P<qualifier>(?: // indirect)?)$"
        )
        matches = list(pattern.finditer(updated_mod))
        if len(matches) != 1:
            fail(f"reviewed module requirement missing or repeated: {module}")
        updated_mod = pattern.sub(
            lambda match: f"{match.group('indent')}{module} {new_version}{match.group('qualifier')}",
            updated_mod, count=1,
        )

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
        "build_go_directive": BUILD_GO_DIRECTIVE,
        "reviewed_security_module_versions": {module: version for module, (_, version) in SECURITY_GRAPH_UPGRADES.items()},
        "reviewed_optional_module_versions": REVIEWED_OPTIONAL_GRAPH_VERSIONS,
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
