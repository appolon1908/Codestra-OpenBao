#!/usr/bin/env python3
"""Apply a checksum-locked maintainer-origin backport to an isolated vendor tree.

No module-cache files, imported source, released versions or acceptance records
are changed. Build/test callers must explicitly use -mod=vendor.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH_ROOT = ROOT / "patches/go-jose-v3"
MODULE = "github.com/go-jose/go-jose/v3"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tree_hash(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlink in vendor tree")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode() + b"\0")
            digest.update(bytes.fromhex(sha(path)))
    return digest.hexdigest()

def apply(source_root, manifest=None, patchfile=None):
    source_root = Path(source_root).absolute()
    vendor = source_root / "vendor"
    target = vendor / MODULE
    for path in (source_root, vendor, target, *target.parents):
        if path.is_symlink():
            raise ValueError("symlink in vendor source path")
    tree_hash(vendor)  # Reject every vendor symlink before any mutation.
    modules = vendor / "modules.txt"
    if modules.is_symlink():
        raise ValueError("symlink in vendor module identity")
    headers = [s for s in modules.read_text().splitlines() if s.startswith("# " + MODULE + " ")]
    if headers != ["# " + MODULE + " v3.0.5"]:
        raise ValueError("unexpected vendored module identity or replacement")
    manifest = manifest if manifest is not None else json.loads((PATCH_ROOT / "manifest.json").read_text())
    patchfile = Path(patchfile) if patchfile is not None else PATCH_ROOT / "security.patch"
    if "patch_sha256" in manifest and sha(patchfile) != manifest["patch_sha256"]:
        raise ValueError("backport patch checksum mismatch")
    files = manifest["files"]
    if not files or any(Path(name).name != name or not name.endswith(".go") for name in files):
        raise ValueError("invalid backport file allowlist")
    # Stage the complete change before touching any vendored file. A rejected
    # second hunk/checksum must not leave a partially repaired build tree.
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp)
        for name, hashes in files.items():
            path = target / name
            if path.is_symlink():
                raise ValueError("symlink in vendor source")
            if path.stat().st_nlink != 1:
                raise ValueError("hardlink in vendor source")
            if sha(path) != hashes["before"]:
                raise ValueError("backport baseline mismatch: " + name)
            shutil.copyfile(path, staged / name)
        result = subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patchfile.resolve())],
                                cwd=staged, capture_output=True, text=True)
        if result.returncode:
            raise ValueError("backport patch rejected: " + result.stdout + result.stderr)
        observed = {p.name for p in staged.iterdir()}
        if observed != set(files) or any(sha(staged / n) != h["after"] for n,h in files.items()):
            raise ValueError("unexpected backport patch output")
        for name in files:
            shutil.copyfile(staged / name, target / name)
    return {"schema_version":1, "module":MODULE, "module_version":"v3.0.5",
            "upstream_fix":manifest["upstream_fix"], "patch_sha256":sha(patchfile),
            "files":files, "vendor_modules_sha256":sha(modules),
            "vendor_tree_sha256":tree_hash(vendor), "runtime_authorized":False,
            "requires_go_mod_flag":"-mod=vendor", "vulnerability_acceptance":False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    evidence = apply(args.source_root)
    args.report.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
    print("OPENBAO_JOSE_V3_VENDOR_BACKPORT=PASS")

if __name__ == "__main__":
    main()
