#!/usr/bin/env python3
"""Prepare a reviewed OpenBao upstream tree for a Git-safe source import.

The importer proves that the extracted tree exactly matches the reviewed Git
index before it changes any fixture. It then sanitizes high-confidence
secret-shaped values, applies a fail-closed admission policy to every path
ignored by the repository, and emits a literal pathspec list. The workflow may
force-add only the paths in that list.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Sequence

MAX_IGNORED_FILE_BYTES = 10 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

ALLOWED_MODES = {"100644", "100755", "120000"}
FORBIDDEN_DIRECTORY_PARTS = {
    ".cache",
    ".tmp",
    "bao-data",
    "raft-data",
    "runtime-data",
}
SECRET_DIRECTORY_PARTS = {"credentials", "secrets"}
WHOLE_FILE_SECRET_SUFFIXES = {
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pfx",
    ".secret",
    ".token",
    ".unseal",
}
SAFE_DOCUMENT_BINARY_SUFFIXES = {
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".webp",
}
CONTEXT_PARTS = {
    "demo",
    "demos",
    "doc",
    "docs",
    "documentation",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "sample",
    "samples",
    "test",
    "test-fixtures",
    "testdata",
    "tests",
    "website",
}

PRIVATE_KEY_BLOCK = re.compile(
    rb"-----BEGIN ((?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----"
    rb".*?"
    rb"-----END \1-----",
    flags=re.DOTALL,
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "aws-access-key-id",
        re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ),
    (
        "aws-secret-access-key",
        re.compile(
            rb"(?i)(?:aws_secret_access_key|aws-secret-access-key)"
            rb"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{20,}"
        ),
    ),
    (
        "authorization-bearer",
        re.compile(
            rb"(?i)authorization[\"']?\s*:\s*[\"']?\s*bearer\s+[-A-Za-z0-9._~+/]{16,}=*"
        ),
    ),
    (
        "client-secret",
        re.compile(
            rb"(?i)client_secret[\"']?\s*[:=]\s*[\"'][^<\s\"']{8,}[\"']"
        ),
    ),
    (
        "github-token",
        re.compile(
            rb"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|"
            rb"github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])"
        ),
    ),
    (
        "gitlab-token",
        re.compile(rb"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    ),
    (
        "google-api-key",
        re.compile(rb"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{30,}(?![A-Za-z0-9_-])"),
    ),
    (
        "openbao-token",
        re.compile(
            rb"(?<![A-Za-z0-9])(?:hvs|hvr|hvb|hvp|hvS)\.[A-Za-z0-9_.:-]{8,}"
        ),
    ),
    (
        "openbao-legacy-token",
        re.compile(rb"(?<![A-Za-z0-9])s\.[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])"),
    ),
    (
        "slack-token",
        re.compile(rb"(?<![A-Za-z0-9-])(?:xox[a-z]-|xapp-)[A-Za-z0-9-]{12,}"),
    ),
    (
        "stripe-live-key",
        re.compile(rb"(?<![A-Za-z0-9_])sk_live_[0-9A-Za-z]{16,}(?![A-Za-z0-9_])"),
    ),
)


class ImportPolicyError(RuntimeError):
    """Raised when the reviewed tree cannot be admitted safely."""


@dataclass(frozen=True)
class IndexEntry:
    mode: str
    object_id: str
    path: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_blob_oid(path: Path, *, symlink: bool, algorithm: str) -> str:
    if algorithm not in {"sha1", "sha256"}:
        raise ImportPolicyError(f"unsupported Git object hash algorithm: {algorithm}")
    digest = hashlib.new(algorithm)
    if symlink:
        data = os.fsencode(os.readlink(path))
        digest.update(f"blob {len(data)}\0".encode("ascii"))
        digest.update(data)
        return digest.hexdigest()

    size = path.stat().st_size
    digest.update(f"blob {size}\0".encode("ascii"))
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_repo_path(value: str) -> str:
    if not value or value.startswith("/") or "\x00" in value:
        raise ImportPolicyError(f"invalid tracked path: {value!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ImportPolicyError(f"non-canonical tracked path: {value!r}")
    canonical = PurePosixPath(value).as_posix()
    if canonical != value:
        raise ImportPolicyError(f"ambiguous tracked path: {value!r}")
    return value


def parse_stage_index(data: bytes) -> list[IndexEntry]:
    entries: list[IndexEntry] = []
    seen: set[str] = set()
    for raw in data.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            mode_b, object_id_b, stage_b = metadata.split(b" ", 2)
            mode = mode_b.decode("ascii")
            object_id = object_id_b.decode("ascii").lower()
            stage = stage_b.decode("ascii")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ImportPolicyError("malformed or non-UTF-8 reviewed Git index") from exc
        if stage != "0":
            raise ImportPolicyError(f"unmerged index entry is prohibited: {path!r}")
        if mode not in ALLOWED_MODES:
            raise ImportPolicyError(f"unsupported tracked mode {mode!r}: {path!r}")
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", object_id):
            raise ImportPolicyError(f"invalid object ID for {path!r}")
        path = _validate_repo_path(path)
        if path in seen:
            raise ImportPolicyError(f"duplicate tracked path: {path!r}")
        seen.add(path)
        entries.append(IndexEntry(mode=mode, object_id=object_id, path=path))
    if not entries:
        raise ImportPolicyError("reviewed Git index is empty")
    object_id_lengths = {len(entry.object_id) for entry in entries}
    if len(object_id_lengths) != 1:
        raise ImportPolicyError("mixed Git object hash algorithms are prohibited")
    return sorted(entries, key=lambda item: item.path)


def load_stage_index(path: Path) -> list[IndexEntry]:
    return parse_stage_index(path.read_bytes())


def _walk_tree(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}

    def walk(directory: Path, prefix: str = "") -> None:
        with os.scandir(directory) as iterator:
            for item in iterator:
                relative = f"{prefix}/{item.name}" if prefix else item.name
                relative = _validate_repo_path(relative)
                item_path = Path(item.path)
                info = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    found[relative] = "symlink"
                elif stat.S_ISDIR(info.st_mode):
                    walk(item_path, relative)
                elif stat.S_ISREG(info.st_mode):
                    found[relative] = "file"
                else:
                    raise ImportPolicyError(f"special file is prohibited: {relative}")

    walk(root)
    return found


def verify_exact_source(root: Path, entries: Sequence[IndexEntry]) -> None:
    expected = {entry.path: entry for entry in entries}
    actual = _walk_tree(root)
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing or unexpected:
        raise ImportPolicyError(
            "extracted tree differs from reviewed Git index: "
            f"missing={missing[:20]!r}, unexpected={unexpected[:20]!r}"
        )

    algorithm = "sha1" if len(entries[0].object_id) == 40 else "sha256"
    for entry in entries:
        path = root / entry.path
        kind = actual[entry.path]
        expected_kind = "symlink" if entry.mode == "120000" else "file"
        if kind != expected_kind:
            raise ImportPolicyError(
                f"tracked mode mismatch for {entry.path}: expected {expected_kind}, got {kind}"
            )
        if kind == "file":
            executable = bool(path.stat().st_mode & 0o111)
            if executable != (entry.mode == "100755"):
                raise ImportPolicyError(f"executable mode mismatch for {entry.path}")
        actual_object_id = _git_blob_oid(
            path, symlink=(kind == "symlink"), algorithm=algorithm
        )
        if actual_object_id != entry.object_id:
            raise ImportPolicyError(
                f"content mismatch for reviewed path {entry.path}: "
                f"{actual_object_id} != {entry.object_id}"
            )


def _repo_relative_root(root: Path, repo_root: Path) -> str:
    try:
        relative = root.resolve().relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ImportPolicyError("import root must be inside the repository") from exc
    value = relative.as_posix()
    return _validate_repo_path(value)


def discover_git_ignored_paths(
    repo_root: Path, import_root_name: str, entries: Sequence[IndexEntry]
) -> set[str]:
    repo_paths = [f"{import_root_name}/{entry.path}" for entry in entries]
    payload = b"\0".join(path.encode("utf-8") for path in repo_paths) + b"\0"
    result = subprocess.run(
        ["git", "-C", str(repo_root), "check-ignore", "--no-index", "-z", "--stdin"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise ImportPolicyError(
            "git check-ignore failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    prefix = import_root_name + "/"
    ignored: set[str] = set()
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            repo_path = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ImportPolicyError("git check-ignore returned a non-UTF-8 path") from exc
        if not repo_path.startswith(prefix):
            raise ImportPolicyError(f"ignored path escaped import root: {repo_path!r}")
        ignored.add(_validate_repo_path(repo_path[len(prefix) :]))
    return ignored


def _ignored_reason(path: str) -> str | None:
    pure = PurePosixPath(path)
    lower_parts = {part.lower() for part in pure.parts}
    name = pure.name.lower()
    suffix = pure.suffix.lower()
    if name == ".ds_store":
        return "forbidden-metadata"
    forbidden = lower_parts & FORBIDDEN_DIRECTORY_PARTS
    if forbidden:
        return "forbidden-runtime-directory"
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "secret-file-name"
    if suffix == ".pem":
        return "pem-material"
    if suffix in WHOLE_FILE_SECRET_SUFFIXES:
        return "secret-file-extension"
    if lower_parts & SECRET_DIRECTORY_PARTS:
        return "secret-directory"
    return None


def _is_secret_directory_path(path: str) -> bool:
    return bool(
        {part.lower() for part in PurePosixPath(path).parts}
        & SECRET_DIRECTORY_PARTS
    )


def _has_review_context(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = {part.lower() for part in pure.parts}
    name = pure.name.lower()
    if parts & CONTEXT_PARTS:
        return True
    if pure.suffix.lower() in {".md", ".mdx", ".rst", ".adoc"}:
        return True
    return any(
        marker in name
        for marker in (
            "_test.",
            "-test.",
            ".test.",
            "test_",
            "test-",
            "_example.",
            "-example.",
            "example_",
            "fixture",
            "sample",
        )
    )


def _replacement(label: str, matched: bytes) -> bytes:
    digest = _sha256(matched)
    return f"CODESTRA_{label.upper().replace('-', '_')}_TEST_INVALID_SHA256_{digest}".encode(
        "ascii"
    )


def _sanitize_pattern(
    data: bytes, pattern: re.Pattern[bytes], label: str
) -> tuple[bytes, int, list[str]]:
    hashes: list[str] = []

    def replace(match: re.Match[bytes]) -> bytes:
        hashes.append(_sha256(match.group(0)))
        return _replacement(label, match.group(0))

    changed, count = pattern.subn(replace, data)
    return changed, count, hashes


def _looks_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def _materialize_symlinks(
    root: Path, entries: Sequence[IndexEntry], records: list[dict[str, object]]
) -> None:
    expected = {entry.path for entry in entries}
    for entry in entries:
        if entry.mode != "120000":
            continue
        path = root / entry.path
        target_value = os.readlink(path)
        if os.path.isabs(target_value):
            raise ImportPolicyError(f"absolute upstream symlink is prohibited: {entry.path}")
        target = (path.parent / target_value).resolve()
        try:
            target_relative = target.relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise ImportPolicyError(
                f"escaping upstream symlink is prohibited: {entry.path}"
            ) from exc
        if target_relative not in expected or not target.is_file() or target.is_symlink():
            raise ImportPolicyError(
                f"upstream symlink target is not one reviewed regular file: {entry.path}"
            )
        original_target = os.fsencode(target_value)
        content = target.read_bytes()
        path.unlink()
        path.write_bytes(content)
        records.append(
            {
                "path": f"{root.name}/{entry.path}",
                "rule": "materialize reviewed in-tree upstream symlink",
                "replacements": 1,
                "original_block_sha256": [_sha256(original_target)],
                "target": target_relative,
            }
        )


def _replace_whole_file(path: Path, relative: str, reason: str) -> str:
    original_sha = _file_sha256(path)
    original_size = path.stat().st_size
    placeholder = (
        "CODESTRA_REVIEWED_UPSTREAM_SECRET_FIXTURE_REMOVED\n"
        f"path={relative}\n"
        f"reason={reason}\n"
        f"original_sha256={original_sha}\n"
        f"original_size={original_size}\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + ".codestra-sanitized")
    temporary.write_bytes(placeholder)
    os.chmod(temporary, path.stat().st_mode & 0o777)
    os.replace(temporary, path)
    return original_sha


def sanitize_tree(
    root: Path,
    entries: Sequence[IndexEntry],
    ignored_paths: set[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    records: list[dict[str, object]] = []
    ignored_records: list[dict[str, object]] = []
    _materialize_symlinks(root, entries, records)

    expected = {entry.path for entry in entries}
    for relative in sorted(expected):
        path = root / relative
        if path.is_symlink():
            raise ImportPolicyError(f"symlink remained after normalization: {relative}")
        size = path.stat().st_size
        ignored = relative in ignored_paths
        reason = _ignored_reason(relative)

        if ignored and reason is None:
            raise ImportPolicyError(
                f".gitignore matched an unclassified upstream path: {relative}"
            )
        if not ignored and reason is not None and relative != ".env.example":
            raise ImportPolicyError(
                f"secret-path policy and .gitignore disagree for {relative}: {reason}"
            )
        if reason in {"forbidden-metadata", "forbidden-runtime-directory"}:
            raise ImportPolicyError(f"runtime or local state is prohibited: {relative}")
        if ignored and not _has_review_context(relative):
            raise ImportPolicyError(
                f"ignored upstream path lacks test/example/documentation context: {relative}"
            )
        if ignored and size > MAX_IGNORED_FILE_BYTES:
            raise ImportPolicyError(
                f"ignored upstream file exceeds {MAX_IGNORED_FILE_BYTES} bytes: {relative}"
            )

        original_sha = _file_sha256(path)
        original_size = size
        action = "not-ignored"
        replacement_count = 0
        match_hashes: list[str] = []

        if ignored and (
            path.name.lower() == ".env"
            or (
                path.name.lower().startswith(".env.")
                and path.name.lower() != ".env.example"
            )
            or path.suffix.lower() in WHOLE_FILE_SECRET_SUFFIXES
            or _is_secret_directory_path(relative)
        ):
            original_sha = _replace_whole_file(path, relative, reason or "")
            action = "whole-file-placeholder"
            replacement_count = 1
            records.append(
                {
                    "path": f"{root.name}/{relative}",
                    "rule": "replace reviewed ignored secret-bearing fixture with deterministic invalid placeholder",
                    "replacements": 1,
                    "original_block_sha256": [original_sha],
                }
            )
        else:
            if size <= MAX_IGNORED_FILE_BYTES:
                data = path.read_bytes()
                all_hashes: list[str] = []
                total = 0
                data, count, hashes = _sanitize_pattern(
                    data, PRIVATE_KEY_BLOCK, "private-key"
                )
                total += count
                all_hashes.extend(hashes)
                for label, pattern in SECRET_PATTERNS:
                    data, count, hashes = _sanitize_pattern(data, pattern, label)
                    total += count
                    all_hashes.extend(hashes)
                if total:
                    if not _has_review_context(relative):
                        raise ImportPolicyError(
                            f"secret-shaped content appears outside a reviewed fixture: {relative}"
                        )
                    path.write_bytes(data)
                    action = "matched-blocks-replaced"
                    replacement_count = total
                    match_hashes = all_hashes
                    records.append(
                        {
                            "path": f"{root.name}/{relative}",
                            "rule": "replace secret-shaped upstream test/example/documentation content with deterministic invalid placeholders",
                            "replacements": total,
                            "original_block_sha256": all_hashes,
                        }
                    )

            if ignored and action == "not-ignored":
                data = path.read_bytes()
                if (
                    _looks_binary(data)
                    and path.suffix.lower() not in SAFE_DOCUMENT_BINARY_SUFFIXES
                ):
                    raise ImportPolicyError(
                        f"unrecognized binary content is prohibited in ignored path: {relative}"
                    )
                action = "verified-no-secret-match"

        if ignored:
            final_data = path.read_bytes()
            if PRIVATE_KEY_BLOCK.search(final_data):
                raise ImportPolicyError(
                    f"private key remained after sanitization: {relative}"
                )
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(final_data):
                    raise ImportPolicyError(
                        f"{label} remained after sanitization: {relative}"
                    )
            ignored_records.append(
                {
                    "path": f"{root.name}/{relative}",
                    "reason": reason,
                    "action": action,
                    "original_sha256": original_sha,
                    "final_sha256": _file_sha256(path),
                    "original_size": original_size,
                    "final_size": path.stat().st_size,
                    "replacements": replacement_count,
                    "matched_block_sha256": match_hashes,
                }
            )

    return records, ignored_records


def _write_pathspecs(
    path: Path, import_root_name: str, entries: Sequence[IndexEntry]
) -> str:
    payload = b"".join(
        f"{import_root_name}/{entry.path}".encode("utf-8") + b"\0"
        for entry in entries
    )
    path.write_bytes(payload)
    return _sha256(payload)


def prepare_import(
    *,
    repo_root: Path,
    root: Path,
    stage_index_path: Path,
    upstream_url: str,
    upstream_ref: str,
    upstream_sha: str,
    manifest_path: Path,
    lock_path: Path,
    pathspec_output: Path,
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ImportPolicyError("upstream import root must be a real directory")
    if upstream_url != "https://github.com/openbao/openbao.git":
        raise ImportPolicyError("unexpected upstream clone URL")
    if upstream_ref != "main":
        raise ImportPolicyError("unexpected upstream reference")
    if not re.fullmatch(r"[0-9a-f]{40}", upstream_sha):
        raise ImportPolicyError(
            "upstream commit must be one lowercase 40-character SHA"
        )

    entries = load_stage_index(stage_index_path)
    verify_exact_source(root, entries)
    import_root_name = _repo_relative_root(root, repo_root)
    ignored_paths = discover_git_ignored_paths(repo_root, import_root_name, entries)
    records, ignored_records = sanitize_tree(root, entries, ignored_paths)

    final_paths = _walk_tree(root)
    if set(final_paths) != {entry.path for entry in entries}:
        raise ImportPolicyError("sanitization changed the reviewed path set")
    if any(kind != "file" for kind in final_paths.values()):
        raise ImportPolicyError("all admitted upstream paths must be regular files")

    pathspec_sha = _write_pathspecs(pathspec_output, import_root_name, entries)
    index_sha = _sha256(stage_index_path.read_bytes())
    generated_at = datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": "2.0",
        "purpose": "GitHub push-protection-safe exact upstream source snapshot",
        "upstream_clone_url": upstream_url,
        "upstream_ref": upstream_ref,
        "upstream_commit": upstream_sha,
        "import_path": import_root_name,
        "generated_at": generated_at,
        "exact_source_verification": "PASS",
        "source_behavior_changed": "test_example_documentation_and_fixture_material_only",
        "tracked_path_count": len(entries),
        "tracked_index_sha256": index_sha,
        "ignored_path_count": len(ignored_paths),
        "ignored_path_policy": {
            "derived_from_repository_gitignore": True,
            "exact_reviewed_paths_only": True,
            "maximum_ignored_file_bytes": MAX_IGNORED_FILE_BYTES,
            "unclassified_ignored_paths_rejected": True,
            "runtime_and_local_state_rejected": True,
            "high_risk_secret_files_replaced": True,
            "remaining_ignored_files_scanned_and_recorded": True,
        },
        "sanitizations": sorted(records, key=lambda item: str(item["path"])),
        "ignored_paths": sorted(
            ignored_records, key=lambda item: str(item["path"])
        ),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lock = {
        "schema_version": "2.0",
        "upstream_clone_url": upstream_url,
        "upstream_ref": upstream_ref,
        "upstream_commit": upstream_sha,
        "import_path": import_root_name,
        "synchronized_at": generated_at,
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
        "sanitization_manifest": manifest_path.as_posix(),
        "sanitization_count": len(records),
        "ignored_path_count": len(ignored_paths),
        "tracked_path_count": len(entries),
        "tracked_index_sha256": index_sha,
        "literal_pathspec_sha256": pathspec_sha,
        "force_add_scope": "exact-reviewed-paths-after-fail-closed-validation",
        "runtime_apply_authorized": False,
    }
    lock_path.write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return lock


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--stage-index", type=Path, required=True)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--upstream-ref", required=True)
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--pathspec-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        lock = prepare_import(
            repo_root=args.repo_root,
            root=args.root,
            stage_index_path=args.stage_index,
            upstream_url=args.upstream_url,
            upstream_ref=args.upstream_ref,
            upstream_sha=args.upstream_sha,
            manifest_path=args.manifest,
            lock_path=args.lock,
            pathspec_output=args.pathspec_output,
        )
    except (ImportPolicyError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"UPSTREAM_IMPORT_PREPARATION=FAIL: {exc}") from exc
    print(
        "UPSTREAM_IMPORT_PREPARATION=PASS "
        f"tracked_paths={lock['tracked_path_count']} "
        f"ignored_paths={lock['ignored_path_count']} "
        f"sanitizations={lock['sanitization_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
