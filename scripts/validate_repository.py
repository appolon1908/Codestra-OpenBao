#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao source authority."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PATH = ROOT / "CODESTRA_UPSTREAM.json"
SYNC_WORKFLOW_PATH = ROOT / ".github/workflows/upstream-source-sync.yml"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate.yml"
WORKFLOW_DIR = ROOT / ".github/workflows"
SECRET_SCANNER_PATH = ROOT / "scripts/reject_repository_secrets.sh"

APPROVED_ACTION_REFERENCES = {
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0",
    "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661",
    "sigstore/cosign-installer@d7543c93d881b35a8faa02e8e3605f69b7a1ce62",
    "appolon1908-hue/Codestra-Telemetry/.github/workflows/reusable-validate-service-contract.yml@c35d880a730ca5206d445e8a9a688cb465ae2ad4",
    "./.github/workflows/_deploy-saved-plan.yml",
}

FORBIDDEN_SECRET_FIXTURE_MARKER = (
    "OPENBAO_FORBIDDEN_SECRET_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n"
)
REMOVED_UPSTREAM_SECRET_FIXTURE_PATHS = frozenset({
    Path("upstream/api/test-fixtures/keys/bad-cert.pem"),
    Path("upstream/api/test-fixtures/keys/bad-key.pem"),
    Path("upstream/api/test-fixtures/keys/cert.pem"),
    Path("upstream/api/test-fixtures/keys/key.pem"),
    Path("upstream/api/test-fixtures/root/rootcacert.pem"),
    Path("upstream/api/test-fixtures/root/rootcakey.pem"),
    Path("upstream/command/agent/test-fixtures/reload/reload_bar.key"),
    Path("upstream/command/agent/test-fixtures/reload/reload_bar.pem"),
    Path("upstream/command/agent/test-fixtures/reload/reload_ca.pem"),
    Path("upstream/command/agent/test-fixtures/reload/reload_foo.key"),
    Path("upstream/command/agent/test-fixtures/reload/reload_foo.pem"),
    Path("upstream/command/agentproxyshared/auth/cert/test-fixtures/keys/cert.pem"),
    Path("upstream/command/agentproxyshared/auth/cert/test-fixtures/keys/key.pem"),
    Path("upstream/command/agentproxyshared/auth/cert/test-fixtures/root/rootcacert.pem"),
    Path("upstream/command/agentproxyshared/auth/cert/test-fixtures/root/rootcakey.pem"),
    Path("upstream/command/proxy/test-fixtures/reload/reload_bar.key"),
    Path("upstream/command/proxy/test-fixtures/reload/reload_bar.pem"),
    Path("upstream/command/proxy/test-fixtures/reload/reload_ca.pem"),
    Path("upstream/command/proxy/test-fixtures/reload/reload_foo.key"),
    Path("upstream/command/proxy/test-fixtures/reload/reload_foo.pem"),
    Path("upstream/command/server/test-fixtures/reload/reload_bar.key"),
    Path("upstream/command/server/test-fixtures/reload/reload_bar.pem"),
    Path("upstream/command/server/test-fixtures/reload/reload_ca.pem"),
    Path("upstream/command/server/test-fixtures/reload/reload_foo.key"),
    Path("upstream/command/server/test-fixtures/reload/reload_foo.pem"),
    Path("upstream/vault/diagnose/test-fixtures/chain.crt.pem"),
    Path("upstream/vault/diagnose/test-fixtures/ecdsa.key"),
    Path("upstream/vault/diagnose/test-fixtures/expiredcert.pem"),
    Path("upstream/vault/diagnose/test-fixtures/expiredprivatekey.pem"),
    Path("upstream/vault/diagnose/test-fixtures/fakecert.pem"),
    Path("upstream/vault/diagnose/test-fixtures/goodcertbadroot.pem"),
    Path("upstream/vault/diagnose/test-fixtures/goodcertwithroot.pem"),
    Path("upstream/vault/diagnose/test-fixtures/goodkey.pem"),
    Path("upstream/vault/diagnose/test-fixtures/intermediateCert.pem"),
    Path("upstream/vault/diagnose/test-fixtures/selfSignedCert.pem"),
    Path("upstream/vault/diagnose/test-fixtures/selfSignedCertKey.pem"),
    Path("upstream/vault/diagnose/test-fixtures/trailingdatacert.pem"),
    Path("upstream/vault/diagnose/test-fixtures/twoRootCA.pem"),
})
SANITIZED_SECRET_FIXTURES = {
    path: FORBIDDEN_SECRET_FIXTURE_MARKER
    for path in REMOVED_UPSTREAM_SECRET_FIXTURE_PATHS
}

EXPECTED_UPSTREAM_SHA = "dd9c19c37a878cf4a81b18efb8d6f0599c7da923"
EXPECTED_IMAGE_DIGEST = (
    "sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff"
)


def _logical_shell_lines(source: str) -> tuple[str, ...]:
    records: list[str] = []
    pending = ""
    heredocs: list[str] = []
    for raw in source.splitlines():
        if heredocs:
            if raw.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = pending + line
        trailing_backslashes = len(pending) - len(pending.rstrip("\\"))
        if trailing_backslashes % 2 == 1:
            pending = pending[:-1]
            continue
        records.append(pending)
        for match in re.finditer(
            r"(?<!<)<<-?(?!<)\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))",
            pending,
        ):
            heredocs.append(next(value for value in match.groups() if value))
        pending = ""
    if pending:
        records.append(pending)
    return tuple(records)


def reject_protected_pushes(source: str) -> None:
    """Permit exactly one fully tokenized push to the immutable sync ref."""

    approved = ["git", "push", "origin", "HEAD:refs/heads/${SYNC_BRANCH}"]
    approved_count = 0
    for line in _logical_shell_lines(source):
        if line in {'remote_branch="$(', ')"'}:
            continue
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars="();&|<>")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError as exc:
            raise ValueError("sync_shell_parse_failed") from exc
        if words == approved:
            approved_count += 1
            continue
        for word in words:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=(?:git|push)", word):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        segments: list[list[str]] = [[]]
        for word in words:
            if word in {"{", "}"} or (word and set(word) <= set("();&|")):
                segments.append([])
            else:
                segments[-1].append(word)
        if re.match(r"^(?:(?:elif|if|while)\s+)?(?:\(\(|\[\[)", line) is None:
            for segment in segments:
                while segment and (
                    segment[0] in {"!", "do", "elif", "if", "then", "until", "while"}
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", segment[0])
                ):
                    segment = segment[1:]
                if segment and ("$" in segment[0] or "`" in segment[0]):
                    raise ValueError("protected_branch_sync_forbidden:dynamic_command")
        git_push = False
        for index, word in enumerate(words):
            if Path(word).name != "git":
                continue
            command_index = index + 1
            while command_index < len(words) and words[command_index].startswith("-"):
                option = words[command_index]
                if option == "-c":
                    if command_index + 1 >= len(words):
                        raise ValueError("sync_shell_parse_failed")
                    config = words[command_index + 1]
                    if config.lower().startswith("alias.") or "$" in config:
                        raise ValueError(
                            "protected_branch_sync_forbidden:dynamic_command"
                        )
                if option.lower().startswith(("-calias.", "--config-env=alias.")):
                    raise ValueError(
                        "protected_branch_sync_forbidden:dynamic_command"
                    )
                command_index += 2 if option in {
                    "-c", "-C", "--git-dir", "--work-tree"
                } else 1
            if (
                command_index < len(words)
                and words[command_index] == "config"
                and any(
                    "alias." in argument.lower()
                    or "$" in argument
                    or "`" in argument
                    for argument in words[command_index + 1 :]
                )
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index < len(words) and (
                "$" in words[command_index] or "`" in words[command_index]
            ):
                raise ValueError("protected_branch_sync_forbidden:dynamic_command")
            if command_index < len(words) and words[command_index] == "push":
                git_push = True
                break
        nested_push = any(
            re.search(r"\bgit\s+push\b", re.sub(r"\\([^\n])", r"\1", word))
            for word in words
        )
        dynamic_push = any(
            word == "push"
            and index > 0
            and ("$" in words[index - 1] or "`" in words[index - 1])
            for index, word in enumerate(words)
        )
        if git_push or nested_push or dynamic_push:
            raise ValueError("protected_branch_sync_forbidden:push_not_exact")
    if approved_count != 1:
        raise ValueError("approved_sync_push_count_invalid")


def validate_sync_branch_authority(source: str) -> None:
    """Require one immutable, deterministic authority for the sync destination."""

    expected = 'readonly SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_REF}-${GITHUB_SHA}"'
    lines = _logical_shell_lines(source)
    if lines.count(expected) != 1:
        raise ValueError("sync_branch_authority_invalid")
    for line in lines:
        if line == expected:
            continue
        executable_probe = re.sub(r"\\([^\n])", r"\1", line)
        if re.search(r"(?:^|[();&|<>\s])SYNC_BRANCH\s*=", executable_probe):
            raise ValueError("sync_branch_authority_invalid")
        if re.search(
            r"\b(?:unset|read|mapfile|declare|typeset|local|export|readonly|printf)\b[^\n]*\bSYNC_BRANCH\b",
            executable_probe,
        ):
            raise ValueError("sync_branch_authority_invalid")


def validate_upstream_authority(data: dict) -> None:
    expected = {
        "schema_version": "2.0",
        "component": "OpenBao",
        "codestra_role": "principal-secrets-and-encryption-authority",
        "upstream_repository": "openbao/openbao",
        "upstream_clone_url": "https://github.com/openbao/openbao.git",
        "upstream_version": "2.6.2",
        "upstream_tag": "v2.6.2",
        "upstream_release_url": "https://github.com/openbao/openbao/releases/tag/v2.6.2",
        "image_registry": "ghcr.io/openbao/openbao",
        "image_reference": f"ghcr.io/openbao/openbao@{EXPECTED_IMAGE_DIGEST}",
        "image_index_digest": "sha256:11fd73a2102cda9c55d5d881a8c3210303146a7ec1e8ac76f526e175c6d24641",
        "image_digest": EXPECTED_IMAGE_DIGEST,
        "image_architecture": "linux/amd64",
        "source_identity_verified_at": "2026-09-01",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
        "sanitized_fixture_manifest_required": True,
        "direct_environment_push_allowed": False,
        "branch_promotion": [
            "development",
            "test",
            "staging",
            "production",
            "main",
        ],
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    upstream_ref = data.get("upstream_ref")
    if not isinstance(upstream_ref, str) or re.fullmatch(r"[0-9a-f]{40}", upstream_ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    if upstream_ref != EXPECTED_UPSTREAM_SHA:
        raise ValueError("upstream_authority_drift:upstream_ref")


def validate_sync_workflow(source: str, document: dict) -> None:
    permissions = document.get("permissions") or {}
    expected_permissions = {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }
    if permissions != expected_permissions:
        raise ValueError("sync_permissions_must_only_support_reviewed_pr")
    validate_sync_branch_authority(source)
    reject_protected_pushes(source)
    forbidden_patterns = (
        r"git\s+push\s+origin\s+['\"]?HEAD:(?:refs/heads/)?(?:main|staging|production)['\"]?(?:\s|$)",
        r"git\s+push\s+origin\s+['\"]?(?:refs/heads/)?(?:main|staging|production)['\"]?(?:\s|$)",
        r"git\s+pull\s+--rebase\s+origin\s+main",
        r"git\s+push\s+--force",
    )
    for pattern in forbidden_patterns:
        if re.search(pattern, source):
            raise ValueError(f"protected_branch_sync_forbidden:{pattern}")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'readonly SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_REF}-${GITHUB_SHA}"',
        'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
        "gh pr create",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "--base development",
        "Deployment remains disabled",
        "CODESTRA_UPSTREAM_SANITIZATION.json",
        "scripts/install_ci_tools.sh gitleaks",
        "<CODESTRA_GITLEAKS_FIXTURE_INVALID>",
        "Gitleaks finding outside reviewed fixture paths",
        "UPSTREAM_BASELINE_TREE",
        "upstream import path mismatch",
        "upstream provenance mismatch",
        "git add -f -- upstream",
        "original_block_sha256",
        "PRIVATE_KEY_TEST_FIXTURE_REMOVED",
        "EXPECTED_FORBIDDEN_SECRET_FIXTURES",
        "if discovered_forbidden_secret_fixtures != EXPECTED_FORBIDDEN_SECRET_FIXTURES",
        "OPENBAO_FORBIDDEN_SECRET_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL",
        "forbidden upstream secret fixture path drift",
        "CODESTRA_CLIENT_SECRET_FIXTURE_INVALID",
        "OPENBAO_BATCH_TOKEN_FIXTURE_INVALID",
        "b\\.[A-Za-z0-9_-]{64,}",
        "(?:AKIA|ASIA)[0-9A-Z]{12,}",
        "github_pat_[A-Za-z0-9_]{20,}",
        "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
        "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
        'git ls-remote --exit-code --heads origin "refs/heads/${SYNC_BRANCH}"',
        '[[ "$(git show -s --format=%P "refs/remotes/origin/${SYNC_BRANCH}")" == "$GITHUB_SHA" ]]',
        'git switch --create "$SYNC_BRANCH" --track',
        "(( existing_sync_branch == 1 )) || exit 0",
        "Existing sync branch differs from deterministic rebuild.",
        'gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls"',
        '-f base="development"',
        '-f head="${GITHUB_REPOSITORY_OWNER}:${SYNC_BRANCH}"',
        '.head.repo.full_name',
        '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
        '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        "github.ref == 'refs/heads/development'",
        "Multiple open pull requests claim the sync branch.",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")


def validate_workflow_pins(source: str) -> None:
    use_keys = re.findall(r"(?m)^[ \t]*(?:-[ \t]*)?uses[ \t]*:", source)
    references = re.findall(
        r"(?m)^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*([^\s#]+)[ \t]*(?:#.*)?$",
        source,
    )
    if not references or len(references) != len(use_keys):
        raise ValueError("action_reference_must_be_explicit")
    for reference in references:
        if reference not in APPROVED_ACTION_REFERENCES:
            raise ValueError(f"unapproved_or_mutable_action_reference:{reference}")


def validate_workflow_security(path: Path, source: str, document: dict) -> None:
    validate_workflow_pins(source)
    permissions = document.get("permissions")
    if not isinstance(permissions, dict) or not permissions:
        raise ValueError(f"workflow_permissions_must_be_explicit:{path.name}")
    write_permissions = {
        key for key, value in permissions.items() if str(value).lower() == "write"
    }
    allowed_write_permissions = {
        "upstream-source-sync.yml": {"actions", "contents", "pull-requests"},
        "release.yml": {"attestations", "contents", "id-token"},
    }.get(path.name, set())
    if write_permissions != allowed_write_permissions:
        raise ValueError(f"workflow_write_permissions_drift:{path.name}")

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError(f"workflow_jobs_missing:{path.name}")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValueError(f"workflow_job_invalid:{path.name}:{job_name}")
        job_environment = job.get("env") or {}
        if not isinstance(job_environment, dict):
            raise ValueError(f"workflow_job_environment_invalid:{path.name}:{job_name}")
        if any(
            isinstance(value, str) and "${{ runner." in value
            for value in job_environment.values()
        ):
            raise ValueError(
                f"runner_context_unavailable_in_job_environment:{path.name}:{job_name}"
            )
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError(f"workflow_steps_invalid:{path.name}:{job_name}")
        for step in steps:
            if not isinstance(step, dict):
                continue
            reference = step.get("uses")
            if not isinstance(reference, str) or not reference.startswith("actions/checkout@"):
                continue
            options = step.get("with") or {}
            expected = path.name == "upstream-source-sync.yml"
            if options.get("persist-credentials") is not expected:
                raise ValueError(
                    f"checkout_credential_boundary_drift:{path.name}:{job_name}"
                )


def validate_all_workflows() -> None:
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"workflow_must_be_regular_file:{path.name}")
        source = path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        if not isinstance(document, dict):
            raise ValueError(f"workflow_document_invalid:{path.name}")
        validate_workflow_security(path, source, document)


def validate_whitespace_gate(source: str) -> None:
    required = (
        "fetch-depth: 0",
        'base_sha="${{ github.event.pull_request.base.sha }}"',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"committed_whitespace_gate_missing:{token}")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_secret_scanner(source: str) -> None:
    if "--exclude-dir=tests" in source or '$search_root/tests' in source:
        raise ValueError("imported_tests_must_be_secret_scanned")
    if re.search(r"grep\s+-[^\n]*I", source):
        raise ValueError("binary_secret_scan_must_not_be_skipped")
    if r"""[\"'][^[:space:]<\"']+[\"']""" not in source:
        raise ValueError("sanitized_client_secret_placeholder_must_not_match")
    required = (
        'find "$search_root"',
        '-path "$search_root/.git"',
        "-type f -o -type l",
        '[[ -L "$path" ]]',
        "grep -aEq",
        "find_status=$?",
        "secret_scan_status=$?",
        'exit "$secret_scan_status"',
        "(AKIA|ASIA)[0-9A-Z]{12,}",
        "s\\.[A-Za-z0-9_-]{24}",
        "b\\.[A-Za-z0-9_-]{64,}",
        "github_pat_[A-Za-z0-9_]{20,}",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scan_boundary_missing:{token}")
    if re.search(r"!\s+grep\s+-R", source):
        raise ValueError("secret_scan_errors_must_fail_closed")


def validate_secret_file_policy(root: Path) -> None:
    forbidden_suffixes = (
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".unseal",
        ".token",
        ".secret",
    )
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.name != ".gitignore" and path.name.lower().endswith(forbidden_suffixes):
            expected_fixture = SANITIZED_SECRET_FIXTURES.get(relative)
            if expected_fixture is not None:
                if path.read_text(encoding="utf-8") != expected_fixture:
                    raise ValueError(f"sanitized_fixture_content_drift:{relative}")
                continue
            raise ValueError(f"forbidden_secret_file:{relative}")


def validate_repository() -> None:
    for path in (
        UPSTREAM_PATH,
        SYNC_WORKFLOW_PATH,
        VALIDATE_WORKFLOW_PATH,
        SECRET_SCANNER_PATH,
    ):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
    sync_source = SYNC_WORKFLOW_PATH.read_text(encoding="utf-8")
    sync_document = yaml.safe_load(sync_source)
    validate_source = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
    secret_scanner_source = SECRET_SCANNER_PATH.read_text(encoding="utf-8")
    yaml.safe_load(validate_source)
    validate_upstream_authority(upstream)
    validate_sync_workflow(sync_source, sync_document)
    validate_all_workflows()
    validate_whitespace_gate(validate_source)
    validate_secret_scanner(secret_scanner_source)

    validate_secret_file_policy(ROOT)


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"OPENBAO_SOURCE_VALIDATION=FAIL ERROR={error}") from error
    print("OPENBAO_SOURCE_VALIDATION=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
