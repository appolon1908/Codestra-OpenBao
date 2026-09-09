#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_repository.py"
SPEC = importlib.util.spec_from_file_location("validate_repository", VALIDATOR_PATH)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_upstream_ref_must_be_an_exact_commit(self) -> None:
        self.upstream["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream_authority(self.upstream)

    def test_upstream_image_authority_must_be_an_exact_digest(self) -> None:
        self.upstream["image_reference"] = "ghcr.io/openbao/openbao:2.6.2"
        with self.assertRaisesRegex(ValueError, "upstream_authority_drift:image_reference"):
            VALIDATOR.validate_upstream_authority(self.upstream)

    def test_upstream_sync_opens_reviewed_pr_and_never_pushes_protected_branches(self) -> None:
        VALIDATOR.validate_sync_workflow(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync_workflow(unsafe, self.sync_document)
        for destination in (
            "HEAD:refs/heads/main",
            "HEAD:refs/heads/staging",
            "HEAD:refs/heads/production",
            "refs/heads/main",
        ):
            with self.subTest(destination=destination):
                unsafe = self.sync_source.replace(
                    'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
                    f"git push origin {destination}",
                )
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_only_exact_sync_push_command_is_allowed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        VALIDATOR.reject_protected_pushes(safe)
        unsafe_commands = (
            safe + " HEAD:refs/heads/main",
            safe + " \\\nHEAD:refs/heads/production",
            "git push origin HEAD:refs/heads/main;echo ok",
            "git push origin HEAD:refs/heads/staging&&echo ok",
            "(git push origin HEAD:refs/heads/production)",
            "git push origin 2>/dev/null HEAD:refs/heads/main",
            "/usr/bin/git -c protocol.version=2 push origin HEAD:refs/heads/main",
            "bash -c 'SYNC_BRANCH=main; git push origin HEAD:refs/heads/${SYNC_BRANCH}'",
            "git -c remote.origin.push=HEAD:refs/heads/main push origin",
            "git push origin HEAD:refs/heads/{main,topic}",
        )
        for command in unsafe_commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.reject_protected_pushes(command)

        quoted = self.sync_source.replace(
            safe, safe + "\n          g''it p''ush origin HEAD:refs/heads/main"
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync_workflow(quoted, yaml.safe_load(quoted))
        missing = self.sync_source.replace(safe, "true")
        with self.assertRaisesRegex(ValueError, "approved_sync_push_count_invalid"):
            VALIDATOR.validate_sync_workflow(missing, yaml.safe_load(missing))

    def test_dynamic_command_words_and_subcommands_fail_closed(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for command in (
            safe + '\n          G=git; "$G" push origin HEAD:refs/heads/main',
            safe + '\n          verb=push; git "$verb" origin HEAD:refs/heads/main',
            safe + '\n          suffix=; git p${suffix}ush origin HEAD:refs/heads/main',
            safe
            + '\n          G=/usr/bin/git; P=pu; P+=sh; { "$G" "$P" origin HEAD:refs/heads/main; }',
            safe + '\n          git -c alias.x=push x origin HEAD:refs/heads/main',
            safe + '\n          git -calias.x=push x origin HEAD:refs/heads/main',
            safe + '\n          git config alias.x push; git x origin HEAD:refs/heads/main',
        ):
            with self.subTest(command=command):
                unsafe = self.sync_source.replace(safe, command)
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_heredoc_body_cannot_satisfy_approved_push_count(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        body_only = self.sync_source.replace(
            safe,
            "cat <<'PUSH_EVIDENCE'\n          " + safe + "\n          PUSH_EVIDENCE",
        )
        with self.assertRaisesRegex(ValueError, "approved_sync_push_count_invalid"):
            VALIDATOR.validate_sync_workflow(body_only, yaml.safe_load(body_only))

    def test_sync_branch_destination_is_immutable(self) -> None:
        assignment = (
            'readonly SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_REF}-${GITHUB_SHA}"'
        )
        self.assertIn(assignment, self.sync_source)
        reassigned = self.sync_source.replace(
            assignment, assignment + "\n          SYNC_BRANCH=main"
        )
        with self.assertRaisesRegex(ValueError, "sync_branch_authority_invalid"):
            VALIDATOR.validate_sync_workflow(reassigned, yaml.safe_load(reassigned))

    def test_workflow_actions_are_immutable(self) -> None:
        VALIDATOR.validate_all_workflows()
        self.assertIn(
            "appolon1908-hue/Codestra-Telemetry/.github/workflows/"
            "reusable-validate-service-contract.yml@"
            "c35d880a730ca5206d445e8a9a688cb465ae2ad4",
            VALIDATOR.APPROVED_ACTION_REFERENCES,
        )
        mutable = self.sync_source.replace(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "actions/checkout@main",
        )
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(mutable)
        unapproved = self.sync_source + "\n      - uses: vendor/action@" + ("a" * 40) + "\n"
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(unapproved)

    def test_native_config_validation_uses_supported_cli_and_bounded_startup(self) -> None:
        source = (
            ROOT / ".github/workflows/validate-codestra-runtime-v1.yml"
        ).read_text()
        self.assertIn("./.tmp-openbao operator validate-config", source)
        self.assertNotIn("-verify-only", source)
        self.assertNotIn("-test-verify-only", source)
        self.assertIn(
            "sudo timeout --signal=TERM --kill-after=2s 8s", source
        )
        self.assertIn('if [[ "$server_status" != 124 ]]; then', source)
        self.assertNotIn('"$server_status" != 143', source)
        self.assertIn(
            'OpenBao server exited before the bounded timeout', source
        )
        self.assertIn("grep -q 'OpenBao server started'", source)

    def test_checkout_credentials_are_disabled_except_reviewed_sync_writer(self) -> None:
        VALIDATOR.validate_all_workflows()
        validate_path = ROOT / ".github/workflows/validate.yml"
        source = validate_path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        document["jobs"]["source-authority"]["steps"][0]["with"][
            "persist-credentials"
        ] = True
        with self.assertRaisesRegex(ValueError, "checkout_credential_boundary_drift"):
            VALIDATOR.validate_workflow_security(validate_path, source, document)

    def test_runner_context_is_not_used_in_job_level_environment(self) -> None:
        path = ROOT / ".github/workflows/validate.yml"
        source = path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        document["jobs"]["configuration"].setdefault("env", {})["INVALID"] = (
            "${{ runner.temp }}/evidence.json"
        )
        with self.assertRaisesRegex(
            ValueError, "runner_context_unavailable_in_job_environment"
        ):
            VALIDATOR.validate_workflow_security(path, source, document)

    def test_hcl_container_runs_as_the_calling_user(self) -> None:
        source = (ROOT / "scripts/validate_hcl.sh").read_text(encoding="utf-8")
        self.assertIn('--user "$(id -u):$(id -g)"', source)
        self.assertIn("--entrypoint bao", source)

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )

    def test_exact_upstream_retry_preserves_lock_timestamp(self) -> None:
        self.assertIn(
            "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
            self.sync_source,
        )

    def test_existing_sync_branch_is_reused_without_a_sibling_commit(self) -> None:
        branch_lookup = self.sync_source.index("git ls-remote --exit-code --heads")
        branch_switch = self.sync_source.index(
            'git switch --create "$SYNC_BRANCH" --track'
        )
        lock_read = self.sync_source.index(
            "lock_path = Path('CODESTRA_UPSTREAM_LOCK.json')"
        )
        commit = self.sync_source.index("git commit -m")
        pr_lookup = self.sync_source.index("gh api --method GET", commit)
        self.assertLess(branch_lookup, branch_switch)
        self.assertLess(branch_switch, lock_read)
        self.assertLess(lock_read, commit)
        self.assertLess(commit, pr_lookup)
        self.assertIn(
            '[[ "$(git show -s --format=%P "refs/remotes/origin/${SYNC_BRANCH}")" == "$GITHUB_SHA" ]]',
            self.sync_source,
        )
        self.assertIn(
            "Existing sync branch differs from deterministic rebuild.",
            self.sync_source,
        )

    def test_existing_sync_pr_identity_is_exact(self) -> None:
        for token in (
            'gh api --method GET "repos/${GITHUB_REPOSITORY}/pulls"',
            '-f base="development"',
            '-f head="${GITHUB_REPOSITORY_OWNER}:${SYNC_BRANCH}"',
            ".head.repo.full_name",
            '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
            '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        ):
            self.assertIn(token, self.sync_source)
        for token in (
            '[[ "$pr_head_sha" == "$LOCAL_SHA" ]]',
            '[[ "$pr_repository" == "$GITHUB_REPOSITORY" ]]',
        ):
            with self.subTest(token=token):
                unsafe = self.sync_source.replace(token, "true")
                with self.assertRaisesRegex(
                    ValueError, "reviewed_sync_boundary_missing"
                ):
                    VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_secret_scan_includes_imported_test_directories(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        source = scanner.read_text()
        VALIDATOR.validate_secret_scanner(source)
        self.assertNotIn("--exclude-dir=tests", source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean.txt"
            clean.write_text("no credential material\n")
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            imported = root / "upstream/tests/credentials.json"
            imported.parent.mkdir(parents=True)
            imported.write_text(
                '{"'
                + "Author"
                + "ization"
                + '":"'
                + "Bearer "
                + ("A" * 32)
                + '"}\n'
            )
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("upstream/tests/credentials.json", result.stderr)

    def test_secret_scan_rejects_provider_tokens_and_private_keys(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        cases = {
            "github.txt": "gh" + "p_" + ("A" * 24),
            "fine-grained-github.txt": "github" + "_pat_" + ("G" * 24),
            "aws.txt": "AK" + "IA" + ("A" * 16),
            "aws-sts.txt": "AS" + "IA" + ("B" * 16),
            "encrypted-key.txt": "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\n",
            "dsa-key.txt": "-----BEGIN " + "DSA PRIVATE KEY-----\n",
            "pgp-key.txt": "-----BEGIN PGP PRIVATE" + " KEY BLOCK-----\n",
            "openbao-token.txt": "hv" + "s." + ("A" * 16),
            "legacy-openbao-token.txt": "s." + ("B" * 24),
            "batch-openbao-token.txt": "b." + ("C" * 96),
        }
        for name, contents in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / name
                path.write_text(contents)
                result = subprocess.run(
                    [scanner, directory], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)

    def test_legacy_token_boundary_does_not_reject_claim_field_access(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.txt"
            path.write_text(
                "claims.codestra_environment == 'staging'\n"
                + "blob."
                + ("A" * 96)
                + "\nreturn s.UnsealNamespaceWithContext(context.Background(), req)\n"
            )
            result = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_upstream_sync_sanitizes_legacy_batch_token_fixtures(self) -> None:
        pattern = r"(?<![A-Za-z0-9])b\.[A-Za-z0-9_-]{64,}"
        self.assertIn(
            "(r'(?<![A-Za-z0-9])b\\.[A-Za-z0-9_-]{64,}', "
            "'OPENBAO_BATCH_TOKEN_FIXTURE_INVALID', 0)",
            self.sync_source,
        )
        fixture = "b." + ("A" * 96)
        self.assertEqual(
            re.sub(pattern, "OPENBAO_BATCH_TOKEN_FIXTURE_INVALID", fixture),
            "OPENBAO_BATCH_TOKEN_FIXTURE_INVALID",
        )

    def test_upstream_testing_helpers_are_fixture_eligible(self) -> None:
        self.assertIn("path.name.lower() == 'testing.go'", self.sync_source)
        self.assertIn("'testing','mirage'", self.sync_source)

    def test_upstream_symlink_set_is_exact_and_materialized(self) -> None:
        self.assertIn(
            "Path('upstream/CLAUDE.md'): Path('AGENTS.md')", self.sync_source
        )
        self.assertIn(
            "if discovered_symlinks != EXPECTED_UPSTREAM_SYMLINKS", self.sync_source
        )
        self.assertIn("path.unlink()", self.sync_source)
        self.assertIn("path.write_bytes(contents)", self.sync_source)

    def test_upstream_standalone_private_key_headers_are_sanitized(self) -> None:
        self.assertIn("PRIVATE_KEY_TEST_FIXTURE_HEADER_REMOVED", self.sync_source)

    def test_upstream_bearer_fixtures_are_sanitized(self) -> None:
        self.assertIn("<CODESTRA_BEARER_TOKEN_FIXTURE_INVALID>", self.sync_source)

    def test_upstream_gitleaks_sanitization_is_fixture_only_and_verified(self) -> None:
        self.assertIn("scripts/install_ci_tools.sh gitleaks", self.sync_source)
        self.assertIn("'<CODESTRA_GITLEAKS_FIXTURE_INVALID>'", self.sync_source)
        self.assertIn(
            "Gitleaks finding outside reviewed fixture paths", self.sync_source
        )
        self.assertIn("matcher.subn(replace_gitleaks_fixture, text)", self.sync_source)
        self.assertIn("'decoded:base64'", self.sync_source)
        self.assertIn("decoded Gitleaks fixture lacks an opening quote", self.sync_source)
        self.assertIn("if verification.returncode != 0", self.sync_source)

    def test_upstream_import_is_complete_and_manifest_bound(self) -> None:
        self.assertIn(
            'git -C .codestra-upstream-src ls-tree -r -z "$UPSTREAM_SHA"',
            self.sync_source,
        )
        self.assertIn("git add -f -- upstream", self.sync_source)
        self.assertIn("if baseline.keys() != imported.keys()", self.sync_source)
        self.assertIn("if changed_paths != manifest_paths", self.sync_source)
        self.assertIn("upstream provenance mismatch", self.sync_source)

    def test_client_secret_scanner_distinguishes_values_from_schema_blocks(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        secret_key = "client_" + "secret"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.txt"
            path.write_text(f'oidc_{secret_key} = "test"\n')
            rejected = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(rejected.returncode, 1)
            path.write_text(f'{secret_key.upper()} = "test"\n')
            rejected_upper = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(rejected_upper.returncode, 1)
            path.write_text(
                f'"oidc_{secret_key}": {{\n'
                f'`json:"oidc_{secret_key}"`\n'
                f'"oidc_{secret_key}": s.clientSecret,\n'
            )
            accepted = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_client_secret_fixture_sanitization_preserves_supported_syntax(self) -> None:
        heredoc = self.sync_source.rsplit("python3 - <<'PY'\n", 1)[1].split(
            "\n          PY", 1
        )[0]
        embedded = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in heredoc.splitlines()
        )
        tree = ast.parse(embedded)
        selected = [ast.Import(names=[ast.alias(name="re")])]
        selected.extend(
            node
            for node in tree.body
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "CLIENT_SECRET_ASSIGNMENT"
                    for target in node.targets
                )
            )
            or (
                isinstance(node, ast.FunctionDef)
                and node.name == "sanitize_client_secret_assignment"
            )
        )
        namespace: dict[str, object] = {}
        module = ast.fix_missing_locations(ast.Module(selected, []))
        exec(compile(module, "<sync>", "exec"), namespace)
        pattern = namespace["CLIENT_SECRET_ASSIGNMENT"]
        replacement = namespace["sanitize_client_secret_assignment"]
        self.assertIsInstance(pattern, re.Pattern)

        secret_key = "client_" + "secret"
        supported = {
            f'oidc_{secret_key} = "test"':
                f'oidc_{secret_key} = "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>"',
            f'export {secret_key.upper()}="test"':
                f'export {secret_key.upper()}="<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>"',
            f'oidc_{secret_key}="test" \\':
                f'oidc_{secret_key}="<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>" \\',
            f"{secret_key}: 'fixture' # kept":
                f"{secret_key}: '<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>' # kept",
            f'  "{secret_key}": "fixture",':
                f'  "{secret_key}": "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>",',
        }
        for original, expected in supported.items():
            with self.subTest(original=original):
                self.assertEqual(pattern.sub(replacement, original), expected)

        unsupported = (
            f'{secret_key} := "test"',
            f'{secret_key} == "test"',
            f'"{secret_key}": null',
            f'{secret_key} = unquoted',
            f'{secret_key} = "test" + suffix',
        )
        for original in unsupported:
            with self.subTest(original=original):
                self.assertEqual(pattern.sub(replacement, original), original)

    def test_generated_sync_pr_explicitly_dispatches_validation(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )
        validate_document = yaml.safe_load(
            (ROOT / ".github/workflows/validate.yml").read_text()
        )
        triggers = validate_document.get("on") or validate_document.get(True) or {}
        self.assertIn("workflow_dispatch", triggers)

    def test_manual_sync_is_restricted_to_development(self) -> None:
        self.assertEqual(
            self.sync_document["jobs"]["sync"]["if"],
            "github.actor != 'github-actions[bot]' && "
            "github.ref == 'refs/heads/development'",
        )
        unsafe = self.sync_source.replace(
            " && github.ref == 'refs/heads/development'", ""
        )
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_only_exactly_sanitized_secret_fixture_paths_are_allowed(self) -> None:
        workflow_fixture_block = self.sync_source.split(
            "EXPECTED_FORBIDDEN_SECRET_FIXTURES = {", 1
        )[1].split("\n          }", 1)[0]
        workflow_fixture_paths = {
            Path(path)
            for path in re.findall(r"Path\('([^']+)'\)", workflow_fixture_block)
        }
        self.assertEqual(len(workflow_fixture_paths), 38)
        self.assertEqual(
            workflow_fixture_paths,
            set(VALIDATOR.REMOVED_UPSTREAM_SECRET_FIXTURE_PATHS),
        )
        expected = {
            path: VALIDATOR.FORBIDDEN_SECRET_FIXTURE_MARKER
            for path in VALIDATOR.REMOVED_UPSTREAM_SECRET_FIXTURE_PATHS
        }
        self.assertEqual(VALIDATOR.SANITIZED_SECRET_FIXTURES, expected)
        self.assertIn(
            "if discovered_forbidden_secret_fixtures != "
            "EXPECTED_FORBIDDEN_SECRET_FIXTURES",
            self.sync_source,
        )
        self.assertIn(
            "OPENBAO_FORBIDDEN_SECRET_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL",
            self.sync_source,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, contents in expected.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            VALIDATOR.validate_secret_file_policy(root)

            drifted_relative = min(expected, key=lambda path: path.as_posix())
            drifted = root / drifted_relative
            drifted.write_text("not sanitized\n")
            with self.assertRaisesRegex(ValueError, "sanitized_fixture_content_drift"):
                VALIDATOR.validate_secret_file_policy(root)

            drifted.write_text(expected[drifted_relative])
            unexpected = root / "upstream/runtime/private.pem"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_text("also not allowed\n")
            with self.assertRaisesRegex(ValueError, "forbidden_secret_file"):
                VALIDATOR.validate_secret_file_policy(root)
        weakened = self.sync_source.replace(
            "if discovered_forbidden_secret_fixtures != "
            "EXPECTED_FORBIDDEN_SECRET_FIXTURES",
            "if False",
        )
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync_workflow(weakened, yaml.safe_load(weakened))
        self.assertIn(
            "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
            self.sync_source,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
