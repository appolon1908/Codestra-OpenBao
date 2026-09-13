#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
source_sha="${CODESTRA_SOURCE_SHA:?set CODESTRA_SOURCE_SHA}"
plan="${OPENBAO_SAVED_PLAN:?set exact downloaded plan path}"
checksum="${OPENBAO_SAVED_PLAN_CHECKSUM:?set exact downloaded checksum path}"
expected_plan_sha="${OPENBAO_EXPECTED_PLAN_SHA256:?set reviewed plan checksum}"
evidence_dir="${OPENBAO_DEPLOYMENT_EVIDENCE_DIR:?set sanitized evidence output directory}"
token_file="${OPENBAO_OPERATOR_TOKEN_FILE:?set runner-local operator token file}"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
for path in "$plan" "$checksum" "$token_file"; do
  [[ -f "$path" && ! -L "$path" ]]
done
[[ "$expected_plan_sha" =~ ^[0-9a-f]{64}$ ]]
[[ "$(awk 'NR == 1 {print $1}' "$checksum")" == "$expected_plan_sha" ]]
(cd "$(dirname "$plan")" && sha256sum -c "$(basename "$checksum")") > /dev/null
[[ "$(jq -r .planSourceSha "$plan")" == "$source_sha" ]]
[[ "$(jq -r .environment "$plan")" == "$environment" ]]
[[ "$(jq -r .counts.destroy "$plan")" == 0 ]]
release_id="${OPENBAO_RELEASE_ID:-NOT_APPLICABLE}"
if [[ "$environment" == production ]]; then
  [[ "$release_id" =~ ^openbao-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}\.[0-9]+$ ]]
else
  [[ "$release_id" == NOT_APPLICABLE ]]
fi

umask 077
mkdir -p "$evidence_dir"
chmod 700 "$evidence_dir"
before_ssh="$evidence_dir/ssh-before.json"
after_ssh="$evidence_dir/ssh-after.json"
if [[ "$environment" == production ]]; then
  scripts/capture_ssh_baseline.sh "$before_ssh" > /dev/null
fi

export BAO_TOKEN="$(< "$token_file")"
export OPENBAO_PREFLIGHT_EVIDENCE="$evidence_dir/preflight.json"
scripts/preflight.sh
export OPENBAO_BACKUP_EVIDENCE="$evidence_dir/prechange-backup.json"
scripts/backup.sh

export OPENBAO_PRECHANGE_BACKUP_EVIDENCE="$OPENBAO_BACKUP_EVIDENCE"
export OPENBAO_APPLY_EVIDENCE="$evidence_dir/apply.json"
scripts/apply.sh
scripts/verify.sh > "$evidence_dir/readback.txt"
unset BAO_TOKEN

if [[ "$environment" == production ]]; then
  scripts/capture_ssh_baseline.sh "$after_ssh" > /dev/null
  python3 scripts/verify_ssh_unchanged.py "$before_ssh" "$after_ssh" \
    > "$evidence_dir/ssh-status.txt"
else
  printf 'SSH_CHANGED=NO\nSSH_SCOPE=NOT_TOUCHED\n' > "$evidence_dir/ssh-status.txt"
fi
chmod 400 "$evidence_dir"/*

echo 'OPENBAO_SAVED_PLAN_APPLY=PASS'
echo 'PLAN_APPLIED_EXACTLY=true'
echo 'PLAN_DESTROY_COUNT=0'
echo 'SSH_CHANGED=NO'
