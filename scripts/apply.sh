#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
plan="${OPENBAO_SAVED_PLAN:?set exact saved plan path}"
checksum="${OPENBAO_SAVED_PLAN_CHECKSUM:?set exact saved plan checksum path}"
evidence="${OPENBAO_APPLY_EVIDENCE:?set apply evidence output path}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
[[ "$environment" =~ ^(development|test|staging|production)$ ]]
for command in bao jq sha256sum gh; do command -v "$command" >/dev/null; done

scripts/verify_artifact_checksum.sh "$plan" "$checksum" >/dev/null
source_sha="$(git rev-parse HEAD)"
release_id="${OPENBAO_RELEASE_ID:-NOT_APPLICABLE}"
[[ "$(jq -r '.planSourceSha' "$plan")" == "$source_sha" ]]
[[ "$(jq -r '.environment' "$plan")" == "$environment" ]]
[[ "$(jq -r '.planOnly' "$plan")" == true ]]
[[ "$(jq -r '.counts.destroy' "$plan")" == 0 ]]
[[ "$(jq '.warnings | length' "$plan")" == 0 ]]
[[ "$(jq -r '.runtimeApplyAuthorized' "$plan")" == true ]]
[[ -z "$(git status --porcelain)" ]]
if [[ "$environment" == production ]]; then
  [[ "$release_id" =~ ^openbao-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}\.[0-9]+$ ]]
else
  [[ "$release_id" == NOT_APPLICABLE ]]
fi
confirmation="${OPENBAO_APPLY_CONFIRMATION:-}"
[[ "$confirmation" == "APPLY_EXACT_OPENBAO_PLAN_${source_sha}" ]]

for query in \
  'config/workload-secret-authority.v1.json:.runtimeApplyAuthorized' \
  'openbao/auth/jwt-roles.v1.json:.runtimeApplyAuthorized' \
  'config/audit/audit.v1.json:.runtimeApplyAuthorized' \
  'config/secrets/engines.v1.json:.runtimeApplyAuthorized' \
  'plugins/codestra-jwt-replay/plugin.v1.json:.runtimeApplyAuthorized' \
  "config/environments/${environment}/environment.json:.runtimeApplyAuthorized"; do
  file="${query%%:*}"
  expression="${query#*:}"
  [[ "$(jq -r "$expression" "$file")" == true ]]
done
[[ "$(jq -r '.jtiReplayCacheImplemented' config/auth/keycloak-jwt.v1.json)" == true ]]
[[ "$(jq -r '.jtiReplayCacheImplemented' openbao/auth/jwt-roles.v1.json)" == true ]]

scripts/verify_environment_approval.sh

if jq -e '.operations[] | select(.kind == "auth_plugin")' "$plan" >/dev/null; then
  plugin_binary="${OPENBAO_PLUGIN_BINARY:?plan requires exact plugin binary}"
  [[ -f "$plugin_binary" && ! -L "$plugin_binary" ]]
  expected_plugin_command="$(jq -r '.operations[] | select(.kind == "auth_plugin") | .payload.command' "$plan")"
  expected_plugin_sha="$(jq -r '.operations[] | select(.kind == "auth_plugin") | .payload.sha256' "$plan")"
  [[ "$(basename "$plugin_binary")" == "$expected_plugin_command" ]]
  [[ "$(sha256sum "$plugin_binary" | awk '{print $1}')" == "$expected_plugin_sha" ]]
fi

if [[ "$environment" == production ]]; then
  backup_evidence="${OPENBAO_PRECHANGE_BACKUP_EVIDENCE:?production requires backup evidence}"
  jq -e '
    .schemaVersion == 1 and .environment == "production" and
    .backup == "PASS" and .offHostBackup == "PASS" and
    .checksumVerified == true and .immutabilityVerified == true
  ' "$backup_evidence" >/dev/null
fi

umask 077
apply_dir="$(mktemp -d)"
cleanup() {
  find "$apply_dir" -type f -delete
  find "$apply_dir" -depth -type d -empty -delete
}
trap cleanup EXIT

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Every OpenBao mutation goes through the change kernel's single actuator:
# fenced dispatch intent, one call, readback-only confirmation.
scripts/require_mutation_lease.sh
plan_sha="$(scripts/verify_artifact_checksum.sh "$plan" "$checksum")"
kernel=(python3 -m codestra.change_kernel.cli)
live_dir="$apply_dir/live"
mkdir "$live_dir"
scripts/collect_live_state.sh "$environment" "$live_dir"
submitted="$("${kernel[@]}" submit --environment "$environment" --tenant platform \
  --idempotency-key "saved-plan-${plan_sha}" \
  --request-id "github-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:-1}" \
  --correlation-id "saved-plan-${plan_sha}" \
  --plan "$plan" --checksum "$checksum" --expected-plan-sha256 "$plan_sha" \
  --subject "${GITHUB_ACTOR:?}")"
change_id="$(jq -r '.change_id' <<<"$submitted")"
[[ "$change_id" =~ ^chg_[0-9a-f]{32}$ ]]
if [[ "$(jq -r '.status' <<<"$submitted")" == AWAITING_APPROVAL ]]; then
  # verify_environment_approval.sh above proved the protected-environment
  # approval for this run; bind it to this exact plan digest and cluster.
  "${kernel[@]}" approve --change-id "$change_id" --approver kazan555 \
    --plan-digest "$(jq -r '.plan_digest' <<<"$submitted")" --environment "$environment" \
    --evidence-ref "github-run:${GITHUB_REPOSITORY:?}/${GITHUB_RUN_ID}" --valid-seconds 3600 >/dev/null
fi
"${kernel[@]}" apply --change-id "$change_id" --environment "$environment" --tenant platform \
  --live-dir "$live_dir" --subject "$GITHUB_ACTOR" >/dev/null

python3 scripts/verify_applied_plan.py "$plan"
completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg environment "$environment" --arg sourceSha "$source_sha" \
  --arg planSha256 "$plan_sha" --arg startedAt "$started" --arg completedAt "$completed" \
  --arg releaseId "$release_id" --arg changeId "$change_id" \
  --arg approvedBy kazan555 \
  --argjson createCount "$(jq '.counts.create' "$plan")" \
  --argjson changeCount "$(jq '.counts.change' "$plan")" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,releaseId:$releaseId,changeId:$changeId,planSha256:$planSha256,startedAt:$startedAt,completedAt:$completedAt,approvedBy:$approvedBy,createCount:$createCount,changeCount:$changeCount,destroyCount:0,planAppliedExactly:true}' \
  > "$evidence"
chmod 400 "$evidence"

echo 'OPENBAO_APPLY=PASS'
echo 'PLAN_APPLIED_EXACTLY=true'
echo 'PLAN_DESTROY_COUNT=0'
