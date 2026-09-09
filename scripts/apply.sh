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

(cd "$(dirname "$plan")" && sha256sum -c "$(basename "$checksum")") >/dev/null
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
while IFS= read -r operation; do
  action="$(jq -r '.action' <<<"$operation")"
  kind="$(jq -r '.kind' <<<"$operation")"
  name="$(jq -r '.name' <<<"$operation")"
  [[ "$action" == create || "$action" == update ]]
  payload="$apply_dir/payload.json"
  jq '.payload' <<<"$operation" > "$payload"
  case "$kind:$action" in
    auth_plugin:create)
      bao plugin register \
        -sha256="$(jq -r '.sha256' "$payload")" \
        -command="$(jq -r '.command' "$payload")" \
        -version="$(jq -r '.version' "$payload")" \
        auth "$(jq -r '.name' "$payload")" >/dev/null
      ;;
    secret_engine:create)
      bao secrets enable -path="$(jq -r '.path' "$payload")" \
        -description="$(jq -r '.description' "$payload")" -version=2 kv >/dev/null
      ;;
    secret_engine_config:create|secret_engine_config:update)
      bao write "$name" @"$payload" >/dev/null
      ;;
    auth_method:create)
      bao auth enable -path="$(jq -r '.path' "$payload")" \
        -plugin-name="$(jq -r '.plugin_name' "$payload")" \
        -plugin-version="$(jq -r '.plugin_version' "$payload")" plugin >/dev/null
      ;;
    policy:create|policy:update)
      jq -r '.policy' "$payload" > "$apply_dir/policy.hcl"
      bao policy write "$name" "$apply_dir/policy.hcl" >/dev/null
      ;;
    auth_config:create|auth_config:update|jwt_role:create|jwt_role:update)
      bao write "$name" @"$payload" >/dev/null
      ;;
    *)
      echo "Unsupported or destructive plan operation: ${kind}:${action}" >&2
      exit 2
      ;;
  esac
done < <(jq -c '
  .operations |
  sort_by(
    if .kind == "auth_plugin" then 0
    elif .kind == "secret_engine" then 1
    elif .kind == "secret_engine_config" then 2
    elif .kind == "auth_method" then 3
    elif .kind == "policy" then 4
    elif .kind == "auth_config" then 5
    elif .kind == "jwt_role" then 6
    else 99 end
  )[]
' "$plan")

python3 scripts/verify_applied_plan.py "$plan"
completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
plan_sha="$(awk '{print $1}' "$checksum")"
jq -n \
  --arg environment "$environment" --arg sourceSha "$source_sha" \
  --arg planSha256 "$plan_sha" --arg startedAt "$started" --arg completedAt "$completed" \
  --arg releaseId "$release_id" \
  --arg approvedBy kazan555 \
  --argjson createCount "$(jq '.counts.create' "$plan")" \
  --argjson changeCount "$(jq '.counts.change' "$plan")" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,releaseId:$releaseId,planSha256:$planSha256,startedAt:$startedAt,completedAt:$completedAt,approvedBy:$approvedBy,createCount:$createCount,changeCount:$changeCount,destroyCount:0,planAppliedExactly:true}' \
  > "$evidence"
chmod 400 "$evidence"

echo 'OPENBAO_APPLY=PASS'
echo 'PLAN_APPLIED_EXACTLY=true'
echo 'PLAN_DESTROY_COUNT=0'
