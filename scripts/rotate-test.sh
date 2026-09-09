#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
identity="${OPENBAO_ROTATION_IDENTITY:?set workload identity}"
logical_path="${OPENBAO_ROTATION_SECRET_PATH:?set exact logical KV path}"
new_secret_file="${OPENBAO_ROTATION_NEW_SECRET_FILE:?set protected N+1 JSON file}"
rendered_file="${OPENBAO_ROTATION_RENDERED_FILE:?set agent-rendered destination}"
expected_sha="${OPENBAO_ROTATION_EXPECTED_SHA256:?set expected payload SHA-256}"
expected_version="${OPENBAO_ROTATION_EXPECTED_CURRENT_VERSION:?set reviewed N version}"
evidence="${OPENBAO_ROTATION_EVIDENCE:?set sanitized evidence output}"
service_uid="${OPENBAO_ROTATION_SERVICE_UID:?set service UID}"
service_gid="${OPENBAO_ROTATION_SERVICE_GID:?set service GID}"
new_verifier="${OPENBAO_ROTATION_NEW_VERIFIER:?set read-only N+1 verifier}"
old_revoke="${OPENBAO_ROTATION_OLD_REVOKE:?set old credential revoker}"
old_verifier="${OPENBAO_ROTATION_OLD_VERIFIER:?set old credential denial verifier}"
health_verifier="${OPENBAO_ROTATION_HEALTH_VERIFIER:?set service health verifier}"

[[ "$environment" =~ ^(development|test|staging)$ ]]
[[ "$identity" =~ ^[a-z][a-z0-9-]+$ ]]
[[ "$logical_path" == "codestra/${environment}/"* && "$logical_path" != */ ]]
[[ "$logical_path" != *..* && "$logical_path" != *//* && "$logical_path" != *'*'* ]]
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]
[[ "$expected_version" =~ ^[1-9][0-9]*$ ]]
[[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]]
[[ "${OPENBAO_PROVIDER_EFFECTS_DISABLED_ACKNOWLEDGED:-false}" == true ]]
[[ "${OPENBAO_ROTATION_CONFIRMATION:-}" == "ROTATE_${identity^^}_${environment^^}_N_TO_N_PLUS_1" ]]
[[ "$(jq -r .runtimeApplyAuthorized "config/environments/${environment}/environment.json")" == true ]]
for command in bao jq sha256sum stat; do command -v "$command" >/dev/null; done

for path in "$new_secret_file" "$new_verifier" "$old_revoke" "$old_verifier" "$health_verifier"; do
  [[ -f "$path" && ! -L "$path" ]]
done
for callback in "$new_verifier" "$old_revoke" "$old_verifier" "$health_verifier"; do
  [[ -x "$callback" ]]
done
jq -e 'type == "object" and (.payload | type == "string" and length > 0) and length == 1' \
  "$new_secret_file" >/dev/null
[[ "$(jq -j .payload "$new_secret_file" | sha256sum | awk '{print $1}')" == "$expected_sha" ]]

role_prefixes="$(jq -c --arg environment "$environment" --arg identity "$identity" '
  .roles[] | select(.environment == $environment and .serviceIdentity == $identity) | .pathPrefixes
' config/workload-secret-authority.v1.json)"
jq -e --arg path "$logical_path" 'any(.[]; . as $prefix | $path | startswith($prefix))' \
  <<<"$role_prefixes" >/dev/null
kv_path="${logical_path#codestra/${environment}/}"

metadata="$(mktemp)"
cleanup() { find "$metadata" -type f -delete; }
trap cleanup EXIT
bao kv metadata get -format=json "codestra/${environment}/${kv_path}" > "$metadata"
[[ "$(jq -r .data.current_version "$metadata")" == "$expected_version" ]]

bao kv put -cas="$expected_version" "codestra/${environment}/${kv_path}" \
  @"$new_secret_file" >/dev/null
new_version="$((expected_version + 1))"

matched=false
for _ in $(seq 1 60); do
  if [[ -f "$rendered_file" && ! -L "$rendered_file" ]] &&
     [[ "$(stat -c %a "$rendered_file")" == 400 ]] &&
     [[ "$(stat -c %u "$rendered_file")" == "$service_uid" ]] &&
     [[ "$(stat -c %g "$rendered_file")" == "$service_gid" ]] &&
     [[ "$(sha256sum "$rendered_file" | awk '{print $1}')" == "$expected_sha" ]]; then
    matched=true
    break
  fi
  sleep 2
done
[[ "$matched" == true ]]

"$new_verifier" >/dev/null 2>&1
"$old_revoke" >/dev/null 2>&1
if "$old_verifier" >/dev/null 2>&1; then
  echo 'Old credential still succeeds after revocation.' >&2
  exit 2
fi
"$health_verifier" >/dev/null 2>&1

current="$(bao kv metadata get -format=json "codestra/${environment}/${kv_path}")"
[[ "$(jq -r .data.current_version <<<"$current")" == "$new_version" ]]
umask 077
jq -n \
  --arg environment "$environment" --arg identity "$identity" \
  --arg path "$logical_path" --arg payloadSha256 "$expected_sha" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson previousVersion "$expected_version" --argjson currentVersion "$new_version" \
  '{schemaVersion:1,environment:$environment,serviceIdentity:$identity,sanitizedPath:$path,previousVersion:$previousVersion,currentVersion:$currentVersion,payloadSha256:$payloadSha256,agentRender:"PASS",newCredential:"PASS",oldCredentialRevoked:true,oldCredentialDenied:true,serviceHealth:"PASS",providerBusinessEffectsEnabled:false,secretValuesIncluded:false,rotation:"PASS",completedAt:$completedAt}' \
  > "$evidence"
chmod 0400 "$evidence"
cleanup
trap - EXIT

echo 'OPENBAO_ROTATION=PASS'
echo "ROTATION_PREVIOUS_VERSION=${expected_version}"
echo "ROTATION_CURRENT_VERSION=${new_version}"
echo 'OLD_CREDENTIAL_REVOKED=YES'
echo 'OLD_CREDENTIAL_ACCESS=DENIED'
echo 'PROVIDER_BUSINESS_EFFECTS_ENABLED=NO'
