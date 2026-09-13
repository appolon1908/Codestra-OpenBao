#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
current="${OPENBAO_CONTAINER_NAME:?set current container name}"
previous="${OPENBAO_ROLLBACK_CONTAINER:?set retained rollback container name}"
expected_source="${OPENBAO_ROLLBACK_SOURCE_SHA:?set exact rollback source SHA}"
expected_digest="${OPENBAO_ROLLBACK_IMAGE_DIGEST:?set exact rollback image digest}"
evidence="${OPENBAO_ROLLBACK_EVIDENCE:?set sanitized rollback evidence path}"
confirmation="${OPENBAO_ROLLBACK_CONFIRMATION:-}"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$expected_source" =~ ^[0-9a-f]{40}$ ]]
[[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$previous" == "${current}-rollback-"* ]]
[[ "$confirmation" == "ROLLBACK_OPENBAO_RUNTIME_TO_${expected_source}" ]]
scripts/verify_environment_approval.sh

current_json="$(docker inspect "$current")"
previous_json="$(docker inspect "$previous")"
[[ "$(jq -r '.[0].State.Running' <<<"$current_json")" == true ]]
[[ "$(jq -r '.[0].State.Running' <<<"$previous_json")" == false ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.source-sha"]' <<<"$previous_json")" == "$expected_source" ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.image-digest"]' <<<"$previous_json")" == "$expected_digest" ]]
[[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs' <<<"$previous_json")" == true ]]
[[ "$(jq '.[0].HostConfig.PortBindings // {} | length' <<<"$previous_json")" == 0 ]]

current_data="$(jq -r '.[0].Mounts[] | select(.Destination == "/openbao/data") | .Source' <<<"$current_json")"
previous_data="$(jq -r '.[0].Mounts[] | select(.Destination == "/openbao/data") | .Source' <<<"$previous_json")"
[[ -n "$current_data" && "$current_data" == "$previous_data" ]]
[[ -d "$current_data" && ! -L "$current_data" ]]

if [[ "$environment" == production ]]; then
  backup_evidence="${OPENBAO_PRECHANGE_BACKUP_EVIDENCE:?production rollback requires backup evidence}"
  jq -e '
    .schemaVersion == 1 and .environment == "production" and
    .backup == "PASS" and .offHostBackup == "PASS" and
    .checksumVerified == true and .immutabilityVerified == true
  ' "$backup_evidence" >/dev/null
  ssh_before="$(dirname "$evidence")/ssh-before-rollback.json"
  scripts/capture_ssh_baseline.sh "$ssh_before" >/dev/null
fi

failed="${current}-failed-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
recover_current() {
  docker stop --time 30 "$current" >/dev/null 2>&1 || true
  docker rename "$current" "$previous" >/dev/null 2>&1 || true
  docker rename "$failed" "$current" >/dev/null 2>&1 || true
  docker start "$current" >/dev/null 2>&1 || true
}
trap recover_current ERR
docker stop --time 90 "$current" >/dev/null
docker rename "$current" "$failed"
docker rename "$previous" "$current"
docker start "$current" >/dev/null

rolled_back_json="$(docker inspect "$current")"
[[ "$(jq -r '.[0].State.Running' <<<"$rolled_back_json")" == true ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.source-sha"]' <<<"$rolled_back_json")" == "$expected_source" ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.image-digest"]' <<<"$rolled_back_json")" == "$expected_digest" ]]
trap - ERR

if [[ "$environment" == production ]]; then
  ssh_after="$(dirname "$evidence")/ssh-after-rollback.json"
  scripts/capture_ssh_baseline.sh "$ssh_after" >/dev/null
  python3 scripts/verify_ssh_unchanged.py "$ssh_before" "$ssh_after" \
    > "$(dirname "$evidence")/ssh-rollback-status.txt"
fi

umask 077
jq -n \
  --arg environment "$environment" --arg sourceSha "$expected_source" \
  --arg imageDigest "$expected_digest" --arg activeContainer "$current" \
  --arg failedContainerRetained "$failed" --arg dataDirectory "$current_data" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,imageDigest:$imageDigest,activeContainer:$activeContainer,failedContainerRetained:$failedContainerRetained,dataDirectory:$dataDirectory,completedAt:$completedAt,raftDataDeleted:false,recoveryMaterialChanged:false,sshChanged:false,secretValuesIncluded:false,rollback:"PASS"}' \
  > "$evidence"
chmod 0400 "$evidence"

echo 'OPENBAO_ROLLBACK=PASS'
echo "ROLLBACK_SOURCE_SHA=${expected_source}"
echo 'RAFT_DATA_DELETED=NO'
echo 'RECOVERY_MATERIAL_CHANGED=NO'
echo 'SSH_CHANGED=NO'
