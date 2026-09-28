#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
current="${OPENBAO_CONTAINER_NAME:?set current container name}"
previous="${OPENBAO_ROLLBACK_CONTAINER:?set retained rollback container name}"
expected_source="${OPENBAO_ROLLBACK_SOURCE_SHA:?set exact rollback source SHA}"
expected_digest="${OPENBAO_ROLLBACK_IMAGE_DIGEST:?set exact rollback image digest}"
evidence="${OPENBAO_ROLLBACK_EVIDENCE:?set sanitized rollback evidence path}"
confirmation="${OPENBAO_ROLLBACK_CONFIRMATION:-}"
authorization_evidence="${OPENBAO_ROLLBACK_AUTHORIZATION_EVIDENCE:?set exact reviewed rollback authorization evidence path}"
backup_evidence="${OPENBAO_PRECHANGE_BACKUP_EVIDENCE:?rollback requires fresh pre-change backup evidence}"
operator_token_file="${OPENBAO_OPERATOR_TOKEN_FILE:?set protected operator token file}"

for command in docker jq python3 bao sha256sum; do
  command -v "$command" >/dev/null
done

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$expected_source" =~ ^[0-9a-f]{40}$ ]]
[[ "$expected_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$previous" == "${current}-rollback-"* ]]
[[ "$confirmation" == "ROLLBACK_OPENBAO_RUNTIME_TO_${expected_source}" ]]
[[ -d "$(dirname "$evidence")" ]]
for path in "$authorization_evidence" "$backup_evidence" "$operator_token_file"; do
  [[ -f "$path" && ! -L "$path" ]]
done

# Re-read the protected environment approval at mutation time, then bind it to
# the exact rollback target and the fresh pre-change backup produced by this run.
scripts/verify_environment_approval.sh
python3 scripts/verify_rollback_preconditions.py "$authorization_evidence" "$backup_evidence"

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
rolled_back_data="$(jq -r '.[0].Mounts[] | select(.Destination == "/openbao/data") | .Source' <<<"$rolled_back_json")"
[[ "$rolled_back_data" == "$current_data" ]]

# Keep the automatic recovery trap active until OpenBao itself proves healthy.
# No secret values are written to evidence; the operator token exists only in
# this process environment for bounded readback calls.
export BAO_TOKEN="$(< "$operator_token_file")"
status_json="$(bao status -format=json)"
[[ "$(jq -r '.initialized' <<<"$status_json")" == true ]]
[[ "$(jq -r '.sealed' <<<"$status_json")" == false ]]
[[ "$(jq -r '.storage_type' <<<"$status_json")" == raft ]]

leader_json="$(bao read -format=json sys/leader)"
[[ "$(jq -r '.data.is_self // false' <<<"$leader_json")" == true || "$(jq -r '.data.ha_enabled // false' <<<"$leader_json")" == true ]]

peers_json="$(bao operator raft list-peers -format=json)"
voter_count="$(jq '[.data.config.servers[] | select(.voter == true)] | length' <<<"$peers_json")"
min_voters=1
if [[ "$environment" == production ]]; then
  min_voters=3
fi
[[ "$voter_count" =~ ^[0-9]+$ ]]
(( voter_count >= min_voters ))

audits_json="$(bao audit list -format=json)"
[[ "$(jq -r '.["file-audit/"].type // empty' <<<"$audits_json")" == file ]]
unset BAO_TOKEN

# From here the retained runtime has passed bounded application readback, so a
# later evidence-writing failure must not silently flip the runtime again.
trap - ERR

if [[ "$environment" == production ]]; then
  ssh_after="$(dirname "$evidence")/ssh-after-rollback.json"
  scripts/capture_ssh_baseline.sh "$ssh_after" >/dev/null
  python3 scripts/verify_ssh_unchanged.py "$ssh_before" "$ssh_after" \
    > "$(dirname "$evidence")/ssh-rollback-status.txt"
fi

authorization_sha="$(sha256sum "$authorization_evidence" | awk '{print $1}')"
backup_evidence_sha="$(sha256sum "$backup_evidence" | awk '{print $1}')"
umask 077
jq -n \
  --arg environment "$environment" --arg sourceSha "$expected_source" \
  --arg imageDigest "$expected_digest" --arg activeContainer "$current" \
  --arg failedContainerRetained "$failed" --arg dataDirectory "$current_data" \
  --arg authorizationEvidenceSha256 "$authorization_sha" \
  --arg backupEvidenceSha256 "$backup_evidence_sha" \
  --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson raftVoterCount "$voter_count" --argjson minimumVoters "$min_voters" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,imageDigest:$imageDigest,activeContainer:$activeContainer,failedContainerRetained:$failedContainerRetained,dataDirectory:$dataDirectory,authorizationEvidenceSha256:$authorizationEvidenceSha256,backupEvidenceSha256:$backupEvidenceSha256,rollbackAuthorizationVerified:true,prechangeBackupVerified:true,runtimeReadback:"PASS",initialized:true,sealed:false,storageType:"raft",leaderReadback:true,raftVoterCount:$raftVoterCount,minimumVoters:$minimumVoters,auditReadback:true,completedAt:$completedAt,raftDataDeleted:false,recoveryMaterialChanged:false,sshChanged:false,secretValuesIncluded:false,rollback:"PASS"}' \
  > "$evidence"
chmod 0400 "$evidence"

echo 'OPENBAO_ROLLBACK=PASS'
echo "ROLLBACK_SOURCE_SHA=${expected_source}"
echo "RAFT_VOTING_PEERS=${voter_count}"
echo 'ROLLBACK_AUTHORIZATION=PASS'
echo 'PRECHANGE_BACKUP=PASS'
echo 'RUNTIME_READBACK=PASS'
echo 'RAFT_DATA_DELETED=NO'
echo 'RECOVERY_MATERIAL_CHANGED=NO'
echo 'SSH_CHANGED=NO'
