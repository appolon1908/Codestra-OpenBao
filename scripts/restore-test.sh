#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
artifact="${OPENBAO_RESTORE_ARTIFACT:?set encrypted snapshot path}"
checksum="${OPENBAO_RESTORE_CHECKSUM:?set snapshot checksum path}"
identity="${OPENBAO_AGE_IDENTITY_FILE:?set age identity path}"
production_cluster_id="${OPENBAO_PRODUCTION_CLUSTER_ID:?set production cluster ID for exclusion}"
evidence="${OPENBAO_RESTORE_EVIDENCE:?set evidence JSON output path}"
operator_token_file="${OPENBAO_OPERATOR_TOKEN_FILE:?set pre-restore operator token file}"
restored_probe_token_file="${OPENBAO_RESTORED_PROBE_TOKEN_FILE:?set protected token file for a token contained in the snapshot}"
restored_probe_policy="${OPENBAO_RESTORED_PROBE_EXPECTED_POLICY:?set the exact read-only restored probe policy}"

[[ "$environment" != production ]]
[[ "${OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED:-false}" == true ]]
[[ "$restored_probe_policy" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ ]]
case "${restored_probe_policy,,}" in
  default|root)
    echo 'Reserved default/root policies cannot certify a restore probe.' >&2
    exit 1
    ;;
esac
[[ -f "$artifact" && -f "$checksum" && -f "$identity" ]]
[[ -f "$operator_token_file" && ! -L "$operator_token_file" ]]
[[ -f "$restored_probe_token_file" && ! -L "$restored_probe_token_file" ]]
for command in age bao jq realpath sha256sum shred stat; do command -v "$command" >/dev/null; done

operator_token_real="$(realpath "$operator_token_file")"
restored_probe_token_real="$(realpath "$restored_probe_token_file")"
[[ "$operator_token_real" != "$restored_probe_token_real" ]]
if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
  workspace_real="$(realpath "$GITHUB_WORKSPACE")"
  [[ "$restored_probe_token_real" != "$workspace_real"/* ]]
fi
probe_token_mode="$(stat -c '%a' "$restored_probe_token_real")"
(( (8#$probe_token_mode & 077) == 0 ))

(cd "$(dirname "$artifact")" && sha256sum -c "$(basename "$checksum")") >/dev/null

pre_restore_token="${BAO_TOKEN:?set the pre-restore target operator token}"
pre_restore_token_sha="$(printf '%s' "$pre_restore_token" | sha256sum | awk '{print $1}')"
unset pre_restore_token

set +e
before="$(bao status -format=json 2>/dev/null)"
before_status=$?
set -e
[[ "$before_status" == 0 || "$before_status" == 2 ]]
target_cluster_id="$(jq -r '.cluster_id // ""' <<<"$before")"
[[ -n "$target_cluster_id" && "$target_cluster_id" != "$production_cluster_id" ]]
[[ "$BAO_ADDR" == *127.0.0.1* || "$BAO_ADDR" == *localhost* || "$BAO_ADDR" == *restore* ]]

umask 077
plain="$(mktemp)"
probe_token_loaded=false
cleanup() {
  if [[ "$probe_token_loaded" == true && -n "${BAO_TOKEN:-}" ]]; then
    bao token revoke -self >/dev/null 2>&1 || true
  fi
  unset BAO_TOKEN
  if [[ -n "${plain:-}" && -f "$plain" ]]; then
    shred --remove --zero "$plain" 2>/dev/null || true
  fi
}
trap cleanup EXIT

age --decrypt --identity "$identity" --output "$plain" "$artifact"
bao operator raft snapshot inspect "$plain" >/dev/null
bao operator raft snapshot restore -force "$plain" >/dev/null
shred --remove --zero "$plain"
plain=""

# The snapshot replaces the target token store. Never reuse the token that
# authorized the destructive restore for any post-restore certification read.
unset BAO_TOKEN
python3 "$(dirname "$0")/unseal_from_files.py"
after="$(bao status -format=json)"
[[ "$(jq -r '.initialized' <<<"$after")" == true ]]
[[ "$(jq -r '.sealed' <<<"$after")" == false ]]
restored_cluster_id="$(jq -r '.cluster_id' <<<"$after")"
[[ -n "$restored_cluster_id" ]]

restored_probe_token="$(< "$restored_probe_token_real")"
[[ -n "$restored_probe_token" ]]
restored_probe_token_sha="$(printf '%s' "$restored_probe_token" | sha256sum | awk '{print $1}')"
[[ "$restored_probe_token_sha" != "$pre_restore_token_sha" ]]
export BAO_TOKEN="$restored_probe_token"
unset restored_probe_token
probe_token_loaded=true

probe_lookup="$(bao token lookup -format=json)"
python3 "$(dirname "$0")/verify_restored_probe_token.py" \
  --expected-policy "$restored_probe_policy" \
  <<<"$probe_lookup"
unset probe_lookup

python3 "$(dirname "$0")/verify_secret_hash.py" \
  --path "${OPENBAO_RESTORE_PROBE_PATH:?set representative non-production probe path}" \
  --field "${OPENBAO_RESTORE_PROBE_FIELD:?set representative probe field}" \
  --expected-sha256 "${OPENBAO_RESTORE_PROBE_SHA256:?set expected probe hash}"

bao token revoke -self >/dev/null
set +e
bao token lookup -format=json >/dev/null 2>&1
revoked_probe_status=$?
set -e
[[ "$revoked_probe_status" -ne 0 ]]
probe_token_loaded=false
unset BAO_TOKEN

started_epoch="${OPENBAO_RESTORE_STARTED_EPOCH:?record restore test start epoch}"
completed_epoch="$(date +%s)"
duration="$((completed_epoch - started_epoch))"
jq -n \
  --arg environment "$environment" \
  --arg sourceArtifact "$(basename "$artifact")" \
  --arg sourceSha256 "$(awk '{print $1}' "$checksum")" \
  --arg restoredClusterIdHash "$(printf '%s' "$restored_cluster_id" | sha256sum | awk '{print $1}')" \
  --arg restoredProbePolicyHash "$(printf '%s' "$restored_probe_policy" | sha256sum | awk '{print $1}')" \
  --argjson durationSeconds "$duration" \
  '{schemaVersion:2,environment:$environment,isolated:true,sourceArtifact:$sourceArtifact,sourceSha256:$sourceSha256,restoredClusterIdHash:$restoredClusterIdHash,durationSeconds:$durationSeconds,initialized:true,sealed:false,restoredProbeCredentialDistinct:true,restoredProbePolicyHash:$restoredProbePolicyHash,restoredProbeTokenRevoked:true,representativeSecretHashVerified:true,restore:"PASS"}' \
  > "$evidence"
chmod 400 "$evidence"
echo 'OPENBAO_RESTORE=PASS'
echo "RESTORE_DURATION_SECONDS=${duration}"
