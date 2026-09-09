#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
backup_root="${OPENBAO_BACKUP_ROOT:?set protected local backup directory}"
recipient_file="${OPENBAO_AGE_RECIPIENT_FILE:?set age recipient file}"
identity_file="${OPENBAO_AGE_IDENTITY_FILE:?set age identity for verification}"
offhost_remote="${OPENBAO_OFFHOST_REMOTE:?set immutable rclone destination}"
immutability_attestation="${OPENBAO_OFFHOST_IMMUTABILITY_ATTESTATION:?set storage attestation JSON}"
evidence="${OPENBAO_BACKUP_EVIDENCE:-}"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
for command in bao jq age rclone sha256sum shred; do
  command -v "$command" >/dev/null
done
for path in "$recipient_file" "$identity_file" "$immutability_attestation"; do
  [[ -f "$path" && ! -L "$path" ]]
done
jq -e --arg remote "$offhost_remote" '
  .schemaVersion == 1 and
  .remote == $remote and
  .objectLockEnabled == true and
  .retentionDays >= 30 and
  (.owner | type == "string" and length > 0) and
  (.verifiedAt | type == "string" and length > 0)
' "$immutability_attestation" >/dev/null

set +e
status_json="$(bao status -format=json 2>/dev/null)"
status_code=$?
set -e
[[ "$status_code" == 0 ]]
[[ "$(jq -r '.initialized' <<<"$status_json")" == true ]]
[[ "$(jq -r '.sealed' <<<"$status_json")" == false ]]

umask 077
mkdir -p "$backup_root"
chmod 700 "$backup_root"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="openbao-${environment}-${timestamp}.raft.snap"
plain="$(mktemp "$backup_root/.${base}.plain.XXXXXX")"
verified="$(mktemp "$backup_root/.${base}.verified.XXXXXX")"
encrypted_partial="$backup_root/.${base}.age.partial"
artifact="$backup_root/${base}.age"
checksum="$artifact.sha256"

cleanup() {
  for path in "$plain" "$verified" "$encrypted_partial"; do
    if [[ -f "$path" ]]; then
      shred --remove --zero "$path" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT
[[ ! -e "$artifact" && ! -e "$checksum" ]]

bao operator raft snapshot save "$plain" >/dev/null
[[ -s "$plain" ]]
plain_sha="$(sha256sum "$plain" | awk '{print $1}')"
age --encrypt --recipients-file "$recipient_file" --output "$encrypted_partial" "$plain"
age --decrypt --identity "$identity_file" --output "$verified" "$encrypted_partial"
[[ "$(sha256sum "$verified" | awk '{print $1}')" == "$plain_sha" ]]
bao operator raft snapshot inspect "$verified" >/dev/null

chmod 400 "$encrypted_partial"
mv "$encrypted_partial" "$artifact"
artifact_sha="$(sha256sum "$artifact" | awk '{print $1}')"
printf '%s  %s\n' "$artifact_sha" "$(basename "$artifact")" > "$checksum"
chmod 400 "$checksum"

rclone copyto --immutable --no-traverse --quiet "$artifact" "$offhost_remote/$(basename "$artifact")"
rclone copyto --immutable --no-traverse --quiet "$checksum" "$offhost_remote/$(basename "$checksum")"
remote_checksum="$(rclone cat "$offhost_remote/$(basename "$checksum")")"
[[ "$remote_checksum" == "$(cat "$checksum")" ]]

if [[ -n "$evidence" ]]; then
  jq -n \
    --arg environment "$environment" \
    --arg artifact "$(basename "$artifact")" \
    --arg sha256 "$artifact_sha" \
    --arg completedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson sizeBytes "$(stat -c %s "$artifact")" \
    '{schemaVersion:1,environment:$environment,artifact:$artifact,sha256:$sha256,sizeBytes:$sizeBytes,completedAt:$completedAt,backup:"PASS",offHostBackup:"PASS",checksumVerified:true,immutabilityVerified:true,secretValuesIncluded:false}' \
    > "$evidence"
  chmod 400 "$evidence"
fi

cleanup
trap - EXIT
echo 'OPENBAO_BACKUP=PASS'
echo 'OPENBAO_OFFHOST_BACKUP=PASS'
echo "BACKUP_ARTIFACT=$(basename "$artifact")"
echo "BACKUP_SHA256=${artifact_sha}"
echo "BACKUP_SIZE_BYTES=$(stat -c %s "$artifact")"
