#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
source_sha="${CODESTRA_SOURCE_SHA:?set exact protected source SHA}"
container="${OPENBAO_CONTAINER_NAME:?set reviewed container name}"
runtime_root="${OPENBAO_RUNTIME_ROOT:?set protected runtime root}"
data_dir="${OPENBAO_DATA_DIR:?set existing Raft data directory}"
audit_dir="${OPENBAO_AUDIT_DIR:?set protected audit directory}"
plugin_source="${OPENBAO_PLUGIN_BINARY:?set exact verified plugin binary}"
evidence="${OPENBAO_RUNTIME_DEPLOY_EVIDENCE:?set sanitized evidence path}"
confirmation="${OPENBAO_RUNTIME_CONFIRMATION:-}"
release_id="${OPENBAO_RELEASE_ID:-NOT_APPLICABLE}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$source_sha" ]]
[[ -z "$(git status --porcelain)" ]]
[[ "$confirmation" == "DEPLOY_EXACT_OPENBAO_RUNTIME_${source_sha}" ]]
[[ "$(jq -r .runtimeApplyAuthorized "config/environments/${environment}/environment.json")" == true ]]
[[ "$(jq -r .runtimeApplyAuthorized plugins/codestra-jwt-replay/plugin.v1.json)" == true ]]
python3 scripts/verify_vulnerability_gate.py >/dev/null
scripts/verify_environment_approval.sh

for command in docker jq openssl sha256sum stat; do command -v "$command" >/dev/null; done
for path in "$runtime_root" "$data_dir" "$audit_dir"; do
  [[ -d "$path" && ! -L "$path" ]]
done
for path in \
  "$OPENBAO_SERVER_CERT_FILE" "$OPENBAO_SERVER_KEY_FILE" \
  "$CODESTRA_CLIENT_CA_FILE" "$OPENBAO_HEALTH_CLIENT_CERT_FILE" \
  "$OPENBAO_HEALTH_CLIENT_KEY_FILE" "$plugin_source"; do
  [[ -f "$path" && ! -L "$path" ]]
done

check_private_key() {
  local path="$1" mode uid gid
  mode="$(stat -c %a "$path")"
  uid="$(stat -c %u "$path")"
  gid="$(stat -c %g "$path")"
  (( (8#$mode & 007) == 0 ))
  if [[ "$uid" == 100 ]]; then
    (( (8#$mode & 0400) != 0 ))
  elif [[ "$gid" == 1000 ]]; then
    (( (8#$mode & 0040) != 0 ))
  else
    echo "Private key is not readable by the OpenBao UID/GID: $path" >&2
    return 1
  fi
}
check_readable_file() {
  local path="$1" mode uid gid
  mode="$(stat -c %a "$path")"
  uid="$(stat -c %u "$path")"
  gid="$(stat -c %g "$path")"
  if [[ "$uid" == 100 ]]; then
    (( (8#$mode & 0400) != 0 ))
  elif [[ "$gid" == 1000 ]]; then
    (( (8#$mode & 0040) != 0 ))
  else
    (( (8#$mode & 0004) != 0 ))
  fi
}
check_writable_directory() {
  local path="$1" mode uid gid
  mode="$(stat -c %a "$path")"
  uid="$(stat -c %u "$path")"
  gid="$(stat -c %g "$path")"
  (( (8#$mode & 0007) == 0 ))
  if [[ "$uid" == 100 ]]; then
    (( (8#$mode & 0700) == 0700 ))
  elif [[ "$gid" == 1000 ]]; then
    (( (8#$mode & 0070) == 0070 ))
  else
    echo "Directory is not writable by the OpenBao UID/GID: $path" >&2
    return 1
  fi
}
check_private_key "$OPENBAO_SERVER_KEY_FILE"
check_private_key "$OPENBAO_HEALTH_CLIENT_KEY_FILE"
check_readable_file "$OPENBAO_SERVER_CERT_FILE"
check_readable_file "$CODESTRA_CLIENT_CA_FILE"
check_readable_file "$OPENBAO_HEALTH_CLIENT_CERT_FILE"
check_writable_directory "$data_dir"
check_writable_directory "$audit_dir"
scripts/verify_tls_material.sh

expected_plugin_sha="$(jq -r .binarySha256 plugins/codestra-jwt-replay/plugin.v1.json)"
expected_digest="$(jq -r .image_digest CODESTRA_UPSTREAM.json)"
[[ "$(basename "$plugin_source")" == "$(jq -r .name plugins/codestra-jwt-replay/plugin.v1.json)" ]]
[[ "$(sha256sum "$plugin_source" | awk '{print $1}')" == "$expected_plugin_sha" ]]

release_bundle_sha=''
if [[ "$environment" == production ]]; then
  [[ "$release_id" =~ ^openbao-v[0-9]+\.[0-9]+\.[0-9]+-[0-9]{8}\.[0-9]+$ ]]
  release_evidence="${OPENBAO_RELEASE_EVIDENCE:?production requires verified immutable release evidence}"
  [[ -f "$release_evidence" && ! -L "$release_evidence" ]]
  jq -e --arg releaseId "$release_id" --arg sourceSha "$source_sha" \
    --arg imageDigest "$expected_digest" --arg pluginSha256 "$expected_plugin_sha" '
    .schemaVersion == 1 and .releaseId == $releaseId and
    .sourceSha == $sourceSha and .imageDigest == $imageDigest and
    .pluginSha256 == $pluginSha256 and
    .immutable == true and .checksumVerified == true and
    .signatureVerified == true and .secretValuesIncluded == false
  ' "$release_evidence" >/dev/null
  release_bundle_sha="$(jq -r .bundleSha256 "$release_evidence")"
  [[ "$release_bundle_sha" =~ ^[0-9a-f]{64}$ ]]
  backup_evidence="${OPENBAO_PRECHANGE_BACKUP_EVIDENCE:?production runtime deployment requires backup evidence}"
  jq -e '
    .schemaVersion == 1 and .environment == "production" and
    .backup == "PASS" and .offHostBackup == "PASS" and
    .checksumVerified == true and .immutabilityVerified == true
  ' "$backup_evidence" >/dev/null
  ssh_before="$(dirname "$evidence")/ssh-before-runtime.json"
  scripts/capture_ssh_baseline.sh "$ssh_before" >/dev/null
fi

for key in client cluster observability; do
  network="$(jq -r --arg key "$key" '.networks[$key]' "config/environments/${environment}/environment.json")"
  docker network inspect "$network" >/dev/null
done

release_dir="${runtime_root%/}/releases/${source_sha}"
if [[ -e "$release_dir" ]]; then
  [[ -d "$release_dir" && ! -L "$release_dir" ]]
  (cd "$release_dir" && sha256sum -c SHA256SUMS) >/dev/null
  [[ "$(sha256sum "$release_dir/plugins/$(basename "$plugin_source")" | awk '{print $1}')" == "$expected_plugin_sha" ]]
else
  umask 077
  partial_release="${runtime_root%/}/releases/.${source_sha}.partial.$PPID"
  [[ ! -e "$partial_release" ]]
  mkdir -p "$partial_release/plugins"
  python3 scripts/render_openbao_config.py "$environment" --output "$partial_release/openbao.hcl"
  install -m 0555 "$plugin_source" "$partial_release/plugins/$(basename "$plugin_source")"
  (
    cd "$partial_release"
    sha256sum openbao.hcl "plugins/$(basename "$plugin_source")" > SHA256SUMS
  )
  chmod 0400 "$partial_release/openbao.hcl" "$partial_release/SHA256SUMS"
  mv "$partial_release" "$release_dir"
fi

image="$(jq -r .image_reference CODESTRA_UPSTREAM.json)"
docker pull --platform linux/amd64 "$image" >/dev/null
image_json="$(docker image inspect "$image")"
jq -e --arg expected "ghcr.io/openbao/openbao@${expected_digest}" \
  '.[0].RepoDigests | index($expected) != null' <<<"$image_json" >/dev/null

previous_container=''
previous_image=''
previous_source=''
if docker inspect "$container" >/dev/null 2>&1; then
  previous_image="$(docker inspect "$container" --format '{{.Image}}')"
  previous_source="$(docker inspect "$container" --format '{{index .Config.Labels "com.codestra.source-sha"}}')"
  previous_container="${container}-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
  docker stop --time 90 "$container" >/dev/null
  docker rename "$container" "$previous_container"
fi

export OPENBAO_NODE_ID="$(jq -r .nodeId "config/environments/${environment}/environment.json")"
export OPENBAO_CONFIG_FILE="$release_dir/openbao.hcl"
export OPENBAO_PLUGIN_DIR="$release_dir/plugins"
export OPENBAO_CLIENT_NETWORK="$(jq -r .networks.client "config/environments/${environment}/environment.json")"
export OPENBAO_CLUSTER_NETWORK="$(jq -r .networks.cluster "config/environments/${environment}/environment.json")"
export OPENBAO_OBSERVABILITY_NETWORK="$(jq -r .networks.observability "config/environments/${environment}/environment.json")"
project="codestra-openbao-${environment}-${source_sha:0:12}"

rollback_failed_start() {
  if docker inspect "$container" >/dev/null 2>&1; then
    docker stop --time 30 "$container" >/dev/null 2>&1 || true
    docker rename "$container" "${container}-failed-$(date -u +%Y%m%dT%H%M%SZ)" \
      >/dev/null 2>&1 || true
  fi
  if [[ -n "$previous_container" ]]; then
    docker rename "$previous_container" "$container" >/dev/null 2>&1 || true
    docker start "$container" >/dev/null 2>&1 || true
  fi
}
trap rollback_failed_start ERR
docker compose --project-name "$project" -f deploy/compose/compose.yaml \
  up --detach --no-build --pull never

container_json="$(docker inspect "$container")"
[[ "$(jq -r '.[0].State.Running' <<<"$container_json")" == true ]]
[[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs' <<<"$container_json")" == true ]]
[[ "$(jq '.[0].HostConfig.PortBindings // {} | length' <<<"$container_json")" == 0 ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.source-sha"]' <<<"$container_json")" == "$source_sha" ]]
[[ "$(jq -r '.[0].Config.Labels["com.codestra.image-digest"]' <<<"$container_json")" == "$expected_digest" ]]
trap - ERR

if [[ "$environment" == production ]]; then
  ssh_after="$(dirname "$evidence")/ssh-after-runtime.json"
  scripts/capture_ssh_baseline.sh "$ssh_after" >/dev/null
  python3 scripts/verify_ssh_unchanged.py "$ssh_before" "$ssh_after" \
    > "$(dirname "$evidence")/ssh-runtime-status.txt"
fi

umask 077
jq -n \
  --arg environment "$environment" --arg sourceSha "$source_sha" \
  --arg imageDigest "$expected_digest" --arg container "$container" \
  --arg previousContainer "$previous_container" --arg previousImageId "$previous_image" \
  --arg previousSourceSha "$previous_source" --arg pluginSha256 "$expected_plugin_sha" \
  --arg releaseId "$release_id" --arg releaseBundleSha256 "$release_bundle_sha" \
  --arg deployedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,imageDigest:$imageDigest,releaseId:$releaseId,releaseBundleSha256:$releaseBundleSha256,container:$container,previousContainerRetained:$previousContainer,previousImageId:$previousImageId,previousSourceSha:$previousSourceSha,pluginSha256:$pluginSha256,deployedAt:$deployedAt,raftDataDeleted:false,nativePortsPublished:0,readOnlyRoot:true,secretValuesIncluded:false,runtimeDeploy:"PASS"}' \
  > "$evidence"
chmod 0400 "$evidence"

echo 'OPENBAO_RUNTIME_DEPLOY=PASS'
echo "RUNTIME_SOURCE_SHA=${source_sha}"
echo 'RAFT_DATA_DELETED=NO'
echo 'NATIVE_PUBLIC_PORTS=0'
echo 'SSH_CHANGED=NO'
echo "PREVIOUS_CONTAINER_RETAINED=${previous_container:-NONE}"
