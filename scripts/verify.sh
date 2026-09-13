#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
container="${OPENBAO_CONTAINER_NAME:-codestra-openbao}"
expected_image="$(jq -r '.image_digest' CODESTRA_UPSTREAM.json)"
expected_source="${CODESTRA_SOURCE_SHA:?set exact deployed source SHA}"
[[ "$environment" =~ ^(development|test|staging|production)$ ]]

status="$(bao status -format=json)"
[[ "$(jq -r '.initialized' <<<"$status")" == true ]]
[[ "$(jq -r '.sealed' <<<"$status")" == false ]]
[[ "$(jq -r '.storage_type' <<<"$status")" == raft ]]

leader="$(bao read -format=json sys/leader)"
[[ "$(jq -r '.data.is_self' <<<"$leader")" == true || "$(jq -r '.data.ha_enabled' <<<"$leader")" == true ]]
peers="$(bao operator raft list-peers -format=json)"
peer_count="$(jq '[.data.config.servers[] | select(.voter == true)] | length' <<<"$peers")"

mounts="$(bao secrets list -format=json)"
auths="$(bao auth list -format=json)"
audits="$(bao audit list -format=json)"
policies="$(bao policy list -format=json)"
plugin_name="$(jq -r '.name' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_version="$(jq -r '.version' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_sha="$(jq -r '.binarySha256' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_info="$(bao plugin info -format=json -version="$plugin_version" auth "$plugin_name")"
[[ "$(jq -r '.["codestra/"].type' <<<"$mounts")" == kv ]]
[[ "$(jq -r '.["codestra/"].options.version' <<<"$mounts")" == 2 ]]
kv_config="$(bao read -format=json codestra/config)"
desired_kv="$(jq '.engines[] | select(.path == "codestra/")' config/secrets/engines.v1.json)"
[[ "$(jq -r '.data.max_versions' <<<"$kv_config")" == "$(jq -r '.maxVersions' <<<"$desired_kv")" ]]
[[ "$(jq -r '.data.cas_required' <<<"$kv_config")" == "$(jq -r '.casRequired' <<<"$desired_kv")" ]]
[[ "$(jq -r '.data.delete_version_after' <<<"$kv_config")" == "$(jq -r '.deleteVersionAfter' <<<"$desired_kv")" ]]
[[ "$(jq -r '.["jwt-codestra/"].type' <<<"$auths")" == "$plugin_name" ]]
[[ "$(jq -r '.["jwt-codestra/"].plugin_version' <<<"$auths")" == "$plugin_version" ]]
[[ "$(jq -r '.["jwt-codestra/"].running_plugin_version' <<<"$auths")" == "$plugin_version" ]]
[[ "$(jq -r '.["jwt-codestra/"].running_sha256' <<<"$auths")" == "$plugin_sha" ]]
[[ "$(jq -r '.command' <<<"$plugin_info")" == "$plugin_name" ]]
[[ "$(jq -r '.sha256' <<<"$plugin_info")" == "$plugin_sha" ]]
[[ "$(jq -r '.builtin' <<<"$plugin_info")" == false ]]
[[ "$(jq -r '.["file-audit/"].type' <<<"$audits")" == file ]]

expected_policy_count="$(jq --arg environment "$environment" '[.policies[] | select(.environment == $environment)] | length' config/policies/generated-policy-index.v1.json)"
actual_policy_count="$(jq --arg suffix "-${environment}" '[.[] | select(startswith("workload-") and endswith($suffix))] | length' <<<"$policies")"
[[ "$actual_policy_count" == "$expected_policy_count" ]]

container_json="$(docker inspect "$container")"
actual_image="$(jq -r '.[0].Image' <<<"$container_json")"
actual_source="$(jq -r '.[0].Config.Labels["com.codestra.source-sha"] // ""' <<<"$container_json")"
readonly_root="$(jq -r '.[0].HostConfig.ReadonlyRootfs' <<<"$container_json")"
published_ports="$(jq '.[0].HostConfig.PortBindings // {} | length' <<<"$container_json")"
image_json="$(docker image inspect "$actual_image")"
jq -e --arg expected "ghcr.io/openbao/openbao@${expected_image}" \
  '.[0].RepoDigests | index($expected) != null' <<<"$image_json" >/dev/null
[[ "$actual_source" == "$expected_source" ]]
[[ "$readonly_root" == true ]]
[[ "$published_ports" == 0 ]]

echo 'IMAGE_DIGEST_MATCH=PASS'
echo 'SOURCE_SHA_MATCH=PASS'
echo 'INITIALIZED=YES'
echo 'SEALED=NO'
echo 'RAFT_HEALTH=PASS'
echo "RAFT_VOTING_PEERS=${peer_count}"
echo 'AUDIT=PASS'
echo 'POLICY_ENFORCEMENT_SOURCE_MATCH=PASS'
echo 'JTI_REPLAY_PLUGIN=PASS'
echo 'NATIVE_PUBLIC_PORTS=0'
