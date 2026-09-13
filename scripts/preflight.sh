#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
expected_source="${CODESTRA_SOURCE_SHA:?set exact deployed source SHA}"
container="${OPENBAO_CONTAINER_NAME:-codestra-openbao}"
evidence="${OPENBAO_PREFLIGHT_EVIDENCE:?set sanitized preflight output path}"
[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$expected_source" =~ ^[0-9a-f]{40}$ ]]

status="$(bao status -format=json)"
[[ "$(jq -r .initialized <<<"$status")" == true ]]
[[ "$(jq -r .sealed <<<"$status")" == false ]]
[[ "$(jq -r .storage_type <<<"$status")" == raft ]]

peers="$(bao operator raft list-peers -format=json)"
peer_count="$(jq '[.data.config.servers[] | select(.voter == true)] | length' <<<"$peers")"
desired_peers="$(jq -r .desiredVotingNodes "config/environments/${environment}/environment.json")"
(( peer_count >= desired_peers ))

plugin_name="$(jq -r '.name' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_sha="$(jq -r '.binarySha256' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_binary="${OPENBAO_PLUGIN_BINARY:?set exact deployed plugin binary path}"
[[ -f "$plugin_binary" && ! -L "$plugin_binary" ]]
[[ "$(basename "$plugin_binary")" == "$plugin_name" ]]
[[ "$(sha256sum "$plugin_binary" | awk '{print $1}')" == "$plugin_sha" ]]

container_json="$(docker inspect "$container")"
[[ "$(jq -r '.[0].State.Running' <<<"$container_json")" == true ]]
actual_image="$(jq -r '.[0].Image' <<<"$container_json")"
expected_digest="$(jq -r .image_digest CODESTRA_UPSTREAM.json)"
image_json="$(docker image inspect "$actual_image")"
jq -e --arg expected "ghcr.io/openbao/openbao@${expected_digest}" \
  '.[0].RepoDigests | index($expected) != null' <<<"$image_json" > /dev/null
[[ "$(jq -r '.[0].Config.Labels["com.codestra.source-sha"] // ""' <<<"$container_json")" == "$expected_source" ]]
[[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs' <<<"$container_json")" == true ]]
[[ "$(jq '.[0].HostConfig.PortBindings // {} | length' <<<"$container_json")" == 0 ]]
plugin_mount_source="$(jq -r '.[0].Mounts[] | select(.Destination == "/openbao/plugins" and .RW == false) | .Source' <<<"$container_json")"
[[ -n "$plugin_mount_source" ]]
[[ "$(realpath "$plugin_mount_source")" == "$(realpath "$(dirname "$plugin_binary")")" ]]

for network_key in client cluster observability; do
  expected_network="$(jq -r --arg key "$network_key" '.networks[$key]' "config/environments/${environment}/environment.json")"
  jq -e --arg network "$expected_network" '.[0].NetworkSettings.Networks | has($network)' \
    <<<"$container_json" > /dev/null
done

memory_result="$(python3 scripts/validate_host_memory.py)"
grep -Fqx 'OPENBAO_HOST_MEMORY=PASS' <<<"$memory_result"

cluster_id="$(jq -r '.cluster_id // ""' <<<"$status")"
node_id="$(jq -r '.data.config.servers[] | select(.leader == true) | .node_id' <<<"$peers" | head -1)"
[[ -n "$cluster_id" && -n "$node_id" ]]
umask 077
jq -n \
  --arg environment "$environment" \
  --arg sourceSha "$expected_source" \
  --arg imageDigest "$expected_digest" \
  --arg clusterIdSha256 "$(printf '%s' "$cluster_id" | sha256sum | awk '{print $1}')" \
  --arg nodeId "$node_id" \
  --argjson votingPeers "$peer_count" \
  --argjson desiredVotingPeers "$desired_peers" \
  --arg jtiPluginSha256 "$plugin_sha" \
  '{schemaVersion:1,environment:$environment,sourceSha:$sourceSha,imageDigest:$imageDigest,initialized:true,sealed:false,storage:"raft",clusterIdSha256:$clusterIdSha256,nodeId:$nodeId,votingPeers:$votingPeers,desiredVotingPeers:$desiredVotingPeers,jtiReplayPluginBinarySha256:$jtiPluginSha256,privateNativePorts:true,readOnlyRoot:true,memoryProtection:"PASS",secretValuesIncluded:false,preflight:"PASS"}' \
  > "$evidence"
chmod 400 "$evidence"

echo 'OPENBAO_PREFLIGHT=PASS'
echo 'INITIALIZED=YES'
echo 'SEALED=NO'
echo 'RAFT_HEALTH=PASS'
echo "RAFT_VOTING_PEERS=${peer_count}"
echo 'IMAGE_DIGEST_MATCH=PASS'
echo 'SOURCE_SHA_MATCH=PASS'
echo 'JTI_REPLAY_PLUGIN_BINARY=PASS'
echo 'NATIVE_PUBLIC_PORTS=0'
