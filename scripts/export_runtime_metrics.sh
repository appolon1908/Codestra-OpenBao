#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
metric_file="${OPENBAO_RUNTIME_METRIC_FILE:?set node-exporter textfile path}"
container="${OPENBAO_CONTAINER_NAME:?set exact OpenBao container name}"
data_dir="${OPENBAO_DATA_DIR:?set exact OpenBao data directory}"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ -d "$data_dir" && ! -L "$data_dir" ]]
[[ -d "$(dirname "$metric_file")" && ! -L "$(dirname "$metric_file")" ]]
[[ ! -L "$metric_file" ]]
for command in bao docker jq stat; do command -v "$command" >/dev/null; done

set +e
status="$(bao status -format=json 2>/dev/null)"
status_code=$?
set -e
[[ "$status_code" == 0 || "$status_code" == 2 ]]
initialized="$(jq -r 'if .initialized == true then 1 else 0 end' <<<"$status")"
sealed="$(jq -r 'if .sealed == true then 1 else 0 end' <<<"$status")"

voting_peers=0
if [[ "$initialized" == 1 && "$sealed" == 0 ]]; then
  peers="$(bao operator raft list-peers -format=json)"
  voting_peers="$(jq '[.data.config.servers[] | select(.voter == true)] | length' <<<"$peers")"
fi
desired_peers="$(jq -r .desiredVotingNodes "config/environments/${environment}/environment.json")"
restart_count="$(docker inspect "$container" | jq -r '.[0].RestartCount')"
block_size="$(stat -f -c %S "$data_dir")"
free_blocks="$(stat -f -c %a "$data_dir")"
total_blocks="$(stat -f -c %b "$data_dir")"
free_bytes="$((block_size * free_blocks))"
size_bytes="$((block_size * total_blocks))"

umask 077
partial="${metric_file}.partial.$PPID"
cleanup() { find "$partial" -type f -delete 2>/dev/null || true; }
trap cleanup EXIT
{
  printf '# HELP codestra_openbao_initialized Sanitized OpenBao initialization state.\n'
  printf '# TYPE codestra_openbao_initialized gauge\n'
  printf 'codestra_openbao_initialized{environment="%s"} %s\n' "$environment" "$initialized"
  printf '# HELP codestra_openbao_sealed Sanitized OpenBao seal state.\n'
  printf '# TYPE codestra_openbao_sealed gauge\n'
  printf 'codestra_openbao_sealed{environment="%s"} %s\n' "$environment" "$sealed"
  printf '# HELP codestra_openbao_raft_voting_peers Current Raft voters.\n'
  printf '# TYPE codestra_openbao_raft_voting_peers gauge\n'
  printf 'codestra_openbao_raft_voting_peers{environment="%s"} %s\n' "$environment" "$voting_peers"
  printf '# HELP codestra_openbao_raft_desired_voting_peers Protected desired Raft voters.\n'
  printf '# TYPE codestra_openbao_raft_desired_voting_peers gauge\n'
  printf 'codestra_openbao_raft_desired_voting_peers{environment="%s"} %s\n' "$environment" "$desired_peers"
  printf '# HELP codestra_openbao_container_restarts_total Current container restart counter.\n'
  printf '# TYPE codestra_openbao_container_restarts_total counter\n'
  printf 'codestra_openbao_container_restarts_total{environment="%s"} %s\n' "$environment" "$restart_count"
  printf '# HELP codestra_openbao_filesystem_free_bytes Data filesystem free bytes.\n'
  printf '# TYPE codestra_openbao_filesystem_free_bytes gauge\n'
  printf 'codestra_openbao_filesystem_free_bytes{environment="%s"} %s\n' "$environment" "$free_bytes"
  printf '# HELP codestra_openbao_filesystem_size_bytes Data filesystem size bytes.\n'
  printf '# TYPE codestra_openbao_filesystem_size_bytes gauge\n'
  printf 'codestra_openbao_filesystem_size_bytes{environment="%s"} %s\n' "$environment" "$size_bytes"
} > "$partial"
chmod 0644 "$partial"
mv "$partial" "$metric_file"
trap - EXIT

echo 'OPENBAO_RUNTIME_METRICS_EXPORT=PASS'
echo "OPENBAO_INITIALIZED=${initialized}"
echo "OPENBAO_SEALED=${sealed}"
echo "OPENBAO_RAFT_VOTING_PEERS=${voting_peers}"
