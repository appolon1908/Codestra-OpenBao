#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
output="${OPENBAO_PLAN_OUTPUT:?set plan output path}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ ! -e "$output" && ! -e "$output.sha256" ]]
[[ -z "$(git status --porcelain)" ]] || {
  echo 'Plan source must be a clean exact commit.' >&2
  exit 2
}
source_sha="$(git rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]]
command -v bao >/dev/null
command -v jq >/dev/null

set +e
status_json="$(bao status -format=json 2>/dev/null)"
status_code=$?
set -e
[[ "$status_code" == 0 ]]
[[ "$(jq -r '.initialized' <<<"$status_json")" == true ]]
[[ "$(jq -r '.sealed' <<<"$status_json")" == false ]]

live_dir="$(mktemp -d)"
cleanup() {
  find "$live_dir" -type f -delete
  find "$live_dir" -depth -type d -empty -delete
}
trap cleanup EXIT
scripts/collect_live_state.sh "$environment" "$live_dir"
live_state_sha="$(python3 -m codestra.change_kernel.cli live-fingerprint --live-dir "$live_dir" | jq -r .liveStateSha256)"
[[ "$live_state_sha" =~ ^[0-9a-f]{64}$ ]]

python3 scripts/build_plan.py --environment "$environment" --live-dir "$live_dir" \
  --source-sha "$source_sha" --live-state-sha256 "$live_state_sha" --output "$output"
chmod 400 "$output"
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
chmod 400 "$output.sha256"

echo "PLAN_SOURCE_SHA=${source_sha}"
echo "PLAN_SHA256=$(awk '{print $1}' "$output.sha256")"
echo "PLAN_LIVE_STATE_SHA256=${live_state_sha}"
echo 'PROVISIONING_APPLY_RUN=NO'
