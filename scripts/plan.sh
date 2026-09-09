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
mkdir "$live_dir/policies" "$live_dir/jwt-roles"

bao secrets list -format=json > "$live_dir/mounts.json"
bao auth list -format=json > "$live_dir/auth.json"
bao audit list -format=json > "$live_dir/audit.json"
bao policy list -format=json > "$live_dir/policies.json"

if jq -e '."codestra/".type == "kv" and ."codestra/".options.version == "2"' \
  "$live_dir/mounts.json" >/dev/null; then
  bao read -format=json codestra/config > "$live_dir/codestra-config.json"
else
  printf '{}\n' > "$live_dir/codestra-config.json"
fi

mount="$(jq -r '.mount' openbao/auth/jwt-roles.v1.json)"
plugin="$(jq -r '.name' plugins/codestra-jwt-replay/plugin.v1.json)"
plugin_version="$(jq -r '.version' plugins/codestra-jwt-replay/plugin.v1.json)"
set +e
bao plugin info -format=json -version="$plugin_version" auth "$plugin" > "$live_dir/plugin-info.json" 2>/dev/null
plugin_status=$?
set -e
if [[ "$plugin_status" != 0 ]]; then printf '{}\n' > "$live_dir/plugin-info.json"; fi

if jq -e --arg path "${mount}/" --arg plugin "$plugin" '.[$path].type == $plugin' "$live_dir/auth.json" >/dev/null; then
  bao read -format=json "auth/${mount}/config" > "$live_dir/jwt-config.json"
  set +e
  bao list -format=json "auth/${mount}/cel/role" > "$live_dir/jwt-roles.json" 2>/dev/null
  list_status=$?
  set -e
  if [[ "$list_status" != 0 ]]; then printf '[]\n' > "$live_dir/jwt-roles.json"; fi
else
  printf '{}\n' > "$live_dir/jwt-config.json"
  printf '[]\n' > "$live_dir/jwt-roles.json"
fi

while IFS= read -r name; do
  if jq -e --arg name "$name" 'index($name) != null' "$live_dir/policies.json" >/dev/null; then
    bao policy read "$name" > "$live_dir/policies/${name}.hcl"
  fi
done < <(jq -r --arg environment "$environment" '.policies[] | select(.environment == $environment) | .policyName' config/policies/generated-policy-index.v1.json)

if [[ -s "$live_dir/jwt-roles.json" ]]; then
  while IFS= read -r name; do
    if jq -e --arg name "$name" 'index($name) != null' "$live_dir/jwt-roles.json" >/dev/null; then
      bao read -format=json "auth/${mount}/cel/role/${name}" > "$live_dir/jwt-roles/${name}.json"
    fi
  done < <(jq -r --arg suffix "-${environment}" '.roles[] | select(.name | endswith($suffix)) | .name' openbao/auth/jwt-roles.v1.json)
fi

python3 scripts/build_plan.py --environment "$environment" --live-dir "$live_dir" \
  --source-sha "$source_sha" --output "$output"
chmod 400 "$output"
(cd "$(dirname "$output")" && sha256sum "$(basename "$output")" > "$(basename "$output").sha256")
chmod 400 "$output.sha256"

echo "PLAN_SOURCE_SHA=${source_sha}"
echo "PLAN_SHA256=$(awk '{print $1}' "$output.sha256")"
echo 'PROVISIONING_APPLY_RUN=NO'
