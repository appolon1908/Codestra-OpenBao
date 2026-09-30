#!/usr/bin/env bash
# Read sanitized live OpenBao metadata into an empty directory.
#
# Used by plan.sh to build a plan and by apply.sh to prove, just before the
# change kernel acts, that live state still matches the state the reviewed plan
# was built from. Reads only: no secret values, no writes to OpenBao.
set -Eeuo pipefail

environment="${1:?usage: collect_live_state.sh ENVIRONMENT EMPTY_DIRECTORY}"
live_dir="${2:?usage: collect_live_state.sh ENVIRONMENT EMPTY_DIRECTORY}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ -d "$live_dir" && ! -L "$live_dir" && -z "$(ls -A "$live_dir")" ]]
command -v bao >/dev/null
command -v jq >/dev/null

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
