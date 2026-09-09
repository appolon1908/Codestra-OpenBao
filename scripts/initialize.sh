#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
custody_file="${OPENBAO_INIT_CUSTODY_FILE:?set an offline custody output file}"
confirmation="${OPENBAO_INIT_CONFIRMATION:-}"
expected_confirmation="INITIALIZE_NEW_${environment^^}_CLUSTER"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$confirmation" == "$expected_confirmation" ]] || {
  echo 'Initialization confirmation is absent or does not match the environment.' >&2
  exit 2
}
[[ "${OPENBAO_OFFLINE_CUSTODY_ACKNOWLEDGED:-false}" == true ]] || {
  echo 'Protected offline custody has not been acknowledged.' >&2
  exit 2
}
command -v bao >/dev/null
command -v jq >/dev/null

set +e
status_json="$(bao status -format=json 2>/dev/null)"
status_code=$?
set -e
if [[ "$status_code" != 0 && "$status_code" != 2 ]]; then
  echo 'OpenBao status is ambiguous; initialization is prohibited.' >&2
  exit "$status_code"
fi
initialized="$(jq -er '.initialized | type == "boolean" and .' <<<"$status_json" 2>/dev/null || true)"
if [[ "$initialized" == true ]]; then
  echo 'OpenBao is already initialized; refusing to initialize or replace recovery material.' >&2
  exit 3
fi
[[ "$(jq -r '.initialized' <<<"$status_json")" == false ]] || {
  echo 'OpenBao initialization state is ambiguous.' >&2
  exit 2
}

custody_parent="$(dirname "$custody_file")"
mkdir -p "$custody_parent"
chmod 700 "$custody_parent"
resolved_parent="$(realpath "$custody_parent")"
case "$resolved_parent" in
  "$repo_root"|"$repo_root"/*|/tmp|/tmp/*|/var/tmp|/var/tmp/*)
    echo 'Custody output must be outside Git and temporary directories.' >&2
    exit 2
    ;;
esac
[[ ! -e "$custody_file" ]] || {
  echo 'Custody output already exists; refusing to overwrite it.' >&2
  exit 2
}

umask 077
partial="${custody_file}.partial.$PPID"
cleanup() {
  if [[ -f "$partial" ]]; then
    shred --remove --zero "$partial" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# This is the only initialization call in the repository. Its output is sent
# directly to protected offline custody and is never displayed or uploaded.
bao operator init -key-shares=5 -key-threshold=3 -format=json > "$partial"
jq -e '
  (.unseal_keys_b64 | type == "array" and length == 5) and
  (.root_token | type == "string" and length > 0)
' "$partial" >/dev/null
chmod 400 "$partial"
mv "$partial" "$custody_file"
trap - EXIT

echo 'OPENBAO_INITIALIZATION_PERFORMED=YES'
echo "CODESTRA_ENVIRONMENT=${environment}"
echo 'RECOVERY_MATERIAL_PRINTED=NO'
echo 'ROOT_TOKEN_PRINTED=NO'
