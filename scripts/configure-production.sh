#!/usr/bin/env sh
set -eu
umask 077
: "${BAO_CONTAINER:=codestra-openbao}"
: "${BAO_TOKEN_FILE:?set BAO_TOKEN_FILE to a protected short-lived setup token file}"
[ -r "$BAO_TOKEN_FILE" ] || { echo "token file not readable" >&2; exit 1; }
token=$(cat "$BAO_TOKEN_FILE")
policy_dir=$(CDPATH= cd -- "$(dirname "$0")/../policies" && pwd)
remote="/tmp/policies-$$"
cleanup() {
  unset token
  docker exec "$BAO_CONTAINER" rm -rf "$remote" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker exec "$BAO_CONTAINER" mkdir -m 700 "$remote"
for policy in "$policy_dir"/*.hcl; do
  docker cp "$policy" "$BAO_CONTAINER:$remote/$(basename "$policy")" >/dev/null
done
bao() { docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$token" "$BAO_CONTAINER" bao "$@"; }

bao status >/dev/null
bao audit list -format=json | grep -q '"file/"' ||
  bao audit enable file file_path=/openbao/audit/audit.json mode=0600
bao secrets list -format=json | grep -q '"codestra/"' ||
  bao secrets enable -path=codestra -version=2 kv
for policy in "$policy_dir"/*.hcl; do
  name=$(basename "$policy" .hcl)
  bao policy write "$name" "$remote/$(basename "$policy")"
done
echo "audit, KV v2, and production policies configured"
