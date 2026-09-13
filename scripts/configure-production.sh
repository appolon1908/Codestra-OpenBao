#!/usr/bin/env sh
set -eu
: "${BAO_ADDR:=http://127.0.0.1:18200}"
: "${BAO_TOKEN_FILE:?set BAO_TOKEN_FILE to a protected file containing a short-lived setup token}"
[ -r "$BAO_TOKEN_FILE" ] || { echo "token file not readable" >&2; exit 1; }
export BAO_ADDR
export BAO_TOKEN="$(cat "$BAO_TOKEN_FILE")"
trap 'unset BAO_TOKEN' EXIT HUP INT TERM

bao status >/dev/null
if ! bao audit list -format=json | grep -q '"file/"'; then
  bao audit enable file file_path=/openbao/audit/audit.json mode=0600
fi
if ! bao secrets list -format=json | grep -q '"codestra/"'; then
  bao secrets enable -path=codestra -version=2 kv
fi

for policy in /workspace/policies/*.hcl; do
  name=$(basename "$policy" .hcl)
  bao policy write "$name" "$policy"
done

echo "production mounts, audit device, and policies configured"
