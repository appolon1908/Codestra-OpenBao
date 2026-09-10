#!/usr/bin/env bash
set -euo pipefail

# Source-controlled bootstrap for the Codestra OpenBao secret authority.
# This script creates the KV v2 mount and ACL policies only. It NEVER writes
# secret values and it intentionally does not manage init/unseal/recovery keys.

: "${BAO_ADDR:?Set BAO_ADDR to the OpenBao HTTPS endpoint}"
: "${BAO_TOKEN:?Set BAO_TOKEN to an authorized short-lived operator token}"

command -v bao >/dev/null 2>&1 || {
  echo "ERROR: bao CLI is required" >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required" >&2
  exit 1
}

status_json="$(bao status -format=json 2>/dev/null || true)"
python3 - "$status_json" <<'PY'
import json, sys
try:
    state = json.loads(sys.argv[1])
except Exception:
    raise SystemExit("ERROR: unable to read OpenBao status")
if not state.get("initialized", False):
    raise SystemExit("ERROR: OpenBao is not initialized")
if state.get("sealed", True):
    raise SystemExit("ERROR: OpenBao is sealed")
PY

if ! bao secrets list -format=json | python3 -c 'import json,sys; raise SystemExit(0 if "codestra/" in json.load(sys.stdin) else 1)'; then
  echo "Enabling KV v2 secrets engine at codestra/"
  bao secrets enable -path=codestra -version=2 kv
else
  echo "KV mount codestra/ already exists"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

write_read_policy() {
  local env="$1"
  local service="$2"
  local policy="codestra-${env}-${service}-read"
  local file="$tmpdir/${policy}.hcl"

  cat >"$file" <<EOF
path "codestra/data/${env}/${service}/*" {
  capabilities = ["read"]
}

path "codestra/metadata/${env}/${service}/*" {
  capabilities = ["read", "list"]
}
EOF

  bao policy write "$policy" "$file" >/dev/null
  echo "Installed policy: $policy"
}

write_beyvra_policies() {
  local env="$1"
  local backend="codestra-${env}-beyvra-backend-read"
  local execution="codestra-${env}-beyvra-execution-read"
  local backend_file="$tmpdir/${backend}.hcl"
  local execution_file="$tmpdir/${execution}.hcl"

  cat >"$backend_file" <<EOF
path "codestra/data/${env}/beyvra/market-data/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/market-data/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/funding/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/funding/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/kyc/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/kyc/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/webhooks/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/webhooks/*" { capabilities = ["read", "list"] }
EOF

  cat >"$execution_file" <<EOF
path "codestra/data/${env}/beyvra/broker/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/broker/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/exchange/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/exchange/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/custody/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/custody/*" { capabilities = ["read", "list"] }
path "codestra/data/${env}/beyvra/signing/*" { capabilities = ["read"] }
path "codestra/metadata/${env}/beyvra/signing/*" { capabilities = ["read", "list"] }
EOF

  bao policy write "$backend" "$backend_file" >/dev/null
  bao policy write "$execution" "$execution_file" >/dev/null
  echo "Installed policy: $backend"
  echo "Installed policy: $execution"
}

services=(
  shared-saas
  moneybee
  transportation
  larim-a
  breero
  booked4seasons
  restaurant
  klyrow
  telnexa
  vicidial
  social-codestra
  keycloak
  kong
  middleware
  n8n
  odoo
)

for env in staging production; do
  for service in "${services[@]}"; do
    write_read_policy "$env" "$service"
  done
  write_beyvra_policies "$env"
done

cat <<'EOF'

OpenBao source bootstrap complete.

No secret values were written.
No auth role was created automatically.
No production credential was activated.
No init, unseal, recovery, or root material was changed.

Next: bind each service's short-lived workload identity to exactly one matching
environment/service policy. Frontend/browser identities must receive none.
EOF
