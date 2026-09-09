#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
image="$(jq -r .image_reference CODESTRA_UPSTREAM.json)"
container="codestra-openbao-integration-${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}"
work="$(mktemp -d)"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  find "$work" -type f -delete
  find "$work" -depth -type d -empty -delete
}
trap cleanup EXIT

docker run --detach --rm --name "$container" \
  --publish 127.0.0.1::8200 \
  --env BAO_DEV_ROOT_TOKEN_ID=codestra-ci-root \
  "$image" server -dev -dev-listen-address=0.0.0.0:8200 \
  > /dev/null
port="$(docker port "$container" 8200/tcp | awk -F: 'NR == 1 {print $NF}')"
[[ "$port" =~ ^[0-9]+$ ]]
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error \
    "http://127.0.0.1:${port}/v1/sys/health" > /dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error \
  "http://127.0.0.1:${port}/v1/sys/health" > "$work/health.json"
jq -e '.initialized == true and .sealed == false' "$work/health.json" > /dev/null

bao_exec() {
  docker exec \
    --env BAO_ADDR=http://127.0.0.1:8200 \
    --env BAO_TOKEN=codestra-ci-root \
    "$container" bao "$@"
}

mount="$(jq -r .mount openbao/auth/jwt-roles.v1.json)"
role="$(jq -r '.roles[0].name' openbao/auth/jwt-roles.v1.json)"
policy="workload-${role}"
jq --arg role "$role" '.roles[] | select(.name == $role) | .payload' \
  openbao/auth/jwt-roles.v1.json > "$work/role.json"

bao_exec auth enable -path="$mount" jwt > /dev/null
docker cp "$work/role.json" "$container:/tmp/role.json" > /dev/null
bao_exec write "auth/${mount}/cel/role/${role}" @/tmp/role.json > /dev/null
bao_exec list -format=json "auth/${mount}/cel/role" > "$work/roles.json"
jq -e --arg role "$role" 'index($role) != null' "$work/roles.json" > /dev/null
bao_exec read -format=json "auth/${mount}/cel/role/${role}" > "$work/read-role.json"
jq -e --slurpfile desired "$work/role.json" '
  .data.bound_audiences == $desired[0].bound_audiences and
  .data.cel_program == $desired[0].cel_program and
  .data.clock_skew_leeway == $desired[0].clock_skew_leeway
' "$work/read-role.json" > /dev/null

policy_path="$(jq -r --arg policy "$policy" '.policies[] | select(.policyName == $policy) | .path' config/policies/generated-policy-index.v1.json)"
docker cp "$policy_path" "$container:/tmp/policy.hcl" > /dev/null
bao_exec policy write "$policy" /tmp/policy.hcl > /dev/null
bao_exec policy read "$policy" > "$work/read-policy.hcl"
diff -u <(sed '/^[[:space:]]*$/d' "$policy_path") <(sed '/^[[:space:]]*$/d' "$work/read-policy.hcl") > /dev/null

echo 'OPENBAO_INTEGRATION_TEST=PASS'
echo 'JWT_CEL_ROLE_COMPILE=PASS'
echo 'JWT_ROLE_LIST_ENDPOINT=PASS'
echo 'POLICY_WRITE_READBACK=PASS'
