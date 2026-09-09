#!/usr/bin/env bash
set -Eeuo pipefail

report_failure() {
  local status="$?"
  printf 'JTI integration failed at script line %s (exit %s)\n' \
    "${BASH_LINENO[0]}" "$status" >&2
  exit "$status"
}
trap report_failure ERR

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
for command in curl docker go jq sha256sum shred; do command -v "$command" >/dev/null; done

image="$(jq -r .image_reference CODESTRA_UPSTREAM.json)"
plugin="$(jq -r .name plugins/codestra-jwt-replay/plugin.v1.json)"
version="$(jq -r .version plugins/codestra-jwt-replay/plugin.v1.json)"
expected_sha="$(jq -r .binarySha256 plugins/codestra-jwt-replay/plugin.v1.json)"
container="codestra-openbao-jti-${GITHUB_RUN_ID:-$$}-${GITHUB_RUN_ATTEMPT:-1}"
work="$(mktemp -d)"
plugin_dir="$work/plugin"
build_dir="$work/build"
token_dir="$work/tokens"
response_dir="$work/responses"
mkdir "$plugin_dir" "$build_dir" "$response_dir"
chmod 0755 "$work" "$plugin_dir"
chmod 0700 "$build_dir" "$response_dir"
cat >"$work/integration.hcl" <<'EOF'
audit "file" "integration-audit" {
  description = "Ephemeral OpenBao integration-test audit device."
  options {
    file_path = "/tmp/openbao-integration-audit.jsonl"
    log_raw = "false"
  }
}
EOF
chmod 0444 "$work/integration.hcl"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  # The plugin and its checksum are deliberately installed read-only. Restore
  # owner write permission before secure deletion so cleanup cannot turn a
  # successful security test into a false failure on non-root CI runners.
  find "$work" -type f -exec chmod u+w {} + 2>/dev/null || true
  find "$work" -type f -exec shred -u {} +
  find "$work" -depth -type d -empty -delete
}
trap cleanup EXIT

OPENBAO_PLUGIN_OUTPUT="$build_dir/$plugin" \
OPENBAO_TEST_TOKEN_OUTPUT="$token_dir" \
scripts/build_jti_plugin.sh
install -m 0555 "$build_dir/$plugin" "$plugin_dir/$plugin"
[[ "$(sha256sum "$plugin_dir/$plugin" | awk '{print $1}')" == "$expected_sha" ]]

docker run --detach --name "$container" \
  --publish 127.0.0.1::8200 \
  --volume "$plugin_dir:/openbao/plugins:ro" \
  --volume "$work/integration.hcl:/openbao/integration.hcl:ro" \
  --env BAO_DEV_ROOT_TOKEN_ID=codestra-ci-root \
  "$image" server -dev -dev-listen-address=0.0.0.0:8200 \
  -dev-plugin-dir=/openbao/plugins -config=/openbao/integration.hcl > /dev/null
if ! port_output="$(docker port "$container" 8200/tcp 2>&1)"; then
  docker inspect --format='CONTAINER_STATUS={{.State.Status}} EXIT_CODE={{.State.ExitCode}}' \
    "$container" >&2 || true
  printf '%s\n' "$port_output" >&2
  exit 1
fi
port="$(awk -F: 'NR == 1 {print $NF}' <<<"$port_output")"
[[ "$port" =~ ^[0-9]+$ ]]
base="http://127.0.0.1:${port}/v1"
header_name=X-Vault-Token
dev_token=codestra-ci-root
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error "$base/sys/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl --fail --silent --show-error "$base/sys/health" > "$response_dir/health.json"
jq -e '.initialized == true and .sealed == false' "$response_dir/health.json" >/dev/null

bao_exec() {
  docker exec --env BAO_ADDR=http://127.0.0.1:8200 \
    --env BAO_TOKEN=codestra-ci-root "$container" bao "$@"
}

mount="$(jq -r .mount openbao/auth/jwt-roles.v1.json)"
role=middleware-api-staging
policy="workload-${role}"
bao_exec plugin register -sha256="$expected_sha" -command="$plugin" \
  -version="$version" auth "$plugin" >/dev/null
bao_exec plugin info -format=json -version="$version" auth "$plugin" \
  > "$response_dir/plugin-info.json"
jq -e --arg plugin "$plugin" --arg version "$version" --arg sha "$expected_sha" '
  .name == $plugin and .command == $plugin and .version == $version and
  .sha256 == $sha and .builtin == false
' "$response_dir/plugin-info.json" >/dev/null
bao_exec auth enable -path="$mount" -plugin-name="$plugin" -plugin-version="$version" plugin >/dev/null
bao_exec auth list -format=json > "$response_dir/auth.json"
jq -e --arg path "${mount}/" --arg plugin "$plugin" --arg version "$version" --arg sha "$expected_sha" '
  .[$path].type == $plugin and
  .[$path].plugin_version == $version and
  .[$path].running_plugin_version == $version and
  .[$path].running_sha256 == $sha
' "$response_dir/auth.json" >/dev/null

jq -n --rawfile key "$token_dir/public.pem" \
  '{jwt_validation_pubkeys:[$key],jwt_supported_algs:["ES256"],bound_issuer:"https://auth.codestra.co/realms/codestra"}' \
  > "$response_dir/config-payload.json"
code="$(curl -sS -o "$response_dir/config-response.json" -w '%{http_code}' \
  -H "${header_name}: ${dev_token}" -H 'Content-Type: application/json' \
  --data-binary @"$response_dir/config-payload.json" "$base/auth/${mount}/config")"
[[ "$code" == 204 ]]

jq --arg role "$role" '.roles[] | select(.name == $role) | .payload' \
  openbao/auth/jwt-roles.v1.json > "$response_dir/role-payload.json"
code="$(curl -sS -o "$response_dir/role-response.json" -w '%{http_code}' \
  -H "${header_name}: ${dev_token}" -H 'Content-Type: application/json' \
  --data-binary @"$response_dir/role-payload.json" "$base/auth/${mount}/cel/role/${role}")"
[[ "$code" == 200 || "$code" == 204 ]]

policy_path="$(jq -r --arg policy "$policy" '.policies[] | select(.policyName == $policy) | .path' config/policies/generated-policy-index.v1.json)"
docker cp "$policy_path" "$container:/tmp/policy.hcl" >/dev/null
bao_exec policy write "$policy" /tmp/policy.hcl >/dev/null
bao_exec audit list -format=json >"$response_dir/audit-devices.json"
jq -e '.["integration-audit/"].type == "file"' "$response_dir/audit-devices.json" >/dev/null
bao_exec secrets enable -path=codestra -version=2 kv >/dev/null
bao_exec kv put codestra/staging/middleware/api/probe payload=synthetic-middleware-api >/dev/null
bao_exec kv put codestra/staging/middleware/worker/email/probe payload=synthetic-cross-service >/dev/null
bao_exec kv put codestra/production/middleware/api/probe payload=synthetic-cross-environment >/dev/null

login() {
  login_path "$1" "$2" cel/login
}

login_path() {
  local token_name="$1" response="$2" endpoint="$3" payload="$response_dir/login-payload.json"
  local jwt
  jwt="$(jq -r --arg name "$token_name" '.[$name]' "$token_dir/tokens.json")"
  jq -n --arg role "$role" --arg jwt "$jwt" '{role:$role,jwt:$jwt}' > "$payload"
  curl -sS -o "$response" -w '%{http_code}' -H 'Content-Type: application/json' \
    --data-binary @"$payload" "$base/auth/${mount}/${endpoint}"
}

code="$(login_path agentCompatible "$response_dir/agent-compatible.json" login)"
[[ "$code" == 200 ]]
jq -e --arg policy "$policy" '.auth.policies | index($policy) != null' \
  "$response_dir/agent-compatible.json" >/dev/null
code="$(login_path agentCompatible "$response_dir/agent-compatible-replay.json" cel/login)"
[[ "$code" != 200 ]]
jq -e '.errors == ["JWT replay rejected"]' \
  "$response_dir/agent-compatible-replay.json" >/dev/null

code="$(login valid "$response_dir/valid.json")"
[[ "$code" == 200 ]]
jq -e --arg policy "$policy" '
  .auth.lease_duration == 300 and .auth.renewable == true and
  (.auth.policies | index($policy) != null)
' "$response_dir/valid.json" >/dev/null
workload_token="$(jq -r .auth.client_token "$response_dir/valid.json")"
[[ -n "$workload_token" && "$workload_token" != null ]]

authorized_get() {
  local path="$1" response="$2"
  curl --path-as-is -sS -D "${response%.json}.headers" -o "$response" -w '%{http_code}' \
    -H "${header_name}: ${workload_token}" "$base/$path"
}

code="$(authorized_get codestra/data/staging/middleware/api/probe "$response_dir/authorized-secret.json")"
[[ "$code" == 200 ]]
jq -e '.data.data.payload == "synthetic-middleware-api"' \
  "$response_dir/authorized-secret.json" >/dev/null

for denial in \
  'cross-service:codestra/data/staging/middleware/worker/email/probe' \
  'cross-environment:codestra/data/production/middleware/api/probe' \
  'system-admin:sys/auth' \
  'path-traversal:codestra/data/staging/middleware/api/../worker/email/probe'; do
  name="${denial%%:*}"
  path="${denial#*:}"
  code="$(authorized_get "$path" "$response_dir/denied-${name}.json")"
  if [[ "$name" == path-traversal ]]; then
    location="$(awk 'tolower($1) == "location:" {print $2}' \
      "$response_dir/denied-${name}.headers" | tr -d '\r')"
    [[ "$code" == 307 ]]
    [[ "$location" == /v1/codestra/data/staging/middleware/worker/email/probe ]]
    code="$(authorized_get codestra/data/staging/middleware/worker/email/probe \
      "$response_dir/denied-path-traversal-target.json")"
    [[ "$code" == 403 ]]
  elif [[ "$code" != 403 ]]; then
    printf 'denial probe %s expected HTTP 403, received %s\n' "$name" "$code" >&2
    exit 1
  fi
done
code="$(curl --path-as-is -sS -o "$response_dir/denied-anonymous.json" -w '%{http_code}' \
  "$base/codestra/data/staging/middleware/api/probe")"
if [[ "$code" != 403 ]]; then
  printf 'anonymous denial expected HTTP 403, received %s\n' "$code" >&2
  exit 1
fi
code="$(login valid "$response_dir/replay.json")"
[[ "$code" != 200 ]]
jq -e '.errors == ["JWT replay rejected"]' "$response_dir/replay.json" >/dev/null

for name in wrongIssuer wrongAudience wrongEnvironment wrongClient expired overlong futureIssuedAt missingSubject missingJTI; do
  code="$(login "$name" "$response_dir/negative-${name}.json")"
  [[ "$code" != 200 ]]
  jq -e '.errors | type == "array" and length > 0' "$response_dir/negative-${name}.json" >/dev/null
done

jwt="$(jq -r .concurrent "$token_dir/tokens.json")"
jq -n --arg role "$role" --arg jwt "$jwt" '{role:$role,jwt:$jwt}' > "$response_dir/concurrent-payload.json"
for n in $(seq 1 16); do
  (curl -sS -o "$response_dir/concurrent-response-${n}.json" -w '%{http_code}' \
    -H 'Content-Type: application/json' --data-binary @"$response_dir/concurrent-payload.json" \
    "$base/auth/${mount}/cel/login" > "$response_dir/concurrent-code-${n}") &
done
wait
success="$(awk '$0 == 200 {count++} END {print count+0}' "$response_dir"/concurrent-code-*)"
denied="$(awk '$0 != 200 {count++} END {print count+0}' "$response_dir"/concurrent-code-*)"
[[ "$success" == 1 && "$denied" == 15 ]]
code="$(curl -sS -o "$response_dir/concurrent-final.json" -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary @"$response_dir/concurrent-payload.json" \
  "$base/auth/${mount}/cel/login")"
[[ "$code" != 200 ]]
jq -e '.errors == ["JWT replay rejected"]' "$response_dir/concurrent-final.json" >/dev/null

docker cp "$container:/tmp/openbao-integration-audit.jsonl" \
  "$response_dir/openbao-integration-audit.jsonl" >/dev/null
jq -s -e '
  any(.[]; .type == "request" and .auth.display_name == "root") and
  ([.[] | select(.type == "response" and ((.error // "") | length > 0))] | length >= 5)
' "$response_dir/openbao-integration-audit.jsonl" >/dev/null

echo 'OPENBAO_JTI_PLUGIN_INTEGRATION=PASS'
echo 'AGENT_STANDARD_LOGIN_COMPATIBILITY=PASS'
echo 'AGENT_STANDARD_LOGIN_REPLAY=DENIED'
echo 'JWT_TOKEN_TTL=300'
echo 'JWT_SEQUENTIAL_REPLAY=DENIED'
echo 'JWT_CONCURRENT_SUCCESS_COUNT=1'
echo 'JWT_CONCURRENT_DENY_COUNT=15'
echo 'JWT_NEGATIVE_SECURITY=PASS'
echo 'WORKLOAD_AUTHORIZED_PATH=PASS'
echo 'CROSS_SERVICE_ACCESS=DENIED'
echo 'CROSS_ENVIRONMENT_ACCESS=DENIED'
echo 'ANONYMOUS_ACCESS=DENIED'
echo 'SYSTEM_ADMIN_ACCESS=DENIED'
echo 'PATH_TRAVERSAL_ACCESS=DENIED'
echo 'ROOT_TOKEN_USAGE_DETECTION=PASS'
