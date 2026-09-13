#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${OPENBAO_PLUGIN_OUTPUT:?set an unused plugin output path}"
[[ ! -e "$output" && ! -e "$output.sha256" ]]
for command in git go jq sha256sum; do command -v "$command" >/dev/null; done
manifest="$repo_root/plugins/codestra-jwt-replay/plugin.v1.json"
go_version="$(jq -r .goVersion "$manifest")"
[[ "$(go env GOVERSION)" == "go${go_version}" ]]
if [[ -n "${OPENBAO_TEST_TOKEN_OUTPUT:-}" ]]; then
  [[ ! -e "$OPENBAO_TEST_TOKEN_OUTPUT" ]]
fi

upstream_sha="$(jq -r .upstream_ref "$repo_root/CODESTRA_UPSTREAM.json")"
upstream_url="$(jq -r .upstream_clone_url "$repo_root/CODESTRA_UPSTREAM.json")"
work="$(mktemp -d)"
cleanup() {
  find "$work" -type f -delete
  find "$work" -depth -type d -empty -delete
}
trap cleanup EXIT

if [[ -n "${OPENBAO_UPSTREAM_SOURCE:-}" ]]; then
  [[ -d "$OPENBAO_UPSTREAM_SOURCE/.git" ]]
  git -C "$OPENBAO_UPSTREAM_SOURCE" diff --quiet
  git -C "$OPENBAO_UPSTREAM_SOURCE" diff --cached --quiet
  cp -R "$OPENBAO_UPSTREAM_SOURCE" "$work/openbao"
  find "$work/openbao/.git" -type f -delete
  find "$work/openbao/.git" -depth -type d -empty -delete
  git clone --quiet --no-checkout "$OPENBAO_UPSTREAM_SOURCE" "$work/identity"
  actual_sha="$(git -C "$work/identity" rev-parse HEAD)"
else
  git clone --quiet --filter=blob:none --no-checkout "$upstream_url" "$work/openbao"
  git -C "$work/openbao" checkout --quiet "$upstream_sha"
  actual_sha="$(git -C "$work/openbao" rev-parse HEAD)"
fi
[[ "$actual_sha" == "$upstream_sha" ]]

overlay="$work/openbao/codestra/plugins/codestra-jwt-replay"
mkdir -p "$(dirname "$overlay")"
  cp -R "$repo_root/plugins/codestra-jwt-replay" "$overlay"

(
  cd "$work/openbao"
  [[ "$(sha256sum go.mod | awk '{print $1}')" == "$(jq -r .upstreamGoModSha256 "$manifest")" ]]
  [[ "$(sha256sum go.sum | awk '{print $1}')" == "$(jq -r .upstreamGoSumSha256 "$manifest")" ]]
  [[ "$(awk '$1 == "go" {print $2; exit}' go.mod)" == "$(jq -r .upstreamGoVersion "$manifest")" ]]
  export GOTOOLCHAIN=local GOPRIVATE='' GONOSUMDB='' \
    GOPROXY='https://proxy.golang.org' GOSUMDB='sum.golang.org'
  while IFS=$'\t' read -r module version; do
    go mod edit -require="${module}@${version}"
  done < <(jq -r '.securityDependencyOverrides[] | [.module,.version] | @tsv' "$manifest")
  go mod tidy
  [[ "$(sha256sum go.mod | awk '{print $1}')" == "$(jq -r .overlayGoModSha256 "$manifest")" ]]
  [[ "$(sha256sum go.sum | awk '{print $1}')" == "$(jq -r .overlayGoSumSha256 "$manifest")" ]]
  while IFS=$'\t' read -r module version; do
    [[ "$(go list -m -f '{{.Version}}' "$module")" == "$version" ]]
  done < <(jq -r '.resolvedSecurityModules | to_entries[] | [.key,.value] | @tsv' "$manifest")
  export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  go test ./codestra/plugins/codestra-jwt-replay
  go build -trimpath -buildvcs=false -ldflags='-buildid=' \
    -o "$work/codestra-jwt-replay" \
    ./codestra/plugins/codestra-jwt-replay/cmd
  if [[ -n "${OPENBAO_TEST_TOKEN_OUTPUT:-}" ]]; then
    go run ./codestra/plugins/codestra-jwt-replay/testtoken \
      --output "$OPENBAO_TEST_TOKEN_OUTPUT"
  fi
)

install -m 0555 "$work/codestra-jwt-replay" "$output"
(
  cd "$(dirname "$output")"
  sha256sum "$(basename "$output")" > "$(basename "$output").sha256"
)
chmod 0444 "$output.sha256"
actual_plugin_sha="$(awk '{print $1}' "$output.sha256")"
expected_plugin_sha="$(jq -r .binarySha256 "$manifest")"
[[ "$actual_plugin_sha" == "$expected_plugin_sha" ]]

echo 'OPENBAO_JTI_PLUGIN_BUILD=PASS'
echo "OPENBAO_UPSTREAM_SHA=${upstream_sha}"
echo "OPENBAO_PLUGIN_SHA256=${actual_plugin_sha}"
