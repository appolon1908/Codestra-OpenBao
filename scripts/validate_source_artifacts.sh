#!/usr/bin/env bash
# Build isolated security candidates only. No registry login/push/sign/deploy.
set -Eeuo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
: "${EVIDENCE_DIR:?set unused bounded evidence directory}"
: "${EXPECTED_SHA:?set exact checked-out source SHA}"
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_REPOSITORY:?}"
[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]]
[[ -z "$(git status --porcelain)" ]]
[[ "$(go env GOVERSION)" == go1.26.10 ]]
[[ ! -e "$EVIDENCE_DIR" ]]
mkdir -p "$EVIDENCE_DIR/plugin-root"
export EVIDENCE_DIR EXPECTED_SHA
export GOTOOLCHAIN=local GOWORK=off GOMAXPROCS=2
export GOPRIVATE='' GONOSUMDB='' GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
work="$(mktemp -d "${RUNNER_TEMP:?}/openbao-candidate.XXXXXX")"
trap 'rm -rf "$work"' EXIT
source_root="$work/source"
cp -a upstream "$source_root"
python3 scripts/prepare_openbao_test_fixtures.py --source-root "$source_root" \
  --report "$EVIDENCE_DIR/test-fixture-overlay.json"
mkdir -p "$source_root/codestra/plugins" "$source_root/codestra/security/jose" "$source_root/codestra/security/celotel"
cp -a plugins/codestra-jwt-replay "$source_root/codestra/plugins/"
cp tests/go/josesecurity/security_test.go tests/go/josesecurity/cap_claims_test.go \
  "$source_root/codestra/security/jose/"
cp tests/go/capclaims/kubernetes_test.go.fixture \
  "$source_root/builtin/credential/kubernetes/codestra_cap_claims_test.go"
cp tests/go/celotelsecurity/security_test.go "$source_root/codestra/security/celotel/"
cp tests/go/celotelsecurity/openbao_test.go.fixture "$source_root/codestra/security/celotel/openbao_test.go"
python3 scripts/prepare_openbao_source_build.py --source-root "$source_root" \
  --report "$EVIDENCE_DIR/dependency-overlay.json"
(
  cd "$source_root"
  go mod verify
  go mod vendor
)
cp tests/go/josesecurity/epk_internal_test.go.fixture \
  "$source_root/vendor/github.com/go-jose/go-jose/v4/codestra_security_test.go"
cp "$source_root/go.mod" "$EVIDENCE_DIR/prepared-go.mod"
cp "$source_root/go.sum" "$EVIDENCE_DIR/prepared-go.sum"
cp "$source_root/vendor/modules.txt" "$EVIDENCE_DIR/vendor-modules.txt"
cp plugins/codestra-jwt-replay/plugin.v1.json "$EVIDENCE_DIR/accepted-plugin-manifest.json"
export GOFLAGS='-mod=vendor -p=2'
# Preserve selected packages from the same vendor tree/flags used for both builds.
(
  cd "$source_root"
  go list -deps -tags=openbao -f '{{.ImportPath}}{{with .Module}} {{.Path}} {{.Version}}{{end}}' . >"$EVIDENCE_DIR/bao-build-deps.txt"
  go list -deps -f '{{.ImportPath}}{{with .Module}} {{.Path}} {{.Version}}{{end}}' ./codestra/plugins/codestra-jwt-replay/cmd >"$EVIDENCE_DIR/plugin-build-deps.txt"
)
python3 scripts/collect_openbao_candidate_evidence.py --evidence-dir "$EVIDENCE_DIR" --validate-dependencies
python3 - "$source_root/vendor" "$EVIDENCE_DIR/vendor-tree.sha256" <<'PYHASH'
from pathlib import Path
import sys
from scripts.patch_jose_v3_vendor import tree_hash
Path(sys.argv[2]).write_text(tree_hash(Path(sys.argv[1]))+"\n")
PYHASH
commit_date="$(git show --no-show-signature -s --format=%cI HEAD)"
(
  cd "$source_root"
  if ! go test -count=1 -v ./codestra/security/jose github.com/go-jose/go-jose/v4 \
    ./builtin/credential/jwt ./codestra/plugins/codestra-jwt-replay ./codestra/security/celotel \
    >"$EVIDENCE_DIR/consumer-tests.log" 2>&1; then
    tail -n 120 "$EVIDENCE_DIR/consumer-tests.log"
    exit 1
  fi
  if ! go test -count=1 -v -run '^TestDiagnoseOtelResults$' ./vault/diagnose \
    >>"$EVIDENCE_DIR/consumer-tests.log" 2>&1; then
    tail -n 120 "$EVIDENCE_DIR/consumer-tests.log"
    exit 1
  fi
  if ! go test -count=1 -v \
    -run '^(TestLogin|TestLogin_ContextError|TestLogin_ECDSA_PEM|TestLoginIssValidation|TestLoginProjectedToken|TestCAPKubernetesAudienceAndAliasValidation)$' \
    ./builtin/credential/kubernetes >>"$EVIDENCE_DIR/consumer-tests.log" 2>&1; then
    tail -n 120 "$EVIDENCE_DIR/consumer-tests.log"
    exit 1
  fi
  go build -trimpath -buildvcs=false -tags=openbao \
    -ldflags="-buildid= -X github.com/openbao/openbao/version.GitCommit=${EXPECTED_SHA} -X github.com/openbao/openbao/version.CommitDate=${commit_date}" \
    -o "$EVIDENCE_DIR/bao" .
  go build -trimpath -buildvcs=false -ldflags='-buildid=' \
    -o "$EVIDENCE_DIR/plugin-root/codestra-jwt-replay" ./codestra/plugins/codestra-jwt-replay/cmd
)
go version -m "$EVIDENCE_DIR/bao" >"$EVIDENCE_DIR/bao-go-version.txt"
go version -m "$EVIDENCE_DIR/plugin-root/codestra-jwt-replay" >"$EVIDENCE_DIR/plugin-go-version.txt"
mkdir -p "$work/context/bin/amd64"
cp upstream/Dockerfile upstream/LICENSE "$work/context/"
install -m 0555 "$EVIDENCE_DIR/bao" "$work/context/bin/amd64/bao"
export LOCAL_IMAGE="codestra-openbao:candidate-${EXPECTED_SHA}"
docker build --platform linux/amd64 --target distroless \
  --label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}" \
  --label "org.opencontainers.image.revision=${EXPECTED_SHA}" \
  --tag "$LOCAL_IMAGE" "$work/context"
docker image inspect "$LOCAL_IMAGE" --format '{{json .}}' >"$EVIDENCE_DIR/image-inspect.json"
docker run --rm --platform linux/amd64 "$LOCAL_IMAGE" version | grep -F "$EXPECTED_SHA"
container="$(docker create --platform linux/amd64 "$LOCAL_IMAGE")"
docker cp "${container}:/usr/bin/bao" "$EVIDENCE_DIR/bao-from-image"
docker rm "$container"
cmp "$EVIDENCE_DIR/bao" "$EVIDENCE_DIR/bao-from-image"
docker image save --output "$work/image.tar" "$LOCAL_IMAGE"
python3 scripts/collect_openbao_candidate_evidence.py --evidence-dir "$EVIDENCE_DIR" \
  --docker-save "$work/image.tar"
export CANDIDATE_SOURCE_ROOT="$source_root"
python3 - <<'PY'
import hashlib,json,os,subprocess
from pathlib import Path
from scripts.patch_jose_v3_vendor import tree_hash
root=Path(os.environ["EVIDENCE_DIR"])
source=Path(os.environ["CANDIDATE_SOURCE_ROOT"])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
vendor_hash=(root/"vendor-tree.sha256").read_text().strip()
assert tree_hash(source/"vendor")==vendor_hash, "vendor changed during build"
build={
 "source_sha":os.environ["EXPECTED_SHA"],
 "source_tree":subprocess.check_output(["git","rev-parse","HEAD^{tree}"],text=True).strip(),
 "repository":os.environ["GITHUB_REPOSITORY"],
 "run_id":int(os.environ["GITHUB_RUN_ID"]),"run_attempt":int(os.environ["GITHUB_RUN_ATTEMPT"]),
 "go_version":subprocess.check_output(["go","env","GOVERSION"],text=True).strip(),
 "local_image":os.environ["LOCAL_IMAGE"],"plugin_scan_root":str(root/"plugin-root"),
 "binaries":{name:sha(root/name) for name in ("bao","plugin-root/codestra-jwt-replay")},
 "go_mod_sha256":sha(source/"go.mod"),"go_sum_sha256":sha(source/"go.sum"),
 "vendor_tree_sha256":vendor_hash,
 "selected_dependencies_sha256":{name:sha(root/(name+"-build-deps.txt")) for name in ("bao","plugin")},
 "test_fixture_overlay_sha256":sha(root/"test-fixture-overlay.json"),
 "plugin_manifest_sha256":sha(Path("plugins/codestra-jwt-replay/plugin.v1.json")),
 "plugin_source_tree_sha256":tree_hash(Path("plugins/codestra-jwt-replay")),
 "upstream":json.loads(Path("CODESTRA_UPSTREAM.json").read_text())["upstream_ref"],
 "runtime_authorized":False,"published":False,"signed":False,"accepted_plugin_identity":False,
}
(root/"build.json").write_text(json.dumps(build,indent=2,sort_keys=True)+"\n")
PY
# Generate BOTH subjects' raw evidence with one frozen DB before policy evaluation.
export TRIVY_CACHE_DIR="$work/trivy-cache"
trivy image --download-db-only
cp "$TRIVY_CACHE_DIR/db/metadata.json" "$EVIDENCE_DIR/db-metadata.json"
sha256sum "$TRIVY_CACHE_DIR/db/trivy.db" | awk '{print $1}' >"$EVIDENCE_DIR/db.sha256"
trivy version --format json >"$EVIDENCE_DIR/trivy-version.json"
syft version -o json >"$EVIDENCE_DIR/syft-version.json"
python3 - <<'PY'
import json,os
from pathlib import Path
p=Path(os.environ["EVIDENCE_DIR"])
(p/"tool-versions.json").write_text(json.dumps({
 "trivy":json.loads((p/"trivy-version.json").read_text()),
 "syft":json.loads((p/"syft-version.json").read_text())},indent=2,sort_keys=True)+"\n")
PY
syft scan "docker:$LOCAL_IMAGE" -o "spdx-json=$EVIDENCE_DIR/image-sbom.json" \
  -o "syft-json=$EVIDENCE_DIR/image-syft.json"
syft scan "file:$EVIDENCE_DIR/plugin-root/codestra-jwt-replay" -o "cyclonedx-json=$EVIDENCE_DIR/plugin-sbom.json"
trivy image --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$EVIDENCE_DIR/image-trivy.json" "$LOCAL_IMAGE"
trivy rootfs --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$EVIDENCE_DIR/plugin-trivy.json" "$EVIDENCE_DIR/plugin-root"
test "$(sha256sum "$TRIVY_CACHE_DIR/db/trivy.db" | awk '{print $1}')" = "$(cat "$EVIDENCE_DIR/db.sha256")"
cmp "$TRIVY_CACHE_DIR/db/metadata.json" "$EVIDENCE_DIR/db-metadata.json"
echo OPENBAO_CANDIDATE_RAW_EVIDENCE=COLLECTED
