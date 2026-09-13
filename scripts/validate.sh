#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/codestra-openbao-pycache"

python3 scripts/generate_workload_authority.py
python3 scripts/generate_workload_policies.py
python3 scripts/generate_jwt_roles.py

for validator in \
  scripts/validate_repository.py \
  scripts/validate_codestra_enterprise_profile.py \
  scripts/validate_codestra_openbao.py \
  scripts/validate_codestra_openbao_oidc.py \
  scripts/validate_codestra_review_boundaries.py \
  scripts/validate_workload_secret_authority.py \
  scripts/validate_orbit_adoption.py; do
  python3 "$validator"
done

python3 -m unittest discover -s tests -p 'test_*.py' -v
for suite in tests/policy tests/security tests/unit tests/integration tests/recovery tests/runtime; do
  python3 -m unittest discover -s "$suite" -p 'test_*.py' -v
done

python3 - <<'PY'
import json
from pathlib import Path

for root in (
    Path('config'),
    Path('openbao'),
    Path('plugins'),
    Path('orbit'),
    Path('artifacts/supply-chain'),
):
    for path in root.rglob('*.json'):
        json.loads(path.read_text(encoding='utf-8'))
print('OPENBAO_JSON_VALIDATION=PASS')
PY

OPENBAO_NODE_ID=validation \
OPENBAO_CONTAINER_NAME=openbao-validation \
CODESTRA_ENVIRONMENT=production \
CODESTRA_SOURCE_SHA=0000000000000000000000000000000000000000 \
OPENBAO_CONFIG_FILE=/tmp/openbao.hcl \
OPENBAO_DATA_DIR=/tmp/openbao-data \
OPENBAO_AUDIT_DIR=/tmp/openbao-audit \
OPENBAO_PLUGIN_DIR=/tmp/openbao-plugins \
OPENBAO_SERVER_CERT_FILE=/tmp/server-cert \
OPENBAO_SERVER_KEY_FILE=/tmp/server-key \
CODESTRA_CLIENT_CA_FILE=/tmp/client-ca \
OPENBAO_HEALTH_CLIENT_CERT_FILE=/tmp/health-cert \
OPENBAO_HEALTH_CLIENT_KEY_FILE=/tmp/health-key \
OPENBAO_CLIENT_NETWORK=client \
OPENBAO_CLUSTER_NETWORK=cluster \
OPENBAO_OBSERVABILITY_NETWORK=observability \
docker compose -f deploy/compose/compose.yaml config --quiet

scripts/validate_hcl.sh
scripts/reject_repository_secrets.sh .
git diff --check
if [[ "${OPENBAO_ALLOW_DIRTY_VALIDATION:-false}" != true ]]; then
  git diff --exit-code
fi

echo 'OPENBAO_CONFIGURATION_VALIDATION=PASS'
echo 'OPENBAO_POLICY_VALIDATION=PASS'
