#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
scan_dir="$(mktemp -d)"

cleanup() {
  find "$scan_dir" -type f -delete
  find "$scan_dir" -depth -type d -empty -delete
}
trap cleanup EXIT

report_findings() {
  local report="$1"
  local label="$2"
  if [[ -s "$report" ]]; then
    echo "${label}=FAIL" >&2
    jq -c '[.[] | {
      rule_id: (.RuleID // .rule_id // "unknown"),
      file: (.File // .file // "unknown"),
      commit: (.Commit // .commit // "working-tree"),
      start_line: (.StartLine // .start_line // 0),
      end_line: (.EndLine // .end_line // 0)
    }]' "$report" >&2
  fi
}

run_gitleaks() {
  local mode="$1"
  local report="$2"
  shift 2
  set +e
  gitleaks "$mode" . --no-banner --redact --config .gitleaks.toml \
    --report-format json --report-path "$report" "$@"
  local status=$?
  set -e
  if [[ $status -ne 0 ]]; then
    return "$status"
  fi
  [[ "$(jq 'length' "$report")" == 0 ]]
}

scripts/reject_repository_secrets.sh .

working_status=0
history_status=0
run_gitleaks dir "$scan_dir/working-tree.json" || working_status=$?
run_gitleaks git "$scan_dir/history.json" --log-opts='--all' || history_status=$?

if [[ $working_status -ne 0 ]]; then
  report_findings "$scan_dir/working-tree.json" "OPENBAO_WORKING_TREE_SECRET_SCAN"
fi
if [[ $history_status -ne 0 ]]; then
  report_findings "$scan_dir/history.json" "OPENBAO_FULL_HISTORY_SECRET_SCAN"
fi
if [[ $working_status -ne 0 || $history_status -ne 0 ]]; then
  exit 1
fi

python3 scripts/verify_vulnerability_gate.py
python3 scripts/verify_plugin_supply_chain.py
(cd artifacts/supply-chain && sha256sum -c SHA256SUMS)

echo 'OPENBAO_SECRET_SCAN=PASS'
echo 'OPENBAO_FULL_HISTORY_SECRET_SCAN=PASS'
echo 'OPENBAO_SECURITY_VALIDATION=PASS'
