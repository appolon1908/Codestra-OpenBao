#!/usr/bin/env bash
set -Eeuo pipefail

metric_file="${OPENBAO_DRIFT_METRIC_FILE:?set node-exporter textfile path}"
plan_file="$(mktemp)"
find "$plan_file" -type f -delete
cleanup() {
  find "$plan_file" "$plan_file.sha256" -type f -delete 2>/dev/null || true
}
trap cleanup EXIT

OPENBAO_PLAN_OUTPUT="$plan_file" scripts/plan.sh >/dev/null
changes="$((
  $(jq '.counts.create' "$plan_file") +
  $(jq '.counts.change' "$plan_file") +
  $(jq '.warnings | length' "$plan_file")
))"

umask 077
metric_partial="${metric_file}.partial.$PPID"
printf '# HELP codestra_openbao_drift_detected Sanitized desired/live drift state.\n' > "$metric_partial"
printf '# TYPE codestra_openbao_drift_detected gauge\n' >> "$metric_partial"
if (( changes == 0 )); then
  printf 'codestra_openbao_drift_detected 0\n' >> "$metric_partial"
  mv "$metric_partial" "$metric_file"
  echo 'OPENBAO_DRIFT=PASS'
  echo 'DRIFT_CHANGES=0'
  exit 0
fi
printf 'codestra_openbao_drift_detected 1\n' >> "$metric_partial"
mv "$metric_partial" "$metric_file"
echo 'OPENBAO_DRIFT=FAIL'
echo "DRIFT_CHANGES=${changes}"
jq -r '.summary[]' "$plan_file" | sed -n '1,100p'
exit 1
