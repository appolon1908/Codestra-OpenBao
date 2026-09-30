#!/usr/bin/env bash
set -Eeuo pipefail

search_root="${1:-.}"
pattern="(BEGIN ([A-Z0-9][A-Z0-9 -]{0,63} )?PRIVATE KEY( BLOCK)?|[\"']?[Aa]uthorization[\"']?[[:space:]]*:[[:space:]]*[\"']?[[:space:]]*[Bb]earer[[:space:]]+[-A-Za-z0-9._~+/]{16,}=*|[\"']?[Cc][Ll][Ii][Ee][Nn][Tt]_[Ss][Ee][Cc][Rr][Ee][Tt][\"']?[[:space:]]*[:=][[:space:]]*[\"'][^[:space:]<\"']+[\"']|(^|[^A-Za-z0-9])s\.[A-Za-z0-9_-]{24}([[:space:]\"'\`,;)}]|$)|(^|[^A-Za-z0-9])(hvs|hvr|hvb|hvp|hvS)\.[A-Za-z0-9_.:-]{8,}|(^|[^A-Za-z0-9])b\.[A-Za-z0-9_-]{64,}([[:space:]\"'\`,;)}]|$)|(AKIA|ASIA)[0-9A-Z]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox(a|b|p|r|s)-[A-Za-z0-9-]{12,}|xapp-[A-Za-z0-9-]{12,}|SK[0-9a-fA-F]{32}|AIza[0-9A-Za-z_-]{30,}|sk_live_[0-9A-Za-z]{16,})"
path_list="$(mktemp)"
trap 'rm -f -- "$path_list"' EXIT

set +e
find "$search_root" \
  -path "$search_root/.git" -prune -o \
  \( -type f -o -type l \) -print0 > "$path_list"
find_status=$?
set -e
if (( find_status != 0 )); then
  echo "Secret scan traversal failed (find status ${find_status})." >&2
  exit "$find_status"
fi

while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    echo "Secret scan refuses symbolic link: ${path}" >&2
    exit 2
  fi
  set +e
  LC_ALL=C grep -aEq "$pattern" -- "$path"
  secret_scan_status=$?
  set -e
  case "$secret_scan_status" in
    0)
      echo "Repository secret pattern detected: ${path#"$search_root"/}" >&2
      exit 1
      ;;
    1)
      ;;
    *)
      echo "Secret scan failed before completing (grep status ${secret_scan_status})." >&2
      exit "$secret_scan_status"
      ;;
  esac
done < "$path_list"
