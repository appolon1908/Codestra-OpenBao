#!/usr/bin/env bash
# Bind a sha256sum checksum file to one exact artifact and print its digest.
#
# `sha256sum -c` alone verifies whichever file the checksum line names, so a
# checksum for a sibling file would "pass" while a different artifact is used.
# This requires exactly one line naming the artifact's own basename and compares
# the artifact's actual digest, plus an optional independently reviewed digest.
set -Eeuo pipefail

artifact="${1:?usage: verify_artifact_checksum.sh ARTIFACT CHECKSUM_FILE [EXPECTED_SHA256]}"
checksum="${2:?usage: verify_artifact_checksum.sh ARTIFACT CHECKSUM_FILE [EXPECTED_SHA256]}"
expected="${3:-}"

fail() {
  echo "OPENBAO_ARTIFACT_CHECKSUM=FAIL ERROR=$1" >&2
  exit 1
}

for path in "$artifact" "$checksum"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "missing_or_symbolic:$(basename "$path")"
done
mapfile -t lines < "$checksum"
(( ${#lines[@]} == 1 )) || fail "checksum_line_count:${#lines[@]}"
pattern='^([0-9a-f]{64}) [ *](.+)$'
[[ "${lines[0]}" =~ $pattern ]] || fail "checksum_format"
recorded="${BASH_REMATCH[1]}"
[[ "${BASH_REMATCH[2]}" == "$(basename "$artifact")" ]] || fail "checksum_names_other_file"
actual="$(sha256sum "$artifact" | awk '{print $1}')"
[[ "$actual" == "$recorded" ]] || fail "artifact_digest_mismatch"
if [[ -n "$expected" && "$expected" != "$recorded" ]]; then
  fail "reviewed_digest_mismatch"
fi
printf '%s\n' "$recorded"
