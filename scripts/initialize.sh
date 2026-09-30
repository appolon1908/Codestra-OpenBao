#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
custody_dir="${OPENBAO_INIT_CUSTODY_DIR:?set encrypted custody output directory}"
pgp_key_files="${OPENBAO_UNSEAL_PGP_KEY_FILES:?set five colon-separated offline public PGP key files}"
root_token_pgp_key="${OPENBAO_ROOT_TOKEN_PGP_KEY_FILE:?set an offline public PGP key file for the initial root token}"
confirmation="${OPENBAO_INIT_CONFIRMATION:-}"
expected_confirmation="INITIALIZE_NEW_${environment^^}_CLUSTER"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ "$confirmation" == "$expected_confirmation" ]] || {
  echo 'Initialization confirmation is absent or does not match the environment.' >&2
  exit 2
}
[[ "${OPENBAO_OFFLINE_CUSTODY_ACKNOWLEDGED:-false}" == true ]] || {
  echo 'Protected offline custody has not been acknowledged.' >&2
  exit 2
}
command -v bao >/dev/null
command -v jq >/dev/null
command -v gpg >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null
command -v stat >/dev/null
command -v sync >/dev/null

# Validate before any mkdir/chmod or server access. The operator provisions the
# persistent 0700 parent; this script never changes an existing parent's mode.
python3 "$repo_root/scripts/initialization_preflight.py"
ram_root="${OPENBAO_INIT_RAM_ROOT:-/dev/shm}"
[[ "$ram_root" == /* && -d "$ram_root" && ! -L "$ram_root" && -w "$ram_root" ]] || {
  echo 'A writable RAM-backed initialization directory is required.' >&2
  exit 2
}
ram_filesystem="$(stat -f -c %T -- "$ram_root")"
[[ "$ram_filesystem" == tmpfs || "$ram_filesystem" == ramfs ]] || {
  echo 'Initialization scratch storage must be tmpfs or ramfs.' >&2
  exit 2
}

set +e
status_json="$(bao status -format=json 2>/dev/null)"
status_code=$?
set -e
if [[ "$status_code" != 0 && "$status_code" != 2 ]]; then
  echo 'OpenBao status is ambiguous; initialization is prohibited.' >&2
  exit "$status_code"
fi
if jq -e 'type == "object" and .initialized == true' <<<"$status_json" >/dev/null 2>&1; then
  echo 'OpenBao is already initialized; refusing to initialize or replace recovery material.' >&2
  exit 3
fi
jq -e 'type == "object" and .initialized == false and .sealed == true' <<<"$status_json" >/dev/null 2>&1 || {
  echo 'OpenBao initialization state is ambiguous.' >&2
  exit 2
}

IFS=: read -r -a unseal_pgp_keys <<<"$pgp_key_files"
[[ "${#unseal_pgp_keys[@]}" -eq 5 ]] || {
  echo 'Exactly five unseal PGP public-key files are required.' >&2
  exit 2
}

all_keys=("${unseal_pgp_keys[@]}" "$root_token_pgp_key")
fingerprints=()
for key_file in "${all_keys[@]}"; do
  [[ "$key_file" == /* && -f "$key_file" && ! -L "$key_file" && -s "$key_file" ]] || {
    echo 'A custody PGP public-key path is invalid.' >&2
    exit 2
  }
  key_info="$(gpg --batch --with-colons --import-options show-only --import "$key_file" 2>/dev/null)" || {
    echo 'A custody PGP public key could not be inspected.' >&2
    exit 2
  }
  # Inspect the complete result; never import private material or silently use
  # the first key from a file containing multiple primary keys.
  [[ "$(awk -F: '$1 == "pub" {n++} END {print n+0}' <<<"$key_info")" == 1 ]] &&
    [[ "$(awk -F: '$1 == "sec" || $1 == "ssb" {n++} END {print n+0}' <<<"$key_info")" == 0 ]] || {
    echo 'Each custody file must contain exactly one public PGP primary key and no private keys.' >&2
    exit 2
  }
  key_fingerprint="$(awk -F: '$1 == "fpr" && !seen++ {print $10}' <<<"$key_info")"
  [[ "$key_fingerprint" =~ ^[0-9A-Fa-f]{40}$ ]] || {
    echo 'A custody PGP public key has no valid primary fingerprint.' >&2
    exit 2
  }
  fingerprints+=("${key_fingerprint^^}")
done

# Five distinct unseal private-key holders are required; the initial root token
# also uses a sixth, distinct offline key so one compromised custodian cannot
# recover the root token or satisfy the 3-of-5 unseal threshold alone.
unique_count="$(printf '%s\n' "${fingerprints[@]}" | sort -u | wc -l | tr -d ' ')"
[[ "$unique_count" -eq 6 ]] || {
  echo 'All five unseal keys and the root-token key must be distinct.' >&2
  exit 2
}

[[ ! -e "$custody_dir" && ! -L "$custody_dir" ]] || {
  echo 'Encrypted custody output already exists; refusing to overwrite it.' >&2
  exit 2
}

umask 077
mkdir -- "$custody_dir"
chmod 700 -- "$custody_dir"

# The raw initialization response exists only in RAM. It contains PGP-encrypted
# shares and a PGP-encrypted initial root token; plaintext recovery material is
# never requested from OpenBao and is never written to persistent storage.
raw_dir="$(mktemp -d "$ram_root/openbao-init.XXXXXX")"
raw_json="$raw_dir/init.json"
initialization_attempted=false
custody_complete=false
cleanup() {
  if [[ "$initialization_attempted" == true && "$custody_complete" != true && -s "$raw_json" ]]; then
    # An export failure must not erase the only remaining encrypted response.
    # Keep the private RAM directory for the authorized recovery operator.
    echo 'OPENBAO_CUSTODY_EXPORT=INCOMPLETE RAM_BUFFER_RETAINED=YES DO_NOT_REINITIALIZE' >&2
    return
  fi
  if [[ -f "$raw_json" ]]; then
    shred --remove --zero "$raw_json" 2>/dev/null || rm -f "$raw_json"
  fi
  rmdir "$raw_dir" 2>/dev/null || true
}
trap cleanup EXIT

pgp_csv="$(IFS=,; printf '%s' "${unseal_pgp_keys[*]}")"
initialization_attempted=true
"$(dirname "${BASH_SOURCE[0]}")/require_mutation_lease.sh" >/dev/null
bao operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -pgp-keys="$pgp_csv" \
  -root-token-pgp-key="$root_token_pgp_key" \
  -format=json >"$raw_json"

jq -e '
  (.unseal_keys_b64 | type == "array" and length == 5 and all(.[]; type == "string" and length > 0)) and
  (.root_token | type == "string" and length > 0)
' "$raw_json" >/dev/null

for index in 0 1 2 3 4; do
  jq -er ".unseal_keys_b64[$index]" "$raw_json" >"$custody_dir/unseal-share-$((index + 1)).pgp.b64"
done
jq -er '.root_token' "$raw_json" >"$custody_dir/initial-root-token.pgp.b64"

jq -n \
  --arg environment "$environment" \
  --arg initialized_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg f1 "${fingerprints[0]}" \
  --arg f2 "${fingerprints[1]}" \
  --arg f3 "${fingerprints[2]}" \
  --arg f4 "${fingerprints[3]}" \
  --arg f5 "${fingerprints[4]}" \
  --arg fr "${fingerprints[5]}" \
  '{
    schema_version: 1,
    environment: $environment,
    initialized_at: $initialized_at,
    seal_type: "shamir",
    key_shares: 5,
    key_threshold: 3,
    recovery_material: "pgp-encrypted-base64",
    plaintext_recovery_material_persisted: false,
    unseal_share_public_key_fingerprints: [$f1,$f2,$f3,$f4,$f5],
    initial_root_token_public_key_fingerprint: $fr
  }' >"$custody_dir/MANIFEST.json"

sha256sum \
  "$custody_dir"/unseal-share-*.pgp.b64 \
  "$custody_dir/initial-root-token.pgp.b64" \
  "$custody_dir/MANIFEST.json" \
  >"$custody_dir/SHA256SUMS"
chmod 400 "$custody_dir"/*
# Finish filesystem persistence before destroying the encrypted RAM response.
sync -f "$custody_dir"
custody_complete=true
cleanup
trap - EXIT

echo 'OPENBAO_INITIALIZATION_PERFORMED=YES'
echo "CODESTRA_ENVIRONMENT=${environment}"
echo 'SHAMIR_KEY_SHARES=5'
echo 'SHAMIR_KEY_THRESHOLD=3'
echo 'UNSEAL_SHARES_PGP_ENCRYPTED=YES'
echo 'INITIAL_ROOT_TOKEN_PGP_ENCRYPTED=YES'
echo 'PLAINTEXT_RECOVERY_MATERIAL_PERSISTED=NO'
echo 'RECOVERY_MATERIAL_PRINTED=NO'
echo 'ROOT_TOKEN_PRINTED=NO'
