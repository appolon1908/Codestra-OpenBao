#!/usr/bin/env bash
# Refuse an OpenBao or runtime effect unless this process holds the current
# mutation lease for the cluster that serves CODESTRA_ENVIRONMENT.
#
# Call immediately before the first effect. The lease is acquired by the
# workflow (or operator) through the change kernel; a stale, released,
# superseded or other-cluster lease fails here with no effect.
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
lease_file="${OPENBAO_CHANGE_KERNEL_LEASE_FILE:?hold the environment mutation lease first (OPENBAO_CHANGE_KERNEL_LEASE_FILE)}"
: "${OPENBAO_CHANGE_KERNEL_DATABASE_URL:?set OPENBAO_CHANGE_KERNEL_DATABASE_URL}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
[[ -f "$lease_file" && ! -L "$lease_file" ]] || {
  echo 'OPENBAO_MUTATION_LEASE=FAIL ERROR=lease_file_missing' >&2
  exit 4
}

(cd "$repo_root" && python3 -m codestra.change_kernel.cli lock-check \
  --environment "$environment" --lease-file "$lease_file") >/dev/null
echo 'OPENBAO_MUTATION_LEASE=VALID'
