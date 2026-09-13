#!/usr/bin/env sh
set -eu
: "${BAO_ADDR:=http://127.0.0.1:18200}"

health=$(curl -fsS "$BAO_ADDR/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200")
printf '%s' "$health" | grep -q '"version"'
published=$(docker port codestra-openbao 8200/tcp)
[ "$published" = "127.0.0.1:18200" ] || {
  echo "native OpenBao port is not loopback-only: $published" >&2
  exit 1
}
docker inspect codestra-openbao --format '{{json .HostConfig.CapDrop}}' | grep -q '"ALL"'
docker inspect codestra-openbao --format '{{json .HostConfig.SecurityOpt}}' | grep -q 'no-new-privileges'
echo "deployment checks passed"
