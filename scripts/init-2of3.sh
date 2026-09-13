#!/usr/bin/env sh
set -eu
umask 077

: "${BAO_ADDR:=http://127.0.0.1:18200}"
: "${BAO_CONTAINER:=codestra-openbao}"
: "${CUSTODY_DIR:?set CUSTODY_DIR to the four public PGP key files}"
: "${OUTPUT_DIR:?set OUTPUT_DIR to a new encrypted-output directory}"

[ ! -e "$OUTPUT_DIR" ] || { echo "refusing existing OUTPUT_DIR" >&2; exit 1; }
for f in custodian-1.pgp custodian-2.pgp custodian-3.pgp root-token.pgp; do
  [ -s "$CUSTODY_DIR/$f" ] || { echo "missing public key: $f" >&2; exit 1; }
done
status=$(curl -fsS "$BAO_ADDR/v1/sys/init")
printf '%s' "$status" | grep -q '"initialized":false' || {
  echo "OpenBao already initialized; refusing" >&2
  exit 1
}

remote="/tmp/custody-$$"
cleanup() { docker exec "$BAO_CONTAINER" rm -rf "$remote" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM
docker exec "$BAO_CONTAINER" mkdir -m 700 "$remote"
for f in custodian-1.pgp custodian-2.pgp custodian-3.pgp root-token.pgp; do
  docker cp "$CUSTODY_DIR/$f" "$BAO_CONTAINER:$remote/$f" >/dev/null
done

mkdir -m 700 "$OUTPUT_DIR"
docker exec "$BAO_CONTAINER" bao operator init -address=http://127.0.0.1:8200 -format=json \
  -key-shares=3 -key-threshold=2 \
  -pgp-keys="$remote/custodian-1.pgp,$remote/custodian-2.pgp,$remote/custodian-3.pgp" \
  -root-token-pgp-key="$remote/root-token.pgp" > "$OUTPUT_DIR/init-encrypted.json"
chmod 600 "$OUTPUT_DIR/init-encrypted.json"
sha256sum "$OUTPUT_DIR/init-encrypted.json" > "$OUTPUT_DIR/init-encrypted.json.sha256"
echo "initialized with encrypted material only; distribute shares separately"
