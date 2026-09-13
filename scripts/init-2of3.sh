#!/usr/bin/env sh
set -eu
umask 077

: "${BAO_ADDR:=http://127.0.0.1:18200}"
: "${CUSTODY_DIR:?set CUSTODY_DIR to a directory containing custodian-1.pgp, custodian-2.pgp, custodian-3.pgp and root-token.pgp}"
: "${OUTPUT_DIR:?set OUTPUT_DIR to a new encrypted-output directory}"

[ ! -e "$OUTPUT_DIR" ] || { echo "refusing existing OUTPUT_DIR" >&2; exit 1; }
for f in custodian-1.pgp custodian-2.pgp custodian-3.pgp root-token.pgp; do
  [ -s "$CUSTODY_DIR/$f" ] || { echo "missing public key: $f" >&2; exit 1; }
done

mkdir -m 700 "$OUTPUT_DIR"
status=$(curl -fsS "$BAO_ADDR/v1/sys/init")
printf '%s' "$status" | grep -q '"initialized":false' || {
  echo "OpenBao is already initialized; refusing to run" >&2
  exit 1
}

bao operator init -address="$BAO_ADDR" -format=json \
  -key-shares=3 -key-threshold=2 \
  -pgp-keys="$CUSTODY_DIR/custodian-1.pgp,$CUSTODY_DIR/custodian-2.pgp,$CUSTODY_DIR/custodian-3.pgp" \
  -root-token-pgp-key="$CUSTODY_DIR/root-token.pgp" > "$OUTPUT_DIR/init-encrypted.json"

chmod 600 "$OUTPUT_DIR/init-encrypted.json"
sha256sum "$OUTPUT_DIR/init-encrypted.json" > "$OUTPUT_DIR/init-encrypted.json.sha256"
echo "Initialization complete. Output contains encrypted material only."
echo "Distribute each encrypted share to its named custodian; do not keep all decrypted shares together."
