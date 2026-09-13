#!/usr/bin/env sh
set -eu
grep -q '127.0.0.1:18200:8200' deploy/compose.yaml
grep -q 'internal: true' deploy/compose.yaml
grep -q 'cap_drop:.*ALL' deploy/compose.yaml
grep -q 'no-new-privileges:true' deploy/compose.yaml
grep -q 'key-shares=3' scripts/init-2of3.sh
grep -q 'key-threshold=2' scripts/init-2of3.sh
grep -q 'root-token-pgp-key' scripts/init-2of3.sh
! grep -REn --exclude-dir=.git '(root_token|unseal_key|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)[[:space:]]*[:=][[:space:]]*[^<]' .
echo "static security checks passed"
