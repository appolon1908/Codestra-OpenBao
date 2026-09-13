#!/usr/bin/env bash
set -Eeuo pipefail

environment="${CODESTRA_ENVIRONMENT:?set CODESTRA_ENVIRONMENT}"
server_cert="${OPENBAO_SERVER_CERT_FILE:?set server certificate path}"
server_key="${OPENBAO_SERVER_KEY_FILE:?set server private-key path}"
server_ca="${OPENBAO_SERVER_CA_FILE:?set server trust-chain CA path}"
client_ca="${CODESTRA_CLIENT_CA_FILE:?set client CA path}"
health_cert="${OPENBAO_HEALTH_CLIENT_CERT_FILE:?set health client certificate path}"
health_key="${OPENBAO_HEALTH_CLIENT_KEY_FILE:?set health client private-key path}"

[[ "$environment" =~ ^(development|test|staging|production)$ ]]
for command in jq openssl sha256sum; do command -v "$command" >/dev/null; done
for path in "$server_cert" "$server_key" "$server_ca" "$client_ca" "$health_cert" "$health_key"; do
  [[ -f "$path" && ! -L "$path" ]]
done

environment_config="config/environments/${environment}/environment.json"
api_address="$(jq -r .canonicalApiAddress "$environment_config")"
[[ "$api_address" == https://* ]]
api_host="${api_address#https://}"
api_host="${api_host%%/*}"
api_host="${api_host%%:*}"
node_id="$(jq -r .nodeId "$environment_config")"
[[ -n "$api_host" && -n "$node_id" ]]

openssl verify -CAfile "$server_ca" -purpose sslserver "$server_cert" >/dev/null
openssl x509 -in "$server_cert" -noout -checkend 604800 >/dev/null
openssl x509 -in "$server_cert" -noout -checkhost "$api_host" >/dev/null
openssl x509 -in "$server_cert" -noout -checkhost "$node_id" >/dev/null
openssl verify -CAfile "$client_ca" -purpose sslclient "$health_cert" >/dev/null
openssl x509 -in "$health_cert" -noout -checkend 604800 >/dev/null
openssl x509 -in "$server_ca" -noout -checkend 2592000 >/dev/null
openssl x509 -in "$client_ca" -noout -checkend 2592000 >/dev/null

cert_public_sha="$(openssl x509 -in "$server_cert" -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
key_public_sha="$(openssl pkey -in "$server_key" -pubout -outform DER 2>/dev/null | \
  sha256sum | awk '{print $1}')"
[[ "$cert_public_sha" == "$key_public_sha" ]]
health_cert_public_sha="$(openssl x509 -in "$health_cert" -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
health_key_public_sha="$(openssl pkey -in "$health_key" -pubout -outform DER 2>/dev/null | \
  sha256sum | awk '{print $1}')"
[[ "$health_cert_public_sha" == "$health_key_public_sha" ]]

echo 'OPENBAO_TLS_MATERIAL=PASS'
echo "OPENBAO_TLS_SERVER_NAME=${api_host}"
echo "OPENBAO_TLS_NODE_NAME=${node_id}"
echo 'OPENBAO_TLS_MINIMUM_CERTIFICATE_VALIDITY=PASS'
echo 'OPENBAO_MTLS_CLIENT_CHAIN=PASS'
