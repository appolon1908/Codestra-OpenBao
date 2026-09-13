path "kv-platform/data/observability/tempo/runtime" {
  capabilities = ["read"]
}

path "kv-platform/data/observability/tempo/object-storage" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/tempo-server" {
  capabilities = ["create", "update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
