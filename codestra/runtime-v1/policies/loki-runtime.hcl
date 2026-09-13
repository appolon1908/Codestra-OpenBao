path "kv-platform/data/observability/loki/runtime" {
  capabilities = ["read"]
}

path "kv-platform/data/observability/loki/object-storage" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/loki-server" {
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
