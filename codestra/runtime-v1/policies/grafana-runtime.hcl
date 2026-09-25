path "kv-platform/data/observability/grafana/runtime" {
  capabilities = ["read"]
}

path "kv-platform/data/observability/grafana/oauth" {
  capabilities = ["read"]
}

path "kv-platform/data/observability/grafana/datasources/*" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/grafana-server" {
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
