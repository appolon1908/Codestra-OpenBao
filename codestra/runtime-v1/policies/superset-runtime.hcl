path "kv-platform/data/analytics/superset/runtime" {
  capabilities = ["read"]
}

path "kv-platform/data/analytics/superset/oauth" {
  capabilities = ["read"]
}

path "database/creds/superset-metadata" {
  capabilities = ["read"]
}

path "database/creds/superset-analytics-readonly" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/superset-server" {
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
