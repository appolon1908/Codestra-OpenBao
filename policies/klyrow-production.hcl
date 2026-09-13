path "codestra/data/production/klyrow/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/klyrow/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
