path "codestra/data/production/telnexa/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/telnexa/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
