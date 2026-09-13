path "codestra/data/production/middleware/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/middleware/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
