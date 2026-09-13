path "codestra/data/production/keycloak/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/keycloak/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" { capabilities = ["read"] }
