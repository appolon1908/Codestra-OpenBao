path "codestra/data/production/odoo/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/odoo/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
