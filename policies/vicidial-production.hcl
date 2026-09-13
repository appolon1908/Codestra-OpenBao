path "codestra/data/production/vicidial/*" {
  capabilities = ["read"]
}
path "codestra/metadata/production/vicidial/*" {
  capabilities = ["read", "list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
