# Codestra Stage 6 monitoring secret boundary.
# Source template only: this file is not part of the active policy set.
# Every deny path enumerates a real mount; embedded wildcard mount names are prohibited.
path "kv-platform/data/observability/middleware/staging/keycloak-client" {
  capabilities = ["read"]
}

path "kv-platform/metadata/observability/middleware/staging/keycloak-client" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "kv-codestra/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-codestra/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-codestra/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-moneybee/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-moneybee/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-moneybee/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-beyvra/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-beyvra/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-beyvra/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-breero/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-breero/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-breero/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-larim-a/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-larim-a/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-larim-a/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-transportation/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-transportation/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-transportation/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-booked4seasons/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-booked4seasons/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-booked4seasons/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-social/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-social/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-social/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-klyrow/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-klyrow/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-klyrow/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-telnexa/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-telnexa/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-telnexa/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-kyqra/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-kyqra/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-kyqra/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-restaurant/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-restaurant/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-restaurant/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-provisioning/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-provisioning/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-provisioning/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}

path "kv-beyvra/data/execution/*" {
  capabilities = ["deny"]
}
