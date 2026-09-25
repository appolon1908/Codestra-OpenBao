# Render __BUSINESS__, __APPLICATION__, __ENVIRONMENT__, __DATABASE_ROLE__,
# __PKI_ROLE__ and __TRANSIT_KEY__ only from reviewed deployment inventory.
# The corresponding JWT role must bind the same immutable claims and audience.
#
# Ordinary workloads deliberately receive no sys/leases/renew or
# sys/leases/revoke capability. Those endpoints take a lease ID in the request
# body and cannot be constrained by these path placeholders. Workloads obtain a
# replacement short-lived credential/certificate through their scoped engine
# path; a separately reviewed broker/operator owns exceptional renewal or
# revocation workflows.

path "kv-__BUSINESS__/data/__APPLICATION__/__ENVIRONMENT__/*" {
  capabilities = ["read"]
}

path "kv-__BUSINESS__/metadata/__APPLICATION__/__ENVIRONMENT__/*" {
  capabilities = ["read", "list"]
}

path "database/creds/__DATABASE_ROLE__" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/__PKI_ROLE__" {
  capabilities = ["update"]
}

path "transit-platform/encrypt/__TRANSIT_KEY__" {
  capabilities = ["update"]
}

path "transit-platform/decrypt/__TRANSIT_KEY__" {
  capabilities = ["update"]
}

path "auth/token/create*" {
  capabilities = ["deny"]
}

path "sys/mounts/*" {
  capabilities = ["deny"]
}

path "sys/auth/*" {
  capabilities = ["deny"]
}

path "sys/audit/*" {
  capabilities = ["deny"]
}
