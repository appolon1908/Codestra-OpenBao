# DO NOT APPLY by default.
# This template requires a separate production change, dual approval, a bound
# Beyvra execution workload identity, non-exportable transit key evidence and
# exact provider/application/environment placeholders. OpenBao denies every
# unspecified path by default; this policy grants only the exact paths below.

path "kv-beyvra/data/__APPLICATION__/__ENVIRONMENT__/broker-exchange-custody/__PROVIDER__/*" {
  capabilities = ["read"]
}

path "kv-beyvra/metadata/__APPLICATION__/__ENVIRONMENT__/broker-exchange-custody/__PROVIDER__/*" {
  capabilities = ["read"]
}

path "transit-beyvra/sign/__SIGNING_KEY__" {
  capabilities = ["update"]
}

path "transit-beyvra/verify/__SIGNING_KEY__" {
  capabilities = ["update"]
}

path "transit-beyvra/export/*" {
  capabilities = ["deny"]
}

path "transit-beyvra/keys/__SIGNING_KEY__/config" {
  capabilities = ["deny"]
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
