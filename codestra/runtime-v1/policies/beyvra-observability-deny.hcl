path "kv-beyvra/data/*/production/broker-exchange-custody/*" {
  capabilities = ["deny"]
}

path "kv-beyvra/metadata/*/production/broker-exchange-custody/*" {
  capabilities = ["deny"]
}

path "transit-beyvra/sign/*" {
  capabilities = ["deny"]
}

path "transit-beyvra/decrypt/*" {
  capabilities = ["deny"]
}

path "transit-beyvra/export/*" {
  capabilities = ["deny"]
}

path "database/creds/beyvra-trading-*" {
  capabilities = ["deny"]
}

path "ssh/sign/beyvra-*" {
  capabilities = ["deny"]
}
