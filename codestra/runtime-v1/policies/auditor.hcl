# Security auditors can review OpenBao health, mounts, auth methods, policies,
# audit-device configuration and Raft status. They cannot read business secret
# values, issue credentials/certificates, create tokens or mutate configuration.

path "sys/health" {
  capabilities = ["read"]
}

path "sys/seal-status" {
  capabilities = ["read"]
}

path "sys/leader" {
  capabilities = ["read"]
}

path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}

path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "sys/policies/acl" {
  capabilities = ["read", "list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read"]
}

path "sys/audit" {
  capabilities = ["read"]
}

path "sys/audit-hash/*" {
  capabilities = ["update"]
}

path "kv-*/data/*" {
  capabilities = ["deny"]
}

path "database/creds/*" {
  capabilities = ["deny"]
}

path "pki-*/issue/*" {
  capabilities = ["deny"]
}

path "transit-*/encrypt/*" {
  capabilities = ["deny"]
}

path "transit-*/decrypt/*" {
  capabilities = ["deny"]
}

path "auth/token/create*" {
  capabilities = ["deny"]
}
