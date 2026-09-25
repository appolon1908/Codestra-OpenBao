# Render __BUSINESS__ only from the reviewed Codestra business catalogue.
# This role administers secret versions inside one business mount. It cannot
# mount engines, alter auth/audit configuration, create tokens, cross business
# boundaries or permanently destroy secret metadata/versions.

path "kv-__BUSINESS__/data/*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list"]
}

path "kv-__BUSINESS__/metadata/*" {
  capabilities = ["read", "update", "list"]
}

path "kv-__BUSINESS__/delete/*" {
  capabilities = ["update"]
}

path "kv-__BUSINESS__/undelete/*" {
  capabilities = ["update"]
}

path "kv-__BUSINESS__/destroy/*" {
  capabilities = ["deny"]
}

path "kv-__BUSINESS__/config" {
  capabilities = ["read"]
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

path "auth/token/create*" {
  capabilities = ["deny"]
}
