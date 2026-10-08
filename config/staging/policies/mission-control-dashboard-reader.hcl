# STAGING SOURCE ONLY. NOT APPLIED to any OpenBao server.
# codestra is the KV-v2 mount, and the token can read exactly one credential.
path "codestra/data/staging/mission-control/database/reader" {
  capabilities = ["read"]
}
