ui = true
cluster_name = "codestra-openbao-production"
disable_clustering = false
log_level = "info"
log_format = "json"
default_lease_ttl = "5m"
max_lease_ttl = "1h"
raw_storage_endpoint = false
plugin_directory = "/openbao/plugins"

api_addr = "https://bao.codestra.media"
cluster_addr = "https://codestra-bao-production-01:8201"

storage "raft" {
  path = "/openbao/data"
  node_id = "codestra-bao-production-01"
  performance_multiplier = 1
}

audit "file" "file-audit" {
  description = "Codestra fail-closed JSON audit log"
  options = {
    file_path = "/openbao/audit/openbao-audit.jsonl"
    mode = "0600"
    format = "json"
    hmac_accessor = "true"
    log_raw = "false"
  }
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"

  tls_disable = 0
  tls_min_version = "tls13"
  tls_cert_file = "/run/secrets/openbao-server-cert"
  tls_key_file = "/run/secrets/openbao-server-key"
  tls_client_ca_file = "/run/secrets/codestra-client-ca"
  tls_require_and_verify_client_cert = true

  x_forwarded_for_authorized_addrs = ["172.31.40.0/24"]
  x_forwarded_for_reject_not_present = true
  x_forwarded_for_reject_not_authorized = true

  disable_unauthed_rekey_endpoints = true
  disable_unauthed_generate_root_endpoints = true

  telemetry {
    unauthenticated_metrics_access = false
  }
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
