ui = true
cluster_name = "codestra-openbao"
disable_mlock = false
disable_clustering = false
log_level = "info"
log_format = "json"
default_lease_ttl = "15m"
max_lease_ttl = "1h"
raw_storage_endpoint = false

api_addr = "https://bao.codestra.media"
cluster_addr = "https://codestra-openbao:8201"

storage "raft" {
  path = "/openbao/data"
  node_id = "codestra-bao-01"
  performance_multiplier = 1
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable = 0
  tls_min_version = "tls13"
  tls_cert_file = "/run/secrets/openbao_server_cert.pem"
  tls_key_file = "/run/secrets/openbao_server_key.pem"
  tls_client_ca_file = "/run/secrets/codestra_workload_ca.pem"
  tls_require_and_verify_client_cert = true
  x_forwarded_for_reject_not_present = true
  x_forwarded_for_reject_not_authorized = true

  telemetry {
    unauthenticated_metrics_access = false
  }
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
