ui = true
disable_mlock = true
api_addr = "https://bao.codestra.media"
cluster_addr = "https://codestra-openbao:8201"

storage "raft" {
  path = "/openbao/data"
  node_id = "codestra-openbao-1"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable = true
  disable_unauthed_rekey_endpoints = true
  disable_unauthed_generate_root_endpoints = true
}

telemetry {
  disable_hostname = true
  prometheus_retention_time = "30s"
}
log_level = "info"
log_format = "json"
