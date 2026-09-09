log_level = "info"
log_format = "json"

vault {
  address     = "__OPENBAO_ADDRESS__"
  ca_cert     = "/run/codestra-openbao-tls/ca.pem"
  client_cert = "/run/codestra-openbao-tls/client.pem"
  client_key  = "/run/codestra-openbao-tls/client-key.pem"

  retry {
    num_retries = 6
  }
}

auto_auth {
  method "jwt" {
    mount_path = "auth/jwt-codestra"
    exit_on_err = true

    config = {
      path                        = "/run/codestra-identity/workload.jwt"
      role                        = "__ROLE__"
      remove_jwt_after_reading    = true
      remove_jwt_follows_symlinks = false
      jwt_read_period             = "1s"
    }
  }
}

template_config {
  exit_on_retry_failure         = true
  static_secret_render_interval = "1m"
}

template {
  source               = "__TEMPLATE_PATH__"
  destination          = "__DESTINATION__"
  create_dest_dirs     = false
  perms                = "0400"
  backup               = false
  error_on_missing_key = true
}
