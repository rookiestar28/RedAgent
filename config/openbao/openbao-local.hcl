ui = false
disable_mlock = true

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

# OpenBao 2.5 manages audit devices declaratively; API creation remains disabled.
audit "file" "audit-file-1" {
  description = "R098 local conformance audit copy one"
  options {
    file_path = "/openbao/logs/audit-file-1.log"
    log_raw = "false"
  }
}

audit "file" "audit-file-2" {
  description = "R098 local conformance audit copy two"
  options {
    file_path = "/openbao/logs/audit-file-2.log"
    log_raw = "false"
  }
}
