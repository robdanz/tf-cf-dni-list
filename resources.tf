# -----------------------------------------------------------------------------
# KV Namespace for session correlation
# -----------------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "session_cache" {
  account_id = var.account_id
  title      = "tf-cf-dni-list-session-cache"
}

# -----------------------------------------------------------------------------
# Gateway List for TLS error hostnames
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_list" "tls_error_hosts" {
  account_id  = var.account_id
  name        = "CLIENT_TLS_ERROR_SNI"
  description = "Hostnames with TLS inspection errors - auto-populated by tf-cf-dni-list worker"
  type        = "DOMAIN"
}

# -----------------------------------------------------------------------------
# Worker (v5 pattern: worker + version + deployment)
# Note: Requires building the TypeScript first. Run: npm run build
# -----------------------------------------------------------------------------

resource "cloudflare_worker" "dni_list" {
  account_id = var.account_id
  name       = "tf-cf-dni-list"
  subdomain = {
    enabled          = true
    previews_enabled = true
  }
}

resource "cloudflare_worker_version" "dni_list" {
  account_id         = var.account_id
  worker_id          = cloudflare_worker.dni_list.id
  compatibility_date = "2024-11-01"
  main_module        = "worker.js"

  modules = [{
    name         = "worker.js"
    content_type = "application/javascript+module"
    content_file = "worker.js"
  }]

  bindings = [
    {
      type         = "kv_namespace"
      name         = "SESSION_CACHE"
      namespace_id = cloudflare_workers_kv_namespace.session_cache.id
    },
    {
      type = "plain_text"
      name = "ACCOUNT_ID"
      text = var.account_id
    },
    {
      type = "plain_text"
      name = "LIST_ID"
      text = cloudflare_zero_trust_list.tls_error_hosts.id
    },
    {
      type = "secret_text"
      name = "API_TOKEN"
      text = var.cloudflare_api_token
    }
  ]
}

resource "cloudflare_workers_deployment" "dni_list" {
  account_id  = var.account_id
  script_name = cloudflare_worker.dni_list.name
  strategy    = "percentage"
  versions = [{
    percentage = 100
    version_id = cloudflare_worker_version.dni_list.id
  }]
}

# -----------------------------------------------------------------------------
# Gateway HTTP Policy - Do Not Inspect for TLS error hosts
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_gateway_policy" "dni_tls_errors" {
  account_id  = var.account_id
  name        = "Do Not Inspect - TLS Error Hosts"
  description = "Bypass TLS inspection for hosts that fail with CLIENT_TLS_ERROR"
  enabled     = true
  action      = "off"
  precedence  = 10

  filters = ["http"]

  traffic = "any(http.request.domains[*] in $${cloudflare_zero_trust_list.tls_error_hosts.id})"
}

# -----------------------------------------------------------------------------
# Logpush Jobs (requires Logpush entitlement - Enterprise or Zero Trust add-on)
# Set enable_logpush = true in terraform.tfvars if your account has access
# -----------------------------------------------------------------------------

resource "cloudflare_logpush_job" "zero_trust_sessions" {
  count            = var.enable_logpush ? 1 : 0
  account_id       = var.account_id
  name             = "tf-cf-dni-list-zero-trust"
  enabled          = true
  dataset          = "zero_trust_network_sessions"
  destination_conf = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/"
  filter = jsonencode({
    where = {
      key      = "ConnectionCloseReason"
      operator = "eq"
      value    = "CLIENT_TLS_ERROR"
    }
  })
  output_options = {
    field_names = ["SessionID", "ConnectionCloseReason"]
    output_type = "ndjson"
  }
}

resource "cloudflare_logpush_job" "gateway_network" {
  count            = var.enable_logpush ? 1 : 0
  account_id       = var.account_id
  name             = "tf-cf-dni-list-gateway"
  enabled          = true
  dataset          = "gateway_network"
  destination_conf = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/gateway"
  output_options = {
    field_names = ["SessionID", "SNI"]
    output_type = "ndjson"
  }
}
