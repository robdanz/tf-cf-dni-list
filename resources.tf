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
# Worker Script
# Note: Requires building the TypeScript first. Run: npm run build
# -----------------------------------------------------------------------------

resource "cloudflare_workers_script" "dni_list" {
  account_id  = var.account_id
  script_name = "tf-cf-dni-list"
  content     = file("${path.module}/worker.js")

  metadata = {
    main_module = "worker.js"
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
        text = var.worker_api_token
      }
    ]
  }
}

# -----------------------------------------------------------------------------
# Gateway HTTP Policy - Do Not Inspect for TLS error hosts
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_gateway_policy" "dni_tls_errors" {
  account_id  = var.account_id
  name        = "Do Not Inspect - TLS Error Hosts"
  description = "Bypass TLS inspection for hosts that fail with CLIENT_TLS_ERROR and are not approved apps"
  enabled     = true
  action      = "off"
  precedence  = 10

  filters = ["http"]

  traffic = "any(http.request.domains[*] in $${cloudflare_zero_trust_list.tls_error_hosts.id}) and any(app.statuses[*] in {\"unapproved\"})"
}

# -----------------------------------------------------------------------------
# Logpush Jobs
# -----------------------------------------------------------------------------

# Zero Trust Network Sessions - filtered to CLIENT_TLS_ERROR at Logpush level
resource "cloudflare_logpush_job" "zero_trust_sessions" {
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

# Gateway Network - all events, worker correlates by SessionID
resource "cloudflare_logpush_job" "gateway_network" {
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
