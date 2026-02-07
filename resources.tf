# -----------------------------------------------------------------------------
# KV Namespace for session correlation
# -----------------------------------------------------------------------------

resource "cloudflare_workers_kv_namespace" "session_cache" {
  account_id = var.account_id
  title      = "tf-cf-dni-list-session-cache"
}

# -----------------------------------------------------------------------------
# Gateway Lists
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_list" "tls_error_hosts" {
  account_id  = var.account_id
  name        = "01-CLIENT_TLS_ERROR_SNI"
  description = "Hostnames with TLS inspection errors - auto-populated by tf-cf-dni-list worker"
  type        = "DOMAIN"
}

resource "cloudflare_zero_trust_list" "bypass_inspection" {
  account_id  = var.account_id
  name        = "01-BYPASS-INSPECTION-DOMAINS"
  description = "Manually managed bypass domains, excluding unapproved apps"
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
    previews_enabled = false
  }
  observability = {
    enabled = true
    logs = {
      enabled           = true
      invocation_logs   = true
      head_sampling_rate = 1
    }
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
    },
    {
      type = "secret_text"
      name = "LOGPUSH_SECRET"
      text = var.logpush_secret
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

# Wait for worker deployment to propagate globally before Logpush validation
resource "time_sleep" "wait_for_worker" {
  depends_on      = [cloudflare_workers_deployment.dni_list]
  create_duration = "10s"
}

# -----------------------------------------------------------------------------
# Gateway HTTP Policy - Do Not Inspect for TLS error hosts
# -----------------------------------------------------------------------------

# Fetch current Gateway rules to calculate precedence
data "http" "gateway_rules" {
  url = "https://api.cloudflare.com/client/v4/accounts/${var.account_id}/gateway/rules"

  request_headers = {
    Authorization = "Bearer ${var.cloudflare_api_token}"
  }
}

locals {
  gateway_rules = jsondecode(data.http.gateway_rules.response_body).result
  # Get all precedence values from ALL rules (excluding our own policy)
  # Precedence is shared across DNS, network, and HTTP policies
  all_precedences = toset([
    for rule in local.gateway_rules :
    rule.precedence if rule.name != "Do Not Inspect - TLS Error Hosts"
  ])
  # Find the minimum precedence currently in use
  min_precedence = length(local.all_precedences) > 0 ? min(local.all_precedences...) : 1000
  # Find first available precedence starting from 0
  # Check values 0 through min-1 to find unused slot, otherwise use min-100
  dni_precedence = (
    !contains(local.all_precedences, 0) ? 0 :
    !contains(local.all_precedences, 1) ? 1 :
    !contains(local.all_precedences, 2) ? 2 :
    !contains(local.all_precedences, 3) ? 3 :
    !contains(local.all_precedences, 4) ? 4 :
    !contains(local.all_precedences, 5) ? 5 :
    local.min_precedence - 100
  )
}

resource "cloudflare_zero_trust_gateway_policy" "dni_tls_errors" {
  account_id  = var.account_id
  name        = "Do Not Inspect - TLS Error Hosts"
  description = "Bypass TLS inspection for approved bypass domains and TLS error hosts filtered by security/content categories and app approval status"
  precedence  = local.dni_precedence
  enabled     = true
  action      = "off"

  filters = ["http"]

  traffic = format(
    "any(http.conn.domains[*] in $%s) or (not(any(http.conn.security_category[*] in {68 178 80 187 83 176 175 117 131 188 134 191 151 153})) and http.conn.hostname in $%s) or (not(any(http.conn.content_category[*] in {32 169 177 128})) and http.conn.hostname in $%s) or (http.conn.hostname in $%s and not(any(app.statuses[*] == \"unapproved\")))",
    cloudflare_zero_trust_list.bypass_inspection.id,
    cloudflare_zero_trust_list.tls_error_hosts.id,
    cloudflare_zero_trust_list.tls_error_hosts.id,
    cloudflare_zero_trust_list.tls_error_hosts.id
  )
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
  destination_conf = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/?header_X-Logpush-Secret=${var.logpush_secret}"

  depends_on = [time_sleep.wait_for_worker]
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
  destination_conf = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/gateway?header_X-Logpush-Secret=${var.logpush_secret}"

  depends_on = [time_sleep.wait_for_worker]
  output_options = {
    field_names = ["SessionID", "SNI"]
    output_type = "ndjson"
  }
}
