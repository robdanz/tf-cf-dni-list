# -----------------------------------------------------------------------------
# Gateway Lists
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_list" "tls_error_hosts" {
  account_id  = var.account_id
  name        = "01-BYPASS_CLIENT_TLS_ERROR_SNI"
  description = "Hostnames with TLS inspection errors - auto-populated by tf-cf-dni-list worker"
  type        = "DOMAIN"
}

resource "cloudflare_zero_trust_list" "bypass_inspection" {
  account_id  = var.account_id
  name        = "01-BYPASS-INSPECTION-DOMAINS"
  description = "Manually managed bypass domains, excluding unapproved apps"
  type        = "DOMAIN"
}

resource "cloudflare_zero_trust_list" "domain_blocklist" {
  account_id  = var.account_id
  name        = "01-BLOCK-DOMAIN-LIST"
  description = "Manually managed domain blocklist - blocked at DNS, Network, and excluded from Do Not Inspect bypass"
  type        = "DOMAIN"
}

resource "cloudflare_zero_trust_list" "bypass_inspection_hosts" {
  account_id  = var.account_id
  name        = "01-BYPASS-INSPECTION-HOSTS"
  description = "Manually managed hostname bypass list - exact hostname match, unconditional Do Not Inspect bypass"
  type        = "HOST"
}

resource "cloudflare_zero_trust_list" "host_blocklist" {
  account_id  = var.account_id
  name        = "01-BLOCK-HOST-LIST"
  description = "Manually managed host blocklist - exact hostname match, blocked at DNS, Network, HTTP, and excluded from Do Not Inspect bypass"
  type        = "HOST"
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
  # Managed policy names to exclude from precedence calculations
  managed_policy_names = toset([
    "Do Not Inspect - TLS Error Hosts",
    "Block HTTP - Domain Blocklist",
    "Block DNS - Domain Blocklist",
    "Block Network - SNI Domain Blocklist",
  ])
  # Get all precedence values from ALL rules (excluding our own policies)
  # Precedence is shared across DNS, network, and HTTP policies
  all_precedences = toset([
    for rule in local.gateway_rules :
    rule.precedence if !contains(local.managed_policy_names, rule.name)
  ])
  # Find the minimum precedence currently in use
  min_precedence = length(local.all_precedences) > 0 ? min(local.all_precedences...) : 1000
  # Find first four available precedence slots starting from 0
  dns_block_precedence = (
    !contains(local.all_precedences, 0) ? 0 :
    !contains(local.all_precedences, 1) ? 1 :
    !contains(local.all_precedences, 2) ? 2 :
    !contains(local.all_precedences, 3) ? 3 :
    !contains(local.all_precedences, 4) ? 4 :
    !contains(local.all_precedences, 5) ? 5 :
    local.min_precedence - 300
  )
  net_block_precedence = (
    !contains(local.all_precedences, local.dns_block_precedence + 1) ? local.dns_block_precedence + 1 :
    !contains(local.all_precedences, local.dns_block_precedence + 2) ? local.dns_block_precedence + 2 :
    !contains(local.all_precedences, local.dns_block_precedence + 3) ? local.dns_block_precedence + 3 :
    local.dns_block_precedence + 100
  )
  dni_precedence = (
    !contains(local.all_precedences, local.net_block_precedence + 1) ? local.net_block_precedence + 1 :
    !contains(local.all_precedences, local.net_block_precedence + 2) ? local.net_block_precedence + 2 :
    !contains(local.all_precedences, local.net_block_precedence + 3) ? local.net_block_precedence + 3 :
    local.net_block_precedence + 100
  )
  http_block_precedence = (
    !contains(local.all_precedences, local.dni_precedence + 1) ? local.dni_precedence + 1 :
    !contains(local.all_precedences, local.dni_precedence + 2) ? local.dni_precedence + 2 :
    !contains(local.all_precedences, local.dni_precedence + 3) ? local.dni_precedence + 3 :
    local.dni_precedence + 100
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
    "(any(http.conn.domains[*] in $%s) and not(any(http.conn.domains[*] in $%s)) and not(http.conn.hostname in $%s)) or (http.conn.hostname in $%s and not(any(http.conn.domains[*] in $%s)) and not(http.conn.hostname in $%s)) or (http.conn.hostname in $%s and not(any(http.conn.security_category[*] in {68 178 80 187 83 176 175 117 131 188 134 191 151 153})) and not(any(http.conn.domains[*] in $%s)) and not(http.conn.hostname in $%s)) or (http.conn.hostname in $%s and not(any(http.conn.content_category[*] in {32 169 177 128})) and not(any(http.conn.domains[*] in $%s)) and not(http.conn.hostname in $%s)) or (http.conn.hostname in $%s and not(any(app.statuses[*] == \"unapproved\")) and not(any(http.conn.domains[*] in $%s)) and not(http.conn.hostname in $%s))",
    cloudflare_zero_trust_list.bypass_inspection.id,       # 1: bypass domains list
    cloudflare_zero_trust_list.domain_blocklist.id,        # 1: not in domain blocklist
    cloudflare_zero_trust_list.host_blocklist.id,          # 1: not in host blocklist
    cloudflare_zero_trust_list.bypass_inspection_hosts.id, # 2: bypass hosts list
    cloudflare_zero_trust_list.domain_blocklist.id,        # 2: not in domain blocklist
    cloudflare_zero_trust_list.host_blocklist.id,          # 2: not in host blocklist
    cloudflare_zero_trust_list.tls_error_hosts.id,         # 3: TLS error hosts
    cloudflare_zero_trust_list.domain_blocklist.id,        # 3: not in domain blocklist
    cloudflare_zero_trust_list.host_blocklist.id,          # 3: not in host blocklist
    cloudflare_zero_trust_list.tls_error_hosts.id,         # 4: TLS error hosts
    cloudflare_zero_trust_list.domain_blocklist.id,        # 4: not in domain blocklist
    cloudflare_zero_trust_list.host_blocklist.id,          # 4: not in host blocklist
    cloudflare_zero_trust_list.tls_error_hosts.id,         # 5: TLS error hosts
    cloudflare_zero_trust_list.domain_blocklist.id,        # 5: not in domain blocklist
    cloudflare_zero_trust_list.host_blocklist.id           # 5: not in host blocklist
  )
}

# -----------------------------------------------------------------------------
# Gateway HTTP Policy - Block domains in blocklist
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_gateway_policy" "http_block_blocklist" {
  account_id  = var.account_id
  name        = "Block HTTP - Domain Blocklist"
  description = "Block HTTP connections for domains or hosts in the manually managed blocklists"
  precedence  = local.http_block_precedence
  enabled     = true
  action      = "block"

  filters = ["http"]

  traffic = format(
    "any(http.request.domains[*] in $%s) or http.request.host in $%s",
    cloudflare_zero_trust_list.domain_blocklist.id,
    cloudflare_zero_trust_list.host_blocklist.id
  )
}

# -----------------------------------------------------------------------------
# Gateway DNS Policy - Block domains in blocklist
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_gateway_policy" "dns_block_blocklist" {
  account_id  = var.account_id
  name        = "Block DNS - Domain Blocklist"
  description = "Block DNS queries for domains or hosts in the manually managed blocklists"
  precedence  = local.dns_block_precedence
  enabled     = true
  action      = "block"

  filters = ["dns"]

  traffic = format(
    "any(dns.domains[*] in $%s) or dns.fqdn in $%s",
    cloudflare_zero_trust_list.domain_blocklist.id,
    cloudflare_zero_trust_list.host_blocklist.id
  )
}

# -----------------------------------------------------------------------------
# Gateway Network Policy - Block SNI domains in blocklist
# -----------------------------------------------------------------------------

resource "cloudflare_zero_trust_gateway_policy" "net_block_blocklist" {
  account_id  = var.account_id
  name        = "Block Network - SNI Domain Blocklist"
  description = "Block network connections with SNI domains or hosts in the manually managed blocklists"
  precedence  = local.net_block_precedence
  enabled     = true
  action      = "block"

  filters = ["l4"]

  traffic = format(
    "any(net.sni.domains[*] in $%s) or net.sni.host in $%s",
    cloudflare_zero_trust_list.domain_blocklist.id,
    cloudflare_zero_trust_list.host_blocklist.id
  )
}

# -----------------------------------------------------------------------------
# Logpush Jobs
# -----------------------------------------------------------------------------

resource "cloudflare_logpush_job" "zero_trust_sessions" {
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
    field_names = ["SessionID", "ConnectionCloseReason", "SNI"]
    output_type = "ndjson"
  }
}
