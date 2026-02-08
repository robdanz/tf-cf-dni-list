variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cloudflare_api_token" {
  description = "Cloudflare scoped API Token (Account: Logs Edit, Zero Trust Edit, Zero Trust PII Read, Workers KV Storage Edit, Workers Scripts Edit)"
  type        = string
  sensitive   = true
}

variable "workers_subdomain" {
  description = "Account's workers.dev subdomain (e.g., 'myaccount' for myaccount.workers.dev)"
  type        = string
}

variable "logpush_secret" {
  description = "Shared secret for Logpush authentication (generate with: openssl rand -hex 32)"
  type        = string
  sensitive   = true
}
