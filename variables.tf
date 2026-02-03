variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token with permissions for Workers, KV, Zero Trust, and Logpush"
  type        = string
  sensitive   = true
}

variable "workers_subdomain" {
  description = "Account's workers.dev subdomain (e.g., 'myaccount' for myaccount.workers.dev)"
  type        = string
}
