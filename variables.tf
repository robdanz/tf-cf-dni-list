variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "cloudflare_email" {
  description = "Cloudflare account email"
  type        = string
}

variable "cloudflare_api_key" {
  description = "Cloudflare Global API Key"
  type        = string
  sensitive   = true
}

variable "workers_subdomain" {
  description = "Account's workers.dev subdomain (e.g., 'myaccount' for myaccount.workers.dev)"
  type        = string
}

variable "enable_logpush" {
  description = "Enable Logpush jobs (requires Enterprise or Zero Trust add-on with Logpush entitlement)"
  type        = bool
  default     = false
}
