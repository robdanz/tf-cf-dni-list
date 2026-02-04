output "worker_url" {
  description = "URL of the deployed worker"
  value       = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/"
}

output "gateway_url" {
  description = "URL for Gateway network logs endpoint"
  value       = "https://tf-cf-dni-list.${var.workers_subdomain}.workers.dev/gateway"
}

output "kv_namespace_id" {
  description = "ID of the KV namespace for session correlation"
  value       = cloudflare_workers_kv_namespace.session_cache.id
}

output "gateway_list_id" {
  description = "ID of the Gateway list for TLS error hostnames"
  value       = cloudflare_zero_trust_list.tls_error_hosts.id
}

output "gateway_list_name" {
  description = "Name of the Gateway list"
  value       = cloudflare_zero_trust_list.tls_error_hosts.name
}

output "bypass_inspection_list_id" {
  description = "ID of the manually managed bypass inspection list"
  value       = cloudflare_zero_trust_list.bypass_inspection.id
}

output "bypass_inspection_list_name" {
  description = "Name of the bypass inspection list"
  value       = cloudflare_zero_trust_list.bypass_inspection.name
}

output "worker_id" {
  description = "ID of the deployed worker"
  value       = cloudflare_worker.dni_list.id
}

output "dni_policy_precedence" {
  description = "Calculated precedence for the DNI policy (lower = higher priority)"
  value       = local.dni_precedence
}
