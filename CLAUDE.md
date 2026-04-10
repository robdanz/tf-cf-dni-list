# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloudflare Worker that acts as a Logpush HTTP destination for Zero Trust network session logs. It reads the SNI field directly from `CLIENT_TLS_ERROR` records and adds hostnames to a Gateway list for automatic "Do Not Inspect" policy application. The policy filters TLS error hosts by security categories, content categories, and application approval status to prevent bypassing inspection for dangerous or unapproved destinations.

## Commands

```bash
npm run build      # Bundle TypeScript to worker.js (required before terraform apply)
npm run typecheck  # TypeScript type checking
terraform init     # Initialize Terraform (run after adding providers)
terraform plan     # Preview infrastructure changes
terraform apply    # Deploy all resources
terraform destroy  # Remove all resources
```

## Architecture

**Single source file:** `src/index.ts` contains all worker logic.

**Five Gateway Lists:**
- `01-BYPASS_CLIENT_TLS_ERROR_SNI` - Auto-populated hostnames from TLS errors
- `01-BYPASS-INSPECTION-DOMAINS` - Manually managed domain overrides (matches domain + subdomains)
- `01-BYPASS-INSPECTION-HOSTS` - Manually managed hostname overrides (exact match only)
- `01-BLOCK-DOMAIN-LIST` - Manually managed domain blocklist (blocked at DNS, Network, HTTP, and excluded from DNI bypass)
- `01-BLOCK-HOST-LIST` - Manually managed host blocklist (exact match, blocked at DNS, Network, HTTP, and excluded from DNI bypass)

**Data Flow:**
1. `POST /` receives `zero_trust_network_sessions` logs filtered to `CLIENT_TLS_ERROR`
2. Each record includes `SNI` directly — valid hostnames are appended to the Gateway list immediately
3. No KV correlation needed; the worker is stateless

**Environment Bindings (configured by Terraform):**
- `API_TOKEN` - Cloudflare scoped API Token
- `LIST_ID` - Gateway list UUID for auto-populated hostnames
- `ACCOUNT_ID` - Cloudflare account ID
- `LOGPUSH_SECRET` - Shared secret for endpoint authentication

**API Token Required Scopes (all Account-level):**
- Logs: Edit
- Zero Trust: Edit
- Zero Trust PII: Read
- Workers Scripts: Edit

**Gateway Policies (4 managed policies, evaluated in order: DNS → Network → HTTP):**

*DNS Block - Domain Blocklist (highest priority DNS):*
```
Domain in $BLOCK_LIST → Block
```

*Network Block - Domain Blocklist (highest priority Network):*
```
SNI Domain in $BLOCK_LIST → Block
```

*Do Not Inspect - TLS Error Hosts (HTTP, 5 OR groups):*
```
Domain in $BYPASS_DOMAIN_LIST
OR Host in $BYPASS_HOST_LIST
OR (Host in $TLS_ERROR_LIST AND Security Categories not in {Anonymizer, Brand Embedding, C2/Botnet, Compromised, Cryptomining, DGA, DNS Tunneling, Malware, Phishing, PUP, Private IP, Scam, Spam, Spyware})
OR (Host in $TLS_ERROR_LIST AND Content Categories not in {Security Risks, New Domains, Newly Seen Domains, Parked & For Sale})
OR (Host in $TLS_ERROR_LIST AND Application Status is not unapproved AND Host not in $DOMAIN_BLOCK_LIST AND Host not in $HOST_BLOCK_LIST)
```

*Block HTTP - Domain/Host Blocklists (lower priority than DNI):*
```
Domain in $DOMAIN_BLOCK_LIST OR Host in $HOST_BLOCK_LIST → Block
```

**Security Category IDs (hardcoded in traffic expression):**
68=Anonymizer, 178=Brand Embedding, 80=C2/Botnet, 187=Compromised Domain, 83=Cryptomining, 176=DGA Domains, 175=DNS Tunneling, 117=Malware, 131=Phishing, 188=PUP, 134=Private IP, 191=Scam, 151=Spam, 153=Spyware

**Content Category IDs (hardcoded in traffic expression):**
32=Security Risks, 169=New Domains, 177=Newly Seen Domains, 128=Parked & For Sale Domains

## Terraform Resources

Uses Cloudflare provider v5 pattern plus `http` and `time` providers.

**Key resources in `resources.tf`:**
- `cloudflare_worker` + `cloudflare_worker_version` + `cloudflare_workers_deployment`
- Five `cloudflare_zero_trust_list` resources (auto TLS error + manual bypass domains + manual bypass hosts + manual domain blocklist + manual host blocklist)
- Four `cloudflare_zero_trust_gateway_policy` resources (DNS Block, Network Block, Do Not Inspect, HTTP Block) with dynamic precedence
- `time_sleep` - 10s delay after deployment for Logpush validation
- `data.http.gateway_rules` - Fetches existing rules to calculate unique precedence
- One `cloudflare_logpush_job` for `zero_trust_network_sessions` (fields: SessionID, ConnectionCloseReason, SNI)

**Precedence calculation:** Queries existing Gateway rules via API and finds first four available consecutive slots starting from 0 (DNS Block → Network Block → DNI → HTTP Block).

## Key Implementation Details

- Worker returns 200 even on errors to prevent Logpush failures (error details in JSON body)
- Logpush endpoint requires `X-Logpush-Secret` header (returns 401 without it)
- Gzip detection via Content-Encoding header OR magic bytes (0x1f 0x8b)
- Hostname validation: RFC-compliant, max 253 chars, alphanumeric + hyphen + dots
- Partial success returns 207 status with `errors` array in response
- **Gateway selector constraints by action:** Pre-TLS selectors (`http.conn.*`) are ONLY valid for the `off` (Do Not Inspect) action. Block/allow actions require post-TLS selectors (`http.request.*`). For example, use `http.conn.domains` in DNI policies but `http.request.domains` in block policies. The API returns error 2091 if you use the wrong selector type for an action.
- Logpush jobs depend on `time_sleep` to allow worker propagation before validation

## Configuration

`terraform.tfvars` (not committed - contains secrets):
```hcl
account_id             = "your-cloudflare-account-id"
cloudflare_api_token   = "your-scoped-api-token"
workers_subdomain      = "your-workers-subdomain"
logpush_secret         = "generate-with-openssl-rand-hex-32"
```

## Testing

```bash
# Health check (no auth required)
curl https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/

# Simulate zero_trust batch with SNI (requires secret header)
curl -X POST https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/ \
  -H "X-Logpush-Secret: YOUR_SECRET" \
  -H "Content-Type: application/x-ndjson" \
  -d '{"ConnectionCloseReason":"CLIENT_TLS_ERROR","SessionID":"test-123","SNI":"example.com"}'
```
