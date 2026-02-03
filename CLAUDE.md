# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloudflare Worker that acts as a Logpush HTTP destination for Zero Trust network session logs. It correlates two log streams via KV to identify hostnames causing TLS inspection failures and adds them to a Gateway list for automatic "Do Not Inspect" policy application.

## Commands

```bash
npm run build      # Bundle TypeScript to worker.js (required before terraform apply)
npm run typecheck  # TypeScript type checking
terraform init     # Initialize Terraform
terraform plan     # Preview infrastructure changes
terraform apply    # Deploy all resources
terraform destroy  # Remove all resources
```

## Architecture

**Single source file:** `src/index.ts` contains all worker logic.

**Data Flow:**
1. `POST /` receives `zero_trust_network_sessions` logs filtered to `CLIENT_TLS_ERROR` → stores `pending:{SessionID}` in KV
2. `POST /gateway` receives `gateway_network` logs with SNI → if matching pending SessionID exists, adds SNI to Gateway list
3. Bidirectional correlation: either log can arrive first; the second completes the match

**KV Keys:**
- `pending:{SessionID}` - Zero Trust arrived first, waiting for Gateway (value: "1")
- `sni:{SessionID}` - Gateway arrived first, waiting for Zero Trust (value: hostname)
- Both expire after 10 minutes (PENDING_TTL_SECONDS)

**Environment Bindings (configured by Terraform):**
- `SESSION_CACHE` - KV namespace for session correlation
- `API_TOKEN` - Cloudflare API token for Gateway list management
- `LIST_ID` - Gateway list UUID to append hostnames
- `ACCOUNT_ID` - Cloudflare account ID

**Terraform Resources (`resources.tf`):**
- Worker script with all bindings
- KV namespace (`tf-cf-dni-list-session-cache`)
- Gateway list (`CLIENT_TLS_ERROR_SNI`)
- Scoped API token for worker
- Gateway HTTP policy ("Do Not Inspect - TLS Error Hosts")
- Two Logpush jobs (zero_trust_network_sessions, gateway_network)

## Key Implementation Details

- Worker returns 200 even on errors to prevent Logpush failures (error details in JSON body)
- Gzip detection via Content-Encoding header OR magic bytes (0x1f 0x8b)
- Hostname validation: RFC-compliant, max 253 chars, alphanumeric + hyphen + dots
- Partial success returns 207 status with `errors` array in response

## Testing Locally

Use curl to simulate Logpush batches against a deployed worker:

```bash
# Health check
curl https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/

# Simulate zero_trust batch
curl -X POST https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/ \
  -H "Content-Type: application/x-ndjson" \
  -d '{"ConnectionCloseReason":"CLIENT_TLS_ERROR","SessionID":"test-123"}'

# Simulate gateway_network batch (completes correlation)
curl -X POST https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/gateway \
  -H "Content-Type: application/x-ndjson" \
  -d '{"SessionID":"test-123","SNI":"example.com"}'
```
