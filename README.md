# tf-cf-dni-list

Automated TLS inspection bypass management for Cloudflare Zero Trust. This solution identifies hostnames causing `CLIENT_TLS_ERROR` failures and automatically adds them to a Gateway "Do Not Inspect" policy, reducing manual triage of TLS inspection issues.

## Overview

When TLS inspection is enabled in Cloudflare Gateway, certain hosts fail inspection due to certificate pinning, mutual TLS, or other incompatibilities. These failures generate `CLIENT_TLS_ERROR` events in Zero Trust network session logs.

This solution:
1. Correlates Zero Trust session logs with Gateway network logs via Logpush
2. Automatically extracts the SNI (hostname) from failed TLS sessions
3. Adds hostnames to a Gateway list used by a "Do Not Inspect" HTTP policy
4. Filters bypass decisions using security categories, content categories, and application approval status

## Two-List Architecture

### 1. `01-CLIENT_TLS_ERROR_SNI` (Auto-populated)
Hostnames are automatically added when a `CLIENT_TLS_ERROR` is detected. This list grows organically as users encounter TLS inspection failures. The Do Not Inspect policy applies additional filtering to these hostnames — bypassing only those that are not in dangerous security/content categories and are not unapproved applications.

### 2. `01-BYPASS-INSPECTION-DOMAINS` (Manually managed)
A curated list of domains for unconditional inspection bypass.

**Recommended workflow:**
1. Periodically review the auto-populated `01-CLIENT_TLS_ERROR_SNI` list
2. Identify patterns (e.g., multiple hostnames like `api1.example.com`, `api2.example.com`)
3. Remove individual hostnames from the auto-populated list
4. Add a single domain entry (e.g., `example.com`) to `01-BYPASS-INSPECTION-DOMAINS`

This consolidation keeps the lists manageable and reduces policy evaluation overhead.

## Requirements

- **Cloudflare Enterprise** with **Zero Trust Enterprise**
- **Logpush entitlement** (included with Enterprise)
- Terraform v1.0+
- Node.js v18+

## Deployment

### 1. Clone and Build

```bash
git clone git@github.com:robdanz/tf-cf-dni-list.git
cd tf-cf-dni-list
npm install
npm run build
```

### 2. Configure Terraform

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
account_id          = "your-cloudflare-account-id"
cloudflare_email    = "your-cloudflare-email"
cloudflare_api_key  = "your-global-api-key"      # Global API Key required for Logpush
workers_subdomain   = "your-workers-subdomain"   # e.g., "myaccount" for myaccount.workers.dev
enable_logpush      = true
logpush_secret      = "your-random-secret"       # Generate with: openssl rand -hex 32
```

> **Note:** Global API Key is required due to Logpush API permission requirements. Scoped API tokens do not currently support all necessary operations.

### 3. Deploy

```bash
terraform init
terraform apply
```

## What Gets Created

| Resource | Description |
|----------|-------------|
| **Worker** | `tf-cf-dni-list` - Logpush HTTP destination endpoint |
| **KV Namespace** | Session correlation cache (10-minute TTL) |
| **Gateway List** | `01-CLIENT_TLS_ERROR_SNI` - Auto-populated hostnames |
| **Gateway List** | `01-BYPASS-INSPECTION-DOMAINS` - Manual domain overrides |
| **Gateway HTTP Policy** | "Do Not Inspect - TLS Error Hosts" - Bypass with category and app filtering |
| **Logpush Jobs** | Two jobs: `zero_trust_network_sessions` and `gateway_network` |

## Gateway Policy Logic

The HTTP "Do Not Inspect" policy uses four OR groups:

| # | Condition | Purpose |
|---|-----------|---------|
| 1 | Domain in `01-BYPASS-INSPECTION-DOMAINS` | Unconditional bypass for curated domains |
| 2 | Security Categories not in {dangerous categories} AND Host in `01-CLIENT_TLS_ERROR_SNI` | Bypass TLS error hosts unless they are in dangerous security categories (Anonymizer, Brand Embedding, C2/Botnet, Compromised, Cryptomining, DGA, DNS Tunneling, Malware, Phishing, PUP, Private IP, Scam, Spam, Spyware) |
| 3 | Content Categories not in {risky categories} AND Host in `01-CLIENT_TLS_ERROR_SNI` | Bypass TLS error hosts unless they are in risky content categories (Security Risks, New Domains, Newly Seen Domains, Parked & For Sale Domains) |
| 4 | Host in `01-CLIENT_TLS_ERROR_SNI` AND Application Status is not unapproved | Bypass TLS error hosts unless the application is unapproved |

## Security

The Logpush endpoint is protected by a shared secret header (`X-Logpush-Secret`). Requests without the correct header receive a `401 Unauthorized` response.

## Data Flow

```
Zero Trust Network Sessions          Gateway Network Logs
(CLIENT_TLS_ERROR + SessionID)       (SessionID + SNI)
            │                                 │
            └──────────┬──────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Worker (KV)    │
              │  Correlates     │
              │  SessionID→SNI  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Gateway Lists  │
              │  TLS Error SNI  │──── auto-populated
              │  Bypass Domains │──── manual
              └────────┬────────┘
                       │
                       ▼
              ┌────────────────┐
              │ Do Not Inspect │
              │ (4 OR groups)  │
              └────────────────┘
```

## Troubleshooting

### Logpush validation fails (404/401)
- Ensure `npm run build` was run before `terraform apply`
- Verify the worker is deployed: `curl https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/`
- Check that `logpush_secret` matches in both tfvars and destination URL

### Hostnames not being added
- Verify Logpush jobs are enabled and running in the Cloudflare dashboard
- Check worker logs in Workers & Pages → tf-cf-dni-list → Logs
- Ensure the hostname passes validation (RFC-compliant, max 253 chars)

### Policy not matching traffic
- Confirm the lists contain entries (Zero Trust → Gateway → Lists)
- For TLS error hosts: check if the hostname falls into a blocked security or content category
- Verify the application isn't marked as "unapproved"
- Check policy precedence (lower number = higher priority)

## Teardown

```bash
terraform destroy
```

## Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Worker source code |
| `resources.tf` | All Cloudflare resources |
| `variables.tf` | Input variable definitions |
| `outputs.tf` | Output values |
| `versions.tf` | Provider requirements |
