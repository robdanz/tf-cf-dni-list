# tf-cf-dni-list

Automated TLS inspection bypass management for Cloudflare Zero Trust. This solution identifies hostnames causing `CLIENT_TLS_ERROR` failures and automatically adds them to a Gateway "Do Not Inspect" policy, reducing manual triage of TLS inspection issues.

## Overview

When TLS inspection is enabled in Cloudflare Gateway, certain hosts fail inspection due to certificate pinning, mutual TLS, or other incompatibilities. These failures generate `CLIENT_TLS_ERROR` events in Zero Trust network session logs, which now include the SNI (hostname) directly.

This solution:
1. Receives `CLIENT_TLS_ERROR` records from a single Logpush job (`zero_trust_network_sessions`)
2. Reads the SNI field directly from each record — no secondary log stream or session correlation needed
3. Adds hostnames to a Gateway list used by a "Do Not Inspect" HTTP policy
4. Filters bypass decisions using security categories, content categories, and application approval status

## Five-List Architecture

### 1. `01-BYPASS_CLIENT_TLS_ERROR_SNI` (Auto-populated)
Hostnames are automatically added when a `CLIENT_TLS_ERROR` is detected. This list grows organically as users encounter TLS inspection failures. The Do Not Inspect policy applies additional filtering to these hostnames — bypassing only those that are not in dangerous security/content categories, are not unapproved applications, and are not in either block list.

### 2. `01-BYPASS-INSPECTION-DOMAINS` (Manually managed)
A curated list of domains for unconditional inspection bypass. Entries match the domain **and all subdomains** (e.g., `example.com` also bypasses `api.example.com`).

**Recommended workflow:**
1. Periodically review the auto-populated `01-BYPASS_CLIENT_TLS_ERROR_SNI` list
2. Identify patterns (e.g., multiple hostnames like `api1.example.com`, `api2.example.com`)
3. Remove individual hostnames from the auto-populated list
4. Add a single domain entry (e.g., `example.com`) to `01-BYPASS-INSPECTION-DOMAINS`

This consolidation keeps the lists manageable and reduces policy evaluation overhead.

### 3. `01-BYPASS-INSPECTION-HOSTS` (Manually managed)
A curated list of exact hostnames for unconditional inspection bypass. Unlike the domains list, entries match **only the specified hostname** — no subdomain matching. Use this when you need precise control over a single hostname without bypassing the entire domain.

### 4. `01-BLOCK-DOMAIN-LIST` (Manually managed)
A curated list of domains to block at every layer. Entries match the domain and all subdomains. Domains in this list are:
- Blocked at the DNS layer (query is refused)
- Blocked at the Network layer (SNI-based connection blocking)
- Blocked at the HTTP layer
- Excluded from the Do Not Inspect bypass (forced inspection so HTTP-level rules can evaluate)

### 5. `01-BLOCK-HOST-LIST` (Manually managed)
A curated list of exact hostnames to block at every layer. Entries match **only the specified hostname**. Use this for targeted blocking of a specific hostname without blocking the entire domain. Hosts in this list are:
- Blocked at the DNS layer (exact FQDN match)
- Blocked at the Network layer (exact SNI match)
- Blocked at the HTTP layer (exact host header match)
- Excluded from the Do Not Inspect bypass

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
account_id             = "your-cloudflare-account-id"
cloudflare_api_token   = "your-scoped-api-token"
workers_subdomain      = "your-workers-subdomain"   # e.g., "myaccount" for myaccount.workers.dev
logpush_secret         = "your-random-secret"        # Generate with: openssl rand -hex 32
```

Create a [scoped API token](https://dash.cloudflare.com/profile/api-tokens) with the following **Account-level** permissions:

| Permission | Access |
|------------|--------|
| Logs | Edit |
| Zero Trust | Edit |
| Zero Trust PII | Read |
| Workers Scripts | Edit |

### 3. Deploy

```bash
terraform init
terraform apply
```

## What Gets Created

| Resource | Description |
|----------|-------------|
| **Worker** | `tf-cf-dni-list` - Logpush HTTP destination endpoint |
| **Gateway List** | `01-BYPASS_CLIENT_TLS_ERROR_SNI` - Auto-populated hostnames |
| **Gateway List** | `01-BYPASS-INSPECTION-DOMAINS` - Manual domain overrides (domain + subdomain match) |
| **Gateway List** | `01-BYPASS-INSPECTION-HOSTS` - Manual hostname overrides (exact match) |
| **Gateway List** | `01-BLOCK-DOMAIN-LIST` - Manual domain blocklist (domain + subdomain match) |
| **Gateway List** | `01-BLOCK-HOST-LIST` - Manual host blocklist (exact match) |
| **Gateway DNS Policy** | "Block DNS - Domain Blocklist" - Block DNS queries for blocklist domains and hosts |
| **Gateway Network Policy** | "Block Network - SNI Domain Blocklist" - Block SNI connections for blocklist domains and hosts |
| **Gateway HTTP Policy** | "Do Not Inspect - TLS Error Hosts" - Bypass with category, app, and blocklist filtering |
| **Gateway HTTP Policy** | "Block HTTP - Domain Blocklist" - Block HTTP connections for blocklist domains and hosts |
| **Logpush Job** | `zero_trust_network_sessions` - Streams `CLIENT_TLS_ERROR` records (with SNI) to the worker |

## Gateway Policy Logic

Policies are evaluated in order: DNS → Network → HTTP. All four policies are deployed at the highest available priority slots.

### DNS Block Policy
| Condition | Action |
|-----------|--------|
| Domain in `01-BLOCK-DOMAIN-LIST` | Block |

### Network Block Policy
| Condition | Action |
|-----------|--------|
| SNI Domain in `01-BLOCK-DOMAIN-LIST` | Block |

### HTTP Do Not Inspect Policy (5 OR groups)

| # | Condition | Purpose |
|---|-----------|---------|
| 1 | Domain in `01-BYPASS-INSPECTION-DOMAINS` | Unconditional bypass for curated domains (matches domain + subdomains) |
| 2 | Host in `01-BYPASS-INSPECTION-HOSTS` | Unconditional bypass for specific hostnames (exact match only) |
| 3 | Host in `01-BYPASS_CLIENT_TLS_ERROR_SNI` AND Security Categories not in {dangerous categories} | Bypass TLS error hosts unless they are in dangerous security categories (Anonymizer, Brand Embedding, C2/Botnet, Compromised, Cryptomining, DGA, DNS Tunneling, Malware, Phishing, PUP, Private IP, Scam, Spam, Spyware) |
| 4 | Host in `01-BYPASS_CLIENT_TLS_ERROR_SNI` AND Content Categories not in {risky categories} | Bypass TLS error hosts unless they are in risky content categories (Security Risks, New Domains, Newly Seen Domains, Parked & For Sale Domains) |
| 5 | Host in `01-BYPASS_CLIENT_TLS_ERROR_SNI` AND Application Status is not unapproved AND Host not in `01-BLOCK-DOMAIN-LIST` AND Host not in `01-BLOCK-HOST-LIST` | Bypass TLS error hosts unless the application is unapproved or the host is in either block list |

### HTTP Block Policy
| Condition | Action |
|-----------|--------|
| Domain in `01-BLOCK-DOMAIN-LIST` OR Host in `01-BLOCK-HOST-LIST` | Block |

This policy has lower priority than Do Not Inspect, ensuring DNI rules are evaluated first.

## Security

The Logpush endpoint is protected by a shared secret header (`X-Logpush-Secret`). Requests without the correct header receive a `401 Unauthorized` response.

## Data Flow

```
Zero Trust Network Sessions
(CLIENT_TLS_ERROR + SessionID + SNI)
              │
              ▼
     ┌─────────────────┐
     │  Worker         │
     │  Reads SNI      │
     │  (stateless)    │
     └────────┬────────┘
              │
              ▼
     ┌─────────────────┐
     │  Gateway Lists  │
     │  TLS Error SNI  │──── auto-populated
     │  Bypass Domains │──── manual
     │  Block Domains  │──── manual
     └────────┬────────┘
              │
     ┌────────┴────────┐
     ▼                 ▼
┌────────────────┐ ┌──────────────┐
│ Do Not Inspect │ │ Block (DNS,  │
│ (4 OR groups)  │ │ Network)     │
└────────────────┘ └──────────────┘
```

## Troubleshooting

### Logpush validation fails (404/401)
- Ensure `npm run build` was run before `terraform apply`
- Verify the worker is deployed: `curl https://tf-cf-dni-list.YOUR_SUBDOMAIN.workers.dev/`
- Check that `logpush_secret` matches in both tfvars and destination URL

### Hostnames not being added
- Verify the Logpush job is enabled and running in the Cloudflare dashboard
- Check worker logs in Workers & Pages → tf-cf-dni-list → Logs
- Ensure the hostname passes validation (RFC-compliant, max 253 chars)
- Confirm `CLIENT_TLS_ERROR` records in the dataset include a non-empty `SNI` field

### Policy not matching traffic
- Confirm the lists contain entries (Zero Trust → Gateway → Lists)
- For TLS error hosts: check if the hostname falls into a blocked security or content category
- Verify the application isn't marked as "unapproved"
- Check policy precedence (lower number = higher priority)

## Upgrading from v1 (KV + dual Logpush)

The original version of this solution required two Logpush jobs and a KV namespace to correlate log streams by `SessionID`:

- `zero_trust_network_sessions` — provided `SessionID` + `ConnectionCloseReason`, but not the SNI
- `gateway_network` — provided `SessionID` + `SNI`
- KV stored pending sessions so whichever log arrived first could wait for the other

Cloudflare updated the `zero_trust_network_sessions` dataset to include the `SNI` field directly on `CLIENT_TLS_ERROR` records. The worker is now stateless — it reads SNI directly from each record and appends it to the list with no session correlation needed.

**What `terraform apply` will do when upgrading:**

| Change | Effect |
|--------|--------|
| Destroy `cloudflare_workers_kv_namespace` (session cache) | Safe — was a short-lived correlation cache only |
| Destroy `cloudflare_logpush_job` (`tf-cf-dni-list-gateway`) | Removes the `gateway_network` job |
| Update `cloudflare_logpush_job` (`tf-cf-dni-list-zero-trust`) | Adds `SNI` to the streamed fields |
| Update `cloudflare_worker_version` | Deploys the simplified stateless worker |
| Gateway lists and policies | **Untouched** — existing entries and rules are preserved |

**To upgrade:**

```bash
git pull origin main
npm install
npm run build
terraform plan   # review: KV + gateway job destroyed, worker + logpush updated
terraform apply
```

The `Workers KV Storage: Edit` scope is no longer required on the API token, but having it does no harm — you can remove it from the token at your discretion.

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
