# tf-cf-dni-list

Cloudflare Worker that automatically adds hostnames causing TLS inspection failures to a Gateway "Do Not Inspect" list.

## Prerequisites

- Terraform v1.0+
- Node.js v18+
- Cloudflare account with Zero Trust and Logpush enabled

## Deployment

### 1. Create API Tokens

You need **two** API tokens:

**Terraform Token** (for provisioning infrastructure):
- Account → Workers Scripts → Edit
- Account → Workers KV Storage → Edit
- Account → Zero Trust → Edit
- Account → Logs → Edit

**Worker Token** (for the worker to manage Gateway lists):
- Account → Zero Trust → Edit

Create tokens at: My Profile → API Tokens → Create Token

### 2. Clone and Build

```bash
git clone git@github.com:robdanz/tf-cf-dni-list.git
cd tf-cf-dni-list
npm install
npm run build
```

### 3. Configure Terraform

```bash
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
```

Variables:
- `account_id` - Your Cloudflare account ID
- `cloudflare_api_token` - Terraform token (for provisioning)
- `worker_api_token` - Worker token (for Gateway list management)
- `workers_subdomain` - Your workers.dev subdomain

### 4. Deploy

```bash
terraform init
terraform apply
```

## Teardown

```bash
terraform destroy
```
