# ShadowTrace — Cloudflare-only setup

This project runs **only on Cloudflare Workers + D1**. There is no Render deployment.

## Live URL

https://shadowtrace-osint.yalangisexter.workers.dev/

## What already works without a secret

- Public frontend
- Guest OSINT searches (username, domain, IP, email, phone, crypto, metadata)
- `/api/v1/plugins`
- D1 database connectivity

## Required: production JWT secret

Auth (register / login / saved investigations) needs a real secret.

### 1. Login to Cloudflare (once)

```bash
npx wrangler login
```

### 2. Set the secret

```bash
cd /path/to/ShadowTrace-OSINT
openssl rand -base64 48
npx wrangler secret put SECRET_KEY
```

Paste the random value when prompted.

### 3. Confirm

```bash
curl https://shadowtrace-osint.yalangisexter.workers.dev/healthz
```

You want:

```json
{
  "status": "ok",
  "config": {
    "secret_key_set": true,
    "database_configured": true
  }
}
```

## Deploy code changes

```bash
npm ci
npm test
npx wrangler deploy
```

Or push to `main` after adding GitHub secret `CLOUDFLARE_API_TOKEN` (Workers edit permission).

## Do not use

- Render
- Hardcoded secrets in `wrangler.toml`
- The in-code fallback secret for production auth
