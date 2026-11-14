# ShadowTrace OSINT (Cloudflare Edition)

A privacy-conscious OSINT workspace for researching **public usernames** across a curated set of public websites. ShadowTrace records the source URL, timestamp, response status, and confidence label for each check.

> ShadowTrace is an independent implementation and is not affiliated with Fingerprint.to. A responding profile page is only a candidate match—not proof of identity.

## Architecture: Cloudflare Workers + D1 + Pages

This application has been migrated from a monolithic server to a globally distributed, edge-native architecture on Cloudflare:

- **Frontend:** Responsive SPA static assets served via Cloudflare Pages / Workers Static Assets.
- **API Runtime:** Edge-native Cloudflare Worker powered by [Hono](https://hono.dev/) with zero cold-starts.
- **Database:** [Cloudflare D1](https://developers.cloudflare.com/d1/) serverless SQL database with automated schema migration.
- **Authentication:** Web Crypto API standard PBKDF2-SHA256 password hashing and expiring HMAC-SHA256 JWT access tokens.
- **Concurrent Subrequests:** Parallel OSINT lookups across 20+ curated public platforms executed concurrently at Cloudflare's edge.

---

## Quickstart & Local Development

### Prerequisites
- Node.js 20+
- Cloudflare Wrangler CLI (included in devDependencies)

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Test Suite
```bash
npm test
```

### 3. Local Cloudflare Development
```bash
npm run dev
```
Open [http://localhost:8787](http://localhost:8787) to interact with the web workspace.

---

## Production Deployment to Cloudflare

### Step 1: Login to Cloudflare Wrangler
```bash
npx wrangler login
```

### Step 2: Create your Cloudflare D1 Database
```bash
npx wrangler d1 create shadowtrace-db
```
Wrangler will output the `database_id`. Update your `wrangler.toml`:
```toml
[[d1_databases]]
binding = "DB"
database_name = "shadowtrace-db"
database_id = "<YOUR_DATABASE_ID_FROM_STEP_2>"
```

### Step 3: Apply the SQL Schema Migrations to D1
```bash
npx wrangler d1 migrations apply shadowtrace-db --remote
```
*(Or execute `npx wrangler d1 execute shadowtrace-db --remote --file=./schema.sql`)*

### Step 4: Set the JWT Production Secret Key
Generate a strong secret (32+ characters) and store it securely in Cloudflare:
```bash
npx wrangler secret put SECRET_KEY
```

### Step 5: Deploy
```bash
npm run deploy
```

---

## API Specification

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/healthz` | Health check & system diagnostics |
| POST | `/api/v1/auth/register` | Create analyst account |
| POST | `/api/v1/auth/login` | Sign in & receive Bearer JWT |
| GET | `/api/v1/auth/me` | Current account details |
| POST | `/api/v1/security/password-exposure` | Authenticated k-anonymity password exposure check (sends only a 5-character SHA-1 prefix) |
| POST | `/api/v1/search/username` | Run concurrent public username checks |
| GET | `/api/v1/search/runs` | List past investigations |
| GET | `/api/v1/search/runs/:run_id` | Read detailed investigation evidence |
| GET | `/api/v1/search/runs/:run_id/report.md` | Download Markdown investigation report |

---

## Responsible-Use Boundaries

Use ShadowTrace only for legitimate security research and investigations with a lawful basis. Do not use it to stalk, harass, discriminate, expose private individuals, or make consequential decisions about a person. Respect each provider's terms, robots policies, and rate limits.

This build checks public profile pages and provides an optional authenticated Pwned Passwords range check. The password exposure check sends only the first five characters of a SHA-1 digest to the provider; the full password is not sent or stored. It does **not** access private accounts, bypass authentication, download breached/stolen datasets, enumerate identities by email or phone, infer an individual's location, or expose sensitive personal information.
