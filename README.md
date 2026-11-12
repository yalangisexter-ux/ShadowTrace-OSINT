# ShadowTrace OSINT

A privacy-conscious OSINT workspace for researching **public usernames** across a curated set of public websites. ShadowTrace records the source URL, timestamp, response status, and confidence label for each check.

> ShadowTrace is an independent implementation and is not affiliated with Fingerprint.to. A responding profile page is only a candidate match—not proof of identity.

## Included in this first build

- Responsive web interface with account registration and sign-in.
- Password hashing with Argon2 and signed, expiring JWT access tokens.
- Concurrent public-profile checks against a fixed provider allowlist (GitHub, GitLab, Reddit, Codeberg, DEV Community).
- Conservative result states: candidate, not found, or inconclusive.
- Per-account investigation history and stored source evidence.
- Request throttling, strict username validation, bounded HTTP timeouts, no redirect following, and no arbitrary URL fetch endpoint.
- SQLite for local development; PostgreSQL for production.
- Render Blueprint and GitHub Actions test workflow.

## Local development

Python 3.11+:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000. The local default database is `shadowtrace.db`.

Run tests:

```bash
pytest -q
```

## Deploy on Render (full ownership checklist)

Service URL (once healthy): https://shadowtrace-osint.onrender.com  
Dashboard: https://dashboard.render.com/web/srv-dbqtf38u01pc73emvm6g

### Required one-time setup

1. **Create a PostgreSQL database** in the same Render workspace (New → PostgreSQL).  
   Prefer the same region as the web service. Copy the **Internal Database URL**.

2. **Set Environment Variables** on the web service:
   - `DATABASE_URL` → the Internal Database URL (must start with `postgresql://` or `postgres://`)
   - `SECRET_KEY` → a long random value (≥ 32 characters). Generate with:
     ```bash
     python -c "import secrets; print(secrets.token_urlsafe(48))"
     ```
   - `APP_ENV` should already be `production`

3. **Trigger a new deploy** (or push any commit). Watch the Logs tab.

4. **Verify**:
   ```bash
   curl https://shadowtrace-osint.onrender.com/healthz
   ```
   Expected healthy response:
   ```json
   {"status":"ok","service":"shadowtrace-osint","version":"0.1.1","config":{"secret_key_set":true,"database_configured":true,...}}
   ```
   If `status` is `"degraded"`, the `config` object tells you exactly which setting is still missing.

The app now boots even when configuration is incomplete and reports the missing pieces via `/healthz` instead of crashing. Never commit production credentials.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/healthz` | Health check |
| POST | `/api/v1/auth/register` | Create account |
| POST | `/api/v1/auth/login` | Sign in |
| GET | `/api/v1/auth/me` | Current account (Bearer token) |
| POST | `/api/v1/search/username` | Run public username checks |
| GET | `/api/v1/search/runs` | List your investigations |
| GET | `/api/v1/search/runs/{run_id}` | Read one investigation |

Registration/login body: `{"email":"analyst@example.com","password":"a-long-password-12"}`

Username search body: `{"username":"octocat"}`

## Responsible-use boundaries

Use ShadowTrace only for legitimate security research and investigations with a lawful basis. Do not use it to stalk, harass, discriminate, expose private individuals, or make consequential decisions about a person. Respect each provider's terms, robots policies, and rate limits.

This build checks only public profile pages. It does **not** access private accounts, bypass authentication, search breached/stolen datasets, enumerate identities by email or phone, infer a person's location, or expose sensitive personal information. Provider response codes can be misleading; restricted, rate-limited, redirected, and failed requests are marked inconclusive.

## Engineering notes / next milestones

This is the first deployable foundation, not a claim of complete Fingerprint.to parity. Before broadening provider coverage, add provider-specific policy tests and stronger false-positive detection. Before scaling beyond a single instance, move throttling to shared storage, add database migrations, add durable background jobs, and add structured audit logging/retention controls. Add report export only after evidence provenance and access controls are reviewed.
