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

## Deploy on Render

1. Create a PostgreSQL database in your Render workspace.
2. Open the [Render Blueprint setup](https://dashboard.render.com/blueprint/new?repo=https%3A%2F%2Fgithub.com%2Fyalangisexter-ux%2FShadowTrace-OSINT).
3. Review the service configuration and apply it.
4. Set `DATABASE_URL` to the database's **internal** connection string.
5. Set `SECRET_KEY` to a cryptographically random value of at least 32 characters.
6. Wait for deployment and verify `https://YOUR-SERVICE.onrender.com/healthz` returns `{"status":"ok",...}`.

The Blueprint does not create a database automatically. This is deliberate: database plan, region, retention, and billing should be selected in the Render workspace. Production startup refuses to run with SQLite or the development secret. Never commit production credentials.

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
