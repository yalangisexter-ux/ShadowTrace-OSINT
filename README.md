# ShadowTrace OSINT — Cloudflare Worker

ShadowTrace is a Cloudflare-hosted, evidence-first OSINT workspace. It collects public-source technical observations and candidate profile leads, preserving source URLs, collection timestamps, provider response status, and confidence.

> A candidate profile is not proof of identity. Separate indicators are not assumed to belong to the same person.

## Production architecture

- **Runtime:** Cloudflare Workers + Hono
- **Static UI:** Worker Static Assets from `./frontend`
- **Database:** Cloudflare D1 (`shadowtrace-db`)
- **Authentication:** PBKDF2 password hashing and HMAC-signed access tokens
- **Deployment config:** `wrangler.toml`

The existing Worker and D1 binding are retained. The evidence-quality corrections in this release do not recreate, reset, or migrate the database.

## Current collector coverage

| Collector | What it actually does | Important limitation |
|---|---|---|
| Domain | Live DNS A/AAAA/MX/NS/TXT/DMARC, crt.sh Certificate Transparency, RDAP | A missing record is not proof of compromise |
| IP | ipwho.is GeoIP/network registration, Google PTR, Shodan InternetDB | GeoIP is approximate network location; Shodan is indexed data, not a live scan |
| Email | Domain MX, public Gravatar, exact-match GitHub commit-author email, public OpenPGP user IDs | MX does not prove mailbox existence; candidate associations do not prove ownership |
| Username | Public profile checks and exact-username API responses | Generic HTTP 200 pages and generic markers are not counted as matches |
| Phone | E.164-like normalization and conservative country-code formatting | No carrier, subscriber name, WhatsApp/Telegram account, Truecaller identity, or UPI handle is inferred |
| Cryptocurrency | Address-format recognition; live Bitcoin and Ethereum public-ledger reads | Format recognition is not checksum/ownership verification; no wallet clustering or AML clearance |
| Metadata | Hash of supplied text/data-URL bytes and embedded text indicators | No arbitrary remote URL fetch; no synthetic EXIF, GPS, camera, or document-author data |

## Evidence semantics

- `observed`: a provider or deterministic parser returned the stated technical fact.
- `candidate`: a public provider returned a profile/record that may be associated with the query.
- `not_found`: a successful provider response returned no matching record. This does not prove global absence.
- `inconclusive`: provider timeout, rate limit, access restriction, malformed response, or insufficient evidence.

A `verified` provider response confirms only that the provider returned the relevant record. It does not verify a real-world person's identity or ownership of an account.

Historical first-seen and last-seen dates are displayed only when an upstream source actually supplies them. The current timeline records collection timestamps, not invented historical events.

## Analysis and risk scoring

The current summary engine is deterministic and rule-based. It is **not a connected generative AI model**. It summarizes evidence counts, source details, and collection timestamps without claiming identity attribution.

Threat scoring is marked `UNKNOWN / UNASSESSED` unless an explicit source-backed vulnerability or breach indicator is present. No score is inferred from profile counts, missing SPF/DMARC, phone formatting, or failed lookups. An unassessed result is not a clean bill of health.

## Local development

Requirements: Node.js 22+.

```bash
npm ci
npm test
npm run typecheck
npm run dev
```

Open http://localhost:8787. The Worker uses the bindings in `wrangler.toml`; for local D1 development, apply the existing migrations with Wrangler.

## Production deployment

```bash
npx wrangler login
npx wrangler deploy
```

The deployed Worker is named `shadowtrace-osint` and uses the existing D1 database binding in `wrangler.toml`. Do not create a replacement D1 database or run destructive SQL during a code-only release.

Before exposing the service publicly, configure a unique `SECRET_KEY` using `npx wrangler secret put SECRET_KEY`. Rotating this key invalidates existing access tokens; users must sign in again. Password hashes and D1 investigation records are not changed by token-secret rotation.

## API

- `GET /healthz`
- `GET /api/v1/plugins`
- `POST /api/v1/search/username`
- `POST /api/v1/collect/domain` (if enabled in the current Worker routes)
- `GET /api/v1/search/runs`
- `GET /api/v1/search/runs/:run_id`
- Report endpoints for Markdown, CSV, and HTML

See the live OpenAPI/route documentation exposed by the deployed Worker.

## Responsible use

Use only public sources and provider-supported access. Respect terms, rate limits, and applicable law. Do not bypass authentication, paywalls, CAPTCHAs, or access controls; do not use the service for stalking, harassment, doxxing, discrimination, or consequential decisions about private individuals. Do not treat public-profile matches as identity proof.
