# ShadowTrace Intelligence Platform

A modular, evidence-first OSINT platform. This is an additive next-generation implementation; the existing Cloudflare Worker application, frontend, and database migrations remain available.

## Development

```bash
cd platform
cp .env.example .env
docker compose up --build
```

- Analyst workspace: http://localhost:3000
- API: http://localhost:8000
- OpenAPI: http://localhost:8000/docs
- Health: http://localhost:8000/healthz

## Implemented foundation

- Next.js / React responsive analyst dashboard shell
- FastAPI application with versioned REST API
- Typed collector contract, plugin registry, and YAML collector manifests
- Passive collectors:
  - **domain.passive** — DNS A/AAAA/MX/NS/TXT/CNAME + Certificate Transparency (crt.sh)
  - **ip.passive** — GeoIP / ASN / ISP via ipwho.is (public addresses only)
  - **email.passive** — MX lookup, domain correlation, public Gravatar check
- Bounded concurrency, timeouts, safe target validation, and evidence provenance
- Docker Compose profile for web app, API, PostgreSQL, and Redis
- CI workflow for backend tests and frontend typecheck/build
- Upstream catalog for the requested API lists and OSINT tools (reference only)

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/healthz` | Health check |
| GET | `/api/v1/plugins` | List registered collectors |
| POST | `/api/v1/collect` | Generic collect (`collector` + `target`) |
| POST | `/api/v1/collect/domain` | Domain intelligence |
| POST | `/api/v1/collect/ip` | IP intelligence |
| POST | `/api/v1/collect/email` | Email intelligence |

Every observation includes source, collection time, and confidence. A public profile or reference is a lead, not proof of identity.

## Design principles

- **Public sources only** — no private accounts, no authenticated scraping, no CAPTCHA bypass.
- **Evidence first** — every fact carries provenance and confidence.
- **Plugin architecture** — new collectors implement the `Collector` protocol and register themselves.
- **No vendored heavy tools yet** — SpiderFoot, Amass, Sherlock, Maigret, PhoneInfoga, Subfinder, etc. are listed as *planned adapters*. They are not cloned or executed inside this codebase until a pinned release, license review, and adapter are added.
- **No breached / dark-web data** — those sources require separate legal basis and provider agreements.

## Realistic roadmap

1. **Persistence** — cases, entities, evidence, and audit events in PostgreSQL.
2. **Task queue** — Redis/Celery for retries, schedules, and webhooks.
3. **Provider layer** — encrypted API-key storage, health checks, caching, fallback routing.
4. **More collectors** — username (public profiles), phone metadata (public only), crypto address format + public explorers, basic image/document metadata.
5. **Entity resolution + graph** — Neo4j or equivalent for relationships and path finding.
6. **AI-assisted summaries** — optional LLM layer with strict source citations (no invented facts).
7. **Reporting** — Markdown / HTML / PDF / JSON / CSV with evidence tables.
8. **Optional CLI adapters** — thin wrappers around pinned releases of Subfinder, Amass, Sherlock, etc., run in isolated containers with rate limits and allow-lists.

## Responsible use

Use only for lawful security research and investigations with a valid basis. Respect provider terms and rate limits. Do not use this platform for stalking, harassment, doxxing, discrimination, or consequential decisions about private individuals without due process.
