# ShadowTrace Intelligence Platform

A modular, evidence-first OSINT platform. This is an additive next-generation implementation; the existing Worker application, frontend, and database migrations remain untouched.

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

- Next.js 15 / React 19 responsive analyst dashboard
- FastAPI application with versioned REST API
- Typed collector contract, plugin registry, and YAML collector manifest
- Passive domain collection: DNS A/AAAA/MX/NS/TXT/CNAME and Certificate Transparency references
- Bounded concurrency, timeouts, safe public-domain validation, and evidence provenance
- Docker Compose profile for the web app, API, PostgreSQL, and Redis
- CI workflow for backend lint/tests and frontend typecheck/build
- Upstream catalog for the requested API lists and OSINT tools

PostgreSQL and Redis are provisioned but not yet connected to application persistence or background workers. The current dashboard is a functional shell with a live passive-domain collection form; other panels are clearly marked as planned rather than simulated.

The first collector intentionally performs passive collection only. It does not scan ports, brute-force accounts, access private systems, scrape authenticated services, retrieve stolen/breached datasets, or access dark-web content. Third-party tools are catalogued as optional integrations; they are not yet cloned or executed. Before enabling an adapter, pin an upstream release, review its license and dependencies, and enforce its terms, scope, and rate limits.

## API

- `GET /healthz`
- `GET /api/v1/plugins`
- `POST /api/v1/collect/domain`

Every returned observation includes its source, collection time, and confidence. A profile or public reference is a lead, not proof of identity.

## Roadmap

1. Persist cases, entities, evidence, and audit events in PostgreSQL.
2. Add Redis/Celery task execution, retries, schedules, and webhooks.
3. Add provider adapters, encrypted API-key storage, health checks, caching, and fallback routing.
4. Add scoped domain/IP/email/username/phone/crypto/image/document/news/company collectors.
5. Add entity resolution, confidence scoring, graph storage, and AI-assisted summaries with source citations.
6. Add graph/timeline/map exploration and PDF/HTML/Markdown/DOCX/JSON/CSV reporting.
7. Add integration tests, backups, migration tooling, and production deployment profiles.
