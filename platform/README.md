# ShadowTrace Intelligence Platform

A modular, evidence-first OSINT platform. This is an additive next-generation implementation; the existing Worker application, frontend, and database migrations remain untouched.

## Development

```bash
cd platform
cp .env.example .env
docker compose up --build
```

API: http://localhost:8000  
OpenAPI: http://localhost:8000/docs  
Health: http://localhost:8000/healthz

## Initial implementation

- FastAPI application with versioned REST API
- Typed collector contract and plugin registry
- YAML collector manifests
- Passive domain collection: DNS records and Certificate Transparency references
- Bounded concurrency, timeouts, safe target validation, and evidence provenance
- PostgreSQL and Redis services for the next persistence/queue increments
- Docker Compose development environment

The first slice intentionally performs passive collection only. It does not scan ports, brute-force accounts, access private systems, scrape authenticated services, or retrieve stolen/breached datasets. Integrations for third-party tools are opt-in adapters and must preserve each tool's license, terms, rate limits, and lawful-use boundaries.

## Roadmap

1. Persist cases, entities, evidence, jobs, and audit events in PostgreSQL.
2. Add Redis/Celery task execution, retries, schedules, and webhooks.
3. Add provider adapters and API-key vaulting/health checks.
4. Add domain/IP/email/username/phone/crypto/image/document/news/company collectors with per-module safety policies.
5. Add entity resolution, confidence scoring, graph storage, and AI-assisted summaries with source citations.
6. Add Next.js analyst workspace, graph/timeline/map visualizations, and report exports.
7. Add integration tests, CI, deployment profiles, backups, and migration tooling.

## API

- `GET /healthz`
- `GET /api/v1/plugins`
- `POST /api/v1/collect/domain`

Every returned observation includes its source, collection time, and confidence. A profile or public reference is a lead, not proof of identity.
