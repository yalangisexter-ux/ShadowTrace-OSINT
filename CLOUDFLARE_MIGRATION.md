# Cloudflare Deployment and Evidence-Quality Status

This document supersedes the original migration notes. ShadowTrace OSINT is deployed as the `shadowtrace-osint` Cloudflare Worker with static assets and the existing D1 binding defined in `wrangler.toml`.

## Existing production resources

- Worker: `shadowtrace-osint`
- D1 database: `shadowtrace-db`
- D1 database ID: configured in `wrangler.toml`
- Static frontend: `./frontend`
- Runtime: Hono on Cloudflare Workers

The evidence-quality release is code-only. It does not create a new database, delete D1 rows, rewrite password hashes, or reset investigations.

## Corrections in this release

- Removed phone carrier, telecom-circle, messaging-account, Truecaller, and UPI claims that were generated from number prefixes or URL templates.
- Removed synthetic image EXIF/GPS and document-author metadata.
- Removed generic IP location and hosting cards when GeoIP/ASN responses are unavailable.
- Distinguished Shodan InternetDB indexed observations from live scans and from failed lookups.
- Replaced placeholder domain WHOIS/Certificate Transparency cards with actual DNS, crt.sh, and RDAP responses.
- Removed hardcoded wallet owner labels and unsupported sanctions/AML clearance.
- Tightened username collectors to require exact API usernames or username-specific page metadata.
- Removed generated GitHub avatar URLs and synthetic profile identities.
- Replaced fabricated first-seen/last-seen and authentication timeline events with source collection timestamps only.
- Made risk assessment unassessed unless explicit source-backed vulnerability or breach evidence exists.
- Updated reports and the knowledge graph to separate candidate profiles from observed technical facts.
- Replaced personal-data tests with deterministic synthetic fixtures.

## Evidence status contract

| Status | Meaning |
|---|---|
| `observed` | A provider/parser returned the stated technical fact |
| `candidate` | A source returned a potentially matching public profile or record |
| `not_found` | A successful lookup returned no match; not proof of global absence |
| `inconclusive` | Provider unavailable, restricted, rate-limited, or evidence insufficient |

Candidate records are not identity verification. Technical observations are not counted as profile matches.

## Current limitations

- The summary engine is deterministic/rule-based. No generative AI provider is configured.
- Phone collection performs conservative number normalization only.
- Metadata collection hashes supplied bytes/text and extracts embedded text indicators; full EXIF/PDF binary parsing is not implemented.
- Bitcoin and Ethereum have public-ledger lookups; other supported address patterns are not live balance lookups.
- Shodan InternetDB is an indexed data source, not a live scan.
- Threat score is `UNKNOWN / UNASSESSED` without explicit source-backed vulnerability or breach indicators.
- The Worker currently has no `SECRET_KEY` binding. The legacy fallback is retained temporarily for login compatibility; configure a unique Cloudflare Worker secret before public production exposure. Rotating it invalidates active access tokens but does not alter D1 password hashes or investigation data.

## Validation

The native Node test suite covers:
- Source-backed domain DNS/CT/RDAP responses
- IP provider evidence and private-address egress suppression
- Email source matching and infrastructure-vs-identity semantics
- Phone parsing without inferred subscriber data
- Metadata extraction without synthetic EXIF/GPS
- AI summary and report generation without fabricated history or identity claims

Run `npm test`, `npm run typecheck`, and `npx wrangler deploy --dry-run` before deployment.
