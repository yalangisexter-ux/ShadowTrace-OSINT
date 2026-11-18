# Platform security and release gates

The platform folder is a development foundation, not a public production deployment.

## Required before exposing the API

- Add analyst authentication, session/token rotation, role-based access, and per-workspace authorization.
- Add per-user and per-provider quotas, abuse controls, and audit trails.
- Persist API credentials only in a managed secret store or encrypted vault; never commit keys or log authorization headers.
- Restrict collectors to explicitly authorized public targets and enforce scope checks server-side.
- Add outbound egress controls, DNS rebinding protections, private/reserved IP and hostname denial, request-size limits, and provider allowlists.
- Add data retention, deletion, export, consent/lawful-basis records, and workspace isolation.
- Add signed webhook delivery and replay protection before enabling callbacks.
- Add dependency/license review and pinned versions for each optional upstream tool.

## Collection policy

- Use public, lawfully accessible sources and documented provider APIs.
- Do not bypass authentication, paywalls, CAPTCHAs, rate limits, or access controls.
- Do not ingest stolen credentials, leaked private datasets, or unlawfully obtained dark-web material.
- Do not use the platform to stalk, harass, dox, discriminate, or make consequential decisions about private individuals.
- Treat social-profile and username matches as candidate leads, not identity proof.
- Record source URL, collection timestamp, method, confidence, and transformation history for every observation.

## Current exposure

The initial development API has no analyst authentication and should only be run on a trusted local development network. Do not deploy it to a public host until the release gates above are implemented and tested.
