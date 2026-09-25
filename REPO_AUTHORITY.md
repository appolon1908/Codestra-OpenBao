# Repository Authority

Canonical service hostname: `bao.codestra.media`
Canonical DNS A target: `37.27.128.39`
DNS TTL: `600`

This repository is the principal source authority for the Codestra OpenBao deployment/configuration. Do not introduce alternate public hostnames or legacy domain names in configuration, documentation, examples, health checks, or deployment manifests.

Exposure policy: PROTECTED BROWSER/API ACCESS ONLY. `bao.codestra.media` may be routed through Caddy only with strong authentication, strict network policy, TLS, security headers, rate limits, audit logging, and least-privilege policies. Native storage/backend/admin ports must remain private. Never expose unsealed bootstrap/recovery material, root tokens, private keys, or provider credentials.

Upstream/downstream: approved platform services authenticate to OpenBao using least-privilege machine identities -> OpenBao returns scoped secrets/leases -> audit logs and operational health flow to the observability stack. OpenBao must never be used as a general data store or bypass Middleware authorization.

Persistent branch model: `main`, `development`, `test`, `staging`, `production`. Temporary branches: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, `release/*`, `rollback/*`.

Promotion: feature/fix/upgrade/security -> development -> test -> staging -> production -> main. Never upgrade directly on staging, production, or main.
