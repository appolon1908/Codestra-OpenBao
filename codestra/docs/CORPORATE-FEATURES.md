# Codestra OpenBao Corporate Features

## Mission

OpenBao is the centralized secrets, lease, PKI and cryptographic-policy authority for Codestra-managed systems. It removes long-lived credentials from Git, application images and unmanaged `.env` files.

## Corporate identity

Human administrators authenticate through Keycloak OIDC with explicit security/admin roles. Workloads use approved machine identity such as JWT/OIDC or AppRole-style bootstrap where platform identity is not available. Root credentials are break-glass only and are not used for routine operations.

## Business/environment isolation

Maintain separate policy boundaries for every Codestra-managed business and environment. A workload receives only the paths and capabilities required for its own service and environment. Cross-business secret reads are denied by default.

## Enterprise features

- versioned KV secrets;
- short-lived/dynamic PostgreSQL credentials where supported;
- credential leases, renewal and revocation;
- automatic rotation procedures;
- internal PKI/certificate issuance;
- transit encryption/signing where appropriate;
- per-business/per-environment policies;
- audit-device configuration with protected forwarding to Loki;
- secret-access alerts through the observability stack;
- backup/recovery and seal/unseal runbooks;
- break-glass procedure;
- migration away from static Git/Compose secrets.

## Secret domains

Use controlled paths for database/cache credentials, OAuth clients, provider APIs, SMTP, webhook HMAC keys, TLS/PKI, application secrets and deployment credentials.

## Beyvra trading compartment

Broker, exchange and custody signing credentials are a dedicated high-sensitivity compartment. Only narrowly authorized backend/execution workload identities may read them. Grafana, Superset, Prometheus, Loki, Tempo, n8n and unrelated business workloads are denied by default. No trading secret is ever delivered to a browser.

## Audit/privacy

Audit events record who/what requested secret capabilities and the result, but never expose secret values in Loki. High-value audit evidence requires protected/tamper-resistant retention beyond ordinary troubleshooting logs where appropriate.

## Release rule

`bao.codestra.media` is private or strongly authenticated administrative access only. Source merge never initializes/unseals a live cluster, creates production root tokens or installs production secrets.
