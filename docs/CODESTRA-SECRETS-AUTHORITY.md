# Codestra OpenBao secrets authority

## Purpose

`Codestra-OpenBao` is the principal source repository for Codestra secrets-management policy, OpenBao configuration, audit policy, authentication policy, and reviewed deployment definitions.

Git is **not** a secret store. This repository must never contain live API keys, client secrets, private keys, unseal material, root tokens, broker credentials, database passwords, webhook secrets, or production trading credentials.

## Environment boundary

The branch promotion model is:

```text
main -> staging -> production
```

Secret namespaces must also remain environment-separated. A staging identity must never be able to read a production secret path.

Recommended logical KV namespaces:

```text
codestra/staging/<service>/...
codestra/production/<service>/...
```

Examples of service namespaces:

- `middleware`
- `beyvra`
- `moneybee`
- `breero`
- `larim-a`
- `transportation`
- `social-codestra`
- `klyrow`
- `telnexa`
- `vicidial`
- `odoo`
- `grafana`
- `superset`

## Beyvra trading boundary

Beyvra is a trading platform and its production provider secrets require a stricter boundary than ordinary application credentials.

Recommended logical paths:

```text
codestra/staging/beyvra/market-data/*
codestra/staging/beyvra/providers/*

codestra/production/beyvra/market-data/*
codestra/production/beyvra/broker/*
codestra/production/beyvra/exchange/*
codestra/production/beyvra/custody/*
codestra/production/beyvra/webhooks/*
```

Production trading credentials must remain inaccessible to browsers and general automation. At minimum, these identities must not receive production Beyvra trading-secret read grants:

- `beyvra-frontend`
- `n8n-automation`
- Grafana/Superset user sessions
- social application identities
- unrelated product backends

A dedicated backend/execution workload should receive only the exact paths it needs. Live-trading secret access must remain disabled until separately reviewed and approved.

## Workload authentication

Prefer short-lived workload identity over static shared tokens. The target integration is Keycloak-issued workload identity with exact audience/client/scope validation where supported, or another reviewed machine-auth mechanism with equivalent least privilege.

Every workload policy must bind:

- one environment;
- one service identity;
- exact secret path prefixes;
- exact allowed operations;
- short TTL/renewal rules;
- audit logging.

No wildcard cross-product secret-reader role is allowed.

## Observability boundary

Grafana, Prometheus, Loki, Tempo, OpenTelemetry/Alloy, exporters, and Superset may observe service health and business telemetry, but observability tooling must not receive application provider credentials merely to display health.

Metrics/logs/traces must redact or avoid:

- Authorization headers;
- API keys;
- OAuth client secrets;
- passwords;
- private keys;
- broker/exchange/custody secrets;
- database connection passwords;
- webhook HMAC secrets.

## Runtime secret classes

OpenBao is intended to hold or issue runtime material such as:

- provider API credentials;
- OAuth/OIDC client secrets;
- database credentials;
- Redis credentials;
- SMTP/provider credentials;
- webhook signing secrets;
- TLS/private-key material where appropriate;
- short-lived dynamic database credentials;
- product-specific integration credentials.

## Repository safety rules

1. No plaintext secrets in Git, issues, PRs, CI logs, screenshots, or generated evidence.
2. No OpenBao root token or unseal/recovery material in GitHub Actions secrets used for ordinary deployment.
3. No production secret values in staging or test fixtures.
4. Secret values must never be copied into Grafana dashboards, Superset datasets, Prometheus labels, Loki log labels, or trace attributes.
5. Every secret-reader policy must be least privilege and environment-scoped.
6. Production trading credentials require separate review/cutover evidence before enablement.
7. Rotation/revocation procedures must exist before any secret becomes production-authoritative.

## Current runtime state

This repository bootstrap is source-only. OpenBao deployment, initialization, unseal/recovery configuration, Keycloak integration, secret creation, secret migration, and production credential activation are not enabled by the upstream-source import.
