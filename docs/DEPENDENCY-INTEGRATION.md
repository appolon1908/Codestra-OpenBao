# Dependent service integration

The machine-readable authority is `contracts/dependent-services.v1.json`. It was reconciled against Middleware, Odoo, Klyrow, Telnexa, Keycloak, Grafana, Prometheus, Alertmanager, Superset, and VICIdial integration ownership.

## Confirmed contracts

- Klyrow defines six secret aliases for Middleware authentication, webhook HMAC, Postal, SMTP TLS, and its n8n credential reference.
- Middleware requires OpenBao-rendered environment, OIDC, and mTLS files for its observability-alert process.
- Keycloak defines the confidential `openbao-secrets` OIDC client, PKCE S256, MFA-bound roles, and runtime files for OpenBao, Grafana, and Superset client secrets.
- Odoo declares OpenBao as credential-only and forbids business or observability data storage in it.
- Telnexa requires OpenBao-backed provider identities but keeps live SMS behind separate carrier and release gates.
- Monitoring components receive only their own authentication material, never application provider credentials.

Create one short-lived authentication role per consumer, attach exactly its matching policy, and render secrets as root-owned `0400` files. A deployment fails closed when a required file is absent.

OpenBao initialization does not activate email, SMS, calling, or business writes. Those kill switches remain separate production gates.
