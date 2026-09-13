# Dependent service integration

This package extends the existing governed OpenBao production framework; it does not introduce a second deployment or initialization path. The machine-readable cross-repository authority is `contracts/dependent-services.v1.json`.

Reviewed consumers: Middleware, Odoo, Klyrow, Telnexa, VICIdial, Keycloak, Grafana, Superset, Prometheus, and Alertmanager.

Confirmed integration details include Klyrow's six secret aliases, Middleware's OpenBao-rendered OIDC/mTLS files, Keycloak's confidential OpenBao/Grafana/Superset clients, Odoo's credential-only boundary, and Telnexa/VICIdial's separate live-effect gates.

The canonical repository framework remains authoritative:

- `deploy/compose/compose.yaml` for the immutable mTLS deployment;
- `scripts/initialize.sh` for distinct-key, PGP-encrypted 3-of-5 offline custody;
- `config/workload-secret-authority.v1.json` and generated JWT policies for exact workload access;
- `scripts/apply_saved_plan.sh` for backed-up, zero-destroy application;
- `scripts/verify.sh` for read-back certification.

A service receives one short-lived Keycloak JWT-bound identity and exact prefixes only. Secrets render as atomic root-managed `0400` files. Missing files fail startup. Initialization alone never enables email, SMS, PSTN, or business writes.

Production requires three voting nodes, audited secret handling, exact scanned image evidence, and explicit runtime authorization. The current one-node state is not production-certified.
