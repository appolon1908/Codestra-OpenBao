# Dependent service integration

This package extends the governed OpenBao production framework; it does not introduce another deployment, policy, or initialization path. The machine-readable dependency contract is `contracts/dependent-services.v1.json`.

## Canonical authority

`config/workload-secret-authority.v1.json` remains the sole workload-access authority. The dependency contract records its reviewed blob SHA and copies only exact production `serviceIdentity` and `pathPrefixes` tuples. Parent-prefix broadening and identities absent from that authority are forbidden.

The admitted dependent-service bindings are:

- Middleware: `middleware-api` plus the seven explicitly enumerated `middleware-worker` provider-family prefixes.
- Odoo: `odoo-integration` at `codestra/production/odoo/integration/`.
- Klyrow: `klyrow-email-adapter` at its exact Middleware email-adapter prefix.
- Telnexa: `telnexa-sms-adapter` at its exact Middleware SMS-adapter prefix.
- VICIdial: `vicidial-adapter` at its exact Middleware telephony-adapter prefix.
- Prometheus: `prometheus-openbao` for the private OpenBao metrics client only.

Keycloak is the JWT issuer. Grafana and Superset are read-only consumers, and Alertmanager routes events through Middleware. None has a direct production OpenBao workload role unless it is first added to the canonical authority and passes policy generation and review.

## Governed runtime

The canonical framework remains authoritative:

- `deploy/compose/compose.yaml` for the immutable mTLS deployment;
- `scripts/initialize.sh` for distinct-key, PGP-encrypted 3-of-5 offline custody;
- `config/workload-secret-authority.v1.json` and generated JWT policies for exact workload access;
- `scripts/apply_saved_plan.sh` for backed-up, zero-destroy application;
- `scripts/verify.sh` for read-back certification.

Secrets render as atomic root-managed `0400` files, and missing files fail startup. Initialization does not enable email, SMS, PSTN, callbacks, Odoo writes, or other business effects.

Production requires three voting nodes, audited secret handling, exact scanned-image evidence, and explicit runtime authorization. The current one-node runtime is not production-certified.
