# OpenBao in the monitoring platform

OpenBao is the secrets, credentials and PKI plane. Middleware is the operational
control plane. Prometheus, Loki, Tempo and Alloy/OTel are the telemetry data
plane. This document records what this repository contributes to that model and
what it deliberately refuses. Everything here is source only:
`runtimeApplyAuthorized` stays `false`, and nothing in this branch initialises,
unseals, applies a policy, writes a secret or enables a provider effect.

## Authority planes

| Plane | Owner | OpenBao's part |
| --- | --- | --- |
| Operational control (catalog, incidents, reconciliation, audit state) | Middleware | none; Middleware stores only secret *references* and lease/rotation metadata |
| Secrets, credentials, PKI, leases, rotation, secret-access audit | **OpenBao** | this repository |
| Metrics, logs, traces | Prometheus, Loki, Tempo, Alloy/OTel | OpenBao exposes `GET /v1/sys/metrics?format=prometheus` and `GET /v1/sys/health` privately and ships its audit file through Alloy to Loki |

## Workload identities admitted for the monitoring plane

`config/policies/workload-identities.v1.json` is the reviewed inventory;
`config/workload-secret-authority.v1.json`, `openbao/policies/*/*.hcl` and
`openbao/auth/jwt-roles.v1.json` are generated from it and drift is a
validation failure.

| Identity (Keycloak `azp`) | Environments | Exact prefix | Purpose |
| --- | --- | --- | --- |
| `prometheus-openbao` | dev, test, staging, production | `observability/openbao/metrics-client/`, `observability/prometheus/scrape-credentials/` | OpenBao metrics token/mTLS material; `monitoring-readonly` client secret and exporter basic-auth for scrapes; the only role with `sys/metrics` read |
| `grafana-runtime` | staging, production | `observability/grafana/` | datasource basic-auth, Middleware read token, OIDC client secret |
| `alertmanager` | staging, production | `observability/alertmanager/` | Middleware webhook bearer only |
| `alloy-collector` | staging, production | `observability/alloy/` | Loki push and OTLP gateway credentials |
| `otel-gateway` | staging, production | `observability/otel-gateway/` | receiver and Tempo/Loki exporter credentials |
| `loki-runtime` / `tempo-runtime` | staging, production | `observability/loki/`, `observability/tempo/` | object-storage credentials |
| `redis-exporter` / `postgres-exporter` | staging, production | `observability/exporters/redis/`, `observability/exporters/postgres/` | monitoring-only database/cache credentials |
| `superset-analytics` | staging, production | `analytics/superset/` | read-only projection database, metadata database and OIDC client secret |

Node Exporter, cAdvisor and Blackbox Exporter hold no credentials and have no
identity. Keycloak issues identities and is not a secret-reading workload.
`monitoring-readonly` is a Keycloak client that scrapes Middleware; it is not an
OpenBao identity and it never receives a secret-reading scope.

Every generated policy for these identities:

- reads only beneath its own `codestra/<environment>/<prefix>`;
- denies every other environment root explicitly;
- denies `sys/*`, `database/*`, `pki-*`, `transit-*` and `auth/token/create*`;
- keeps `auth/token/lookup-self`, `renew-self` and `revoke-self` only.

No wildcard reader exists; `explicitDeny.observability-general` denies every
environment root to any generic observability identity.

## Keycloak → OpenBao workload identity

Every role is a CEL program on the `jwt-codestra` mount that requires
`iss`, `sub`, `aud`, `azp`, `iat`, `exp`, `jti` and `codestra_environment`, and
rejects unless:

- `iss` equals the issuer of **that environment**
  (`config/auth/keycloak-jwt.v1.json` → `issuersByEnvironment`): production
  binds `https://auth.codestra.co/realms/codestra`; staging binds
  `https://auth-staging.codestra.co/realms/codestra`. Development and test
  currently bind the staging issuer because no other non-production issuer
  exists; their roles still require `codestra_environment` to equal their own
  environment and therefore remain unsatisfiable until such an issuer is
  approved. The production issuer is trusted by the production mount only.
- `aud` is or contains `openbao`;
- `azp` equals the service identity;
- `codestra_environment` equals the role's environment;
- the token lifetime is at most 300 seconds; the `jti` replay cache is enforced
  by `plugins/codestra-jwt-replay`.

The returned token carries only `workload-<identity>-<environment>`, a 300 s
TTL and a 300 s maximum TTL, and is renewable within that bound. Foreign issuer,
wrong audience, wrong client, cross-environment claims, missing identity,
expiry and tampering all evaluate to `false` and are audited.

The Keycloak side (`ingtrader21-spec/Keycloak`) must issue the `openbao`
audience and the `codestra_environment` claim to exactly these confidential
clients through the `openbao.workload` optional client scope; the Keycloak
repository validates that mapping against this authority.

## Secret references

`contracts/secret-reference.v1.schema.json` is the shared pointer contract.
`config/secret-references.v1.json` is the reviewed catalog of every reference
the monitoring plane and Middleware consume (validated by
`scripts/validate_secret_references.py`, which fails closed on any value-bearing
key, secret-shaped string, cross-environment path, or path outside the named
identity's admitted prefixes).

```json
{
  "provider": "openbao",
  "environment": "staging",
  "service_id": "middleware",
  "secret_ref": "codestra/staging/middleware/api/database",
  "secret_class": "database_credentials",
  "version": null,
  "reference_uri": "openbao://codestra/staging/middleware/api/database",
  "workload_identity": "middleware-api"
}
```

Middleware may persist this object plus `secret_owner`, `rotation_status`,
`lease_metadata` (hashed lease id, TTL, expiry) and reconciliation timestamps.
It must never store or return `value`, `password`, `token`, `private_key`,
`client_secret` or any secret-shaped string, and no Middleware API resolves a
reference.

## OpenBao → Prometheus

- Scrape: `monitoring/prometheus/openbao-scrape.yml` (production) and
  `openbao-scrape.staging.yml`; `metrics_path: /v1/sys/metrics`,
  `params.format: [prometheus]`, `scheme: https`, mTLS on the private
  observability listener, bearer from `credentials_file` (a short-lived token
  minted by the `prometheus-openbao` role and rendered outside Git). No
  long-lived credential exists in `prometheus.yml`.
- Policy: `workload-prometheus-openbao-<env>` is the only policy with
  `sys/metrics` read; every other `sys/*` path is denied.
- Telemetry contract: `config/telemetry/telemetry.v1.json`
  (`unauthenticatedMetricsAccess: false`, `secretLabelsAllowed: false`).

## OpenBao health

- Probe: Blackbox module `https_openbao_health`
  (`monitoring/blackbox/openbao-health-module.yml`) issues only `GET
  /v1/sys/health`, accepts 200 (active) and 429 (standby), and requires the
  body to report `initialized: true` and `sealed: false`. Targets:
  `monitoring/blackbox/openbao-health-targets.json`.
- Alerts (`monitoring/alerts/openbao-alerts.yml`): reachability, sealed, not
  initialised, no active leader, standby-only, health-probe failure and
  latency, audit request/response failure, audit device silent while unsealed,
  auth-failure surge, policy-denial rate, leadership changes, Raft quorum,
  token creation, irrevocable leases, backup age/failure, rotation/revocation
  failure, credential near expiry, restart loop, filesystem capacity, drift.
- A sealed or uninitialised probe result is an operator page. Nothing in this
  repository or in Middleware unseals or initialises OpenBao in response to a
  probe; unseal and recovery stay under `docs/recovery/` custody procedures.

## Audit pipeline

`config/audit/audit.v1.json` declares the file audit device
(`hmacAccessor: true`, `logRaw: false`, `failClosed: true`, mode `0600`).
`monitoring/alloy-openbao-audit.alloy` tails the file, extracts bounded labels
(`type`, `operation`) and pushes to the private Loki endpoint. HMAC and
redaction are OpenBao's own; the pipeline neither reverses nor weakens them,
and audit lines never reach a public endpoint. Loki ruler alerts
(`monitoring/alerts/openbao-audit-loki-rules.yml`) cover audit stream silence,
root-token use, permission-denial surges, policy and control-plane changes,
initialisation failure and authentication-failure surges.

## Dashboard

`monitoring/dashboards/codestra-openbao.json` shows only operational state:
initialised, sealed/unsealed, leader/standby, Raft peers, request rate and
latency, tokens and leases (counts only), audit success/failure, storage
activity, CPU, memory, filesystem, restarts, health-probe status and latency,
authentication failures and policy-denial rate (from the audit stream). No panel
queries a secret path, token value, unseal or recovery key.

## Rotation, revocation and failure modes

- Rotation and revocation follow `docs/operations/OPENBAO-ROTATION.md` and are
  exercised by `scripts/rotate-test.sh` / `scripts/revoke-test.sh`: the workload
  obtains a short-lived credential, functions, the secret rotates (CAS N→N+1),
  the old credential is revoked and proven denied, the workload re-authenticates
  and keeps functioning, and the sanitised evidence records only hashes,
  versions, identities and paths.
- OpenBao unavailable: the agent-rendered file keeps serving an already valid
  lease only until it expires; a missing or expired credential fails startup
  (`missingSecretFailsStartup: true`); there is no Git or plaintext fallback
  (`gitMaterializationAllowed: false`, `environmentVariablesAllowed: false`).
  The workload reports sanitised health (`secret_source: openbao`,
  `lease_state: expired|missing`) and Middleware records
  `last_reconciliation_status: openbao_unavailable` on the reference.
- Prometheus, Loki, Tempo, Alertmanager or Middleware unavailable: OpenBao keeps
  serving secrets; only monitoring coverage degrades and the corresponding
  alerts fire from the surviving components.

## Staging runtime certification tooling

Two runnable, fail-closed certifiers turn the checklist below into evidence.
Both refuse anything but `staging`, never unseal, never write a secret, read
credentials only from `*_FILE` paths, and refuse to write evidence that
contains a token, a JWT or secret-shaped material.

- `scripts/certify_staging_identity.py` proves one workload identity end to
  end against the live `bao.codestra.media` authority: the public name answers
  TLS on 443 only (native 8200/8201 unreachable), `GET /v1/sys/health` answers
  unauthenticated while seal/unseal/policy/audit mutations are refused, the
  Keycloak token carries `iss`/`aud=openbao`/`azp`/`codestra_environment`/`jti`
  with a ≤ 300 s lifetime, `auth/jwt-codestra/cel/login` returns exactly
  `workload-<identity>-staging`, the own prefix is authorised, and the
  production path, another service's prefix, the wrong role, a token minted
  without `scope=openbao.workload`, a modified signature and a rewritten issuer
  are all refused; `revoke-self` is then proven to deny the next read.
  Optional: `OPENBAO_IDENTITY_WAIT_FOR_EXPIRY=true` proves the expired-token
  rejection, `MONITORING_READONLY_CLIENT_SECRET_FILE` proves that
  `monitoring-readonly` is never admitted. Evidence:
  `STAGING_OPENBAO_IDENTITY_GO=YES|NO` plus a per-check record.
- `config/rotation-certification.v1.json` is the eight-step rotation matrix
  (credential obtained → functions on N → CAS rotate to N+1 → agent renders
  N+1 → new credential verified → old revoked and denied → workload healthy
  again → sanitised evidence) bound to the hooks of `scripts/rotate-test.sh`,
  `scripts/revoke-test.sh` and the identity certifier;
  `tests/security/test_rotation_certification_contract.py` keeps the matrix
  and the scripts aligned. Production rotation is not authorised by this
  contract (`productionRotationAuthorized: false`).

## Staging certification checklist (source view)

| Requirement | Source evidence | Runtime evidence needed |
| --- | --- | --- |
| Initialised through the approved operator procedure; custody documented | `scripts/initialize.sh`, `docs/recovery/` | initialisation record and custody attestations |
| No root token in Git | `scripts/reject_repository_secrets.sh`, `tests/security` | — |
| Audit device active before secret use | `config/audit/audit.v1.json` (`requiredBeforeSecretUse`) | audit listing from the staging node |
| Keycloak JWT works; staging identity reads its path, cannot read production; another service cannot read Middleware paths | `tests/security/test_monitoring_identities.py`, `tests/policy` | `scripts/verify.sh` negative/positive reads with staging tokens |
| Prometheus retrieves `/v1/sys/metrics`; `/v1/sys/health` observed | scrape and probe files above | Prometheus target and probe results |
| Audit telemetry reaches Loki; Grafana displays health | Alloy config, Loki rules, dashboard | LogQL query result and dashboard render |
| No secret value in metrics, logs, traces, dashboards | `tests/security/test_monitoring_contract.py`, secret-reference validator | staging sample scan |

Runtime certification is recorded in the Middleware evidence package for the
mission; this repository asserts the source side only.
