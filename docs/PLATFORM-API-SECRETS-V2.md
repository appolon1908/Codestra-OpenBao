# Codestra platform API secret authority v2

## Status

This document maps the platform API secret boundary already implemented by the
canonical workload-identity inventory and its generated OpenBao authority. It
does not authorize applying that authority to a live cluster.

```text
SOURCE_AUTHORITY=IMPLEMENTED
RUNTIME_BINDINGS_AUTHORIZED=false
OPENBAO_RUNTIME_APPLY=false
SECRETS_WRITTEN=0
TOKENS_ISSUED=0
PROVIDER_ADAPTERS_ACTIVE=false
PRODUCTION_CHANGED=false
```

## Canonical source chain

The reviewed source of truth is deliberately split into an inventory,
deterministic generation, generated artifacts, fail-closed validation and
negative tests:

| Responsibility | Canonical path |
| --- | --- |
| Workload identity and namespace inventory | `config/policies/workload-identities.v1.json` |
| Deterministic generator | `scripts/generate_workload_authority.py` |
| Generated role authority | `config/workload-secret-authority.v1.json` |
| Generated policy source | `scripts/generate_workload_policies.py` |
| Generated policy index | `config/policies/generated-policy-index.v1.json` |
| Separate monitoring API client contract | `codestra/runtime-v1/keycloak-monitoring-readonly.v1.json` |
| Fail-closed validator | `scripts/validate_workload_secret_authority.py` |
| Mutation and isolation tests | `tests/test_workload_secret_authority.py` |
| Repository-wide policy/integration CI | `.github/workflows/policy-tests.yml` |
| Repository security and release gates | `.github/workflows/security.yml`, `.github/workflows/validate.yml` |

Generated artifacts must match the reviewed inventory exactly. Hand-edited
generated output, an unrecognized identity, a broad path, a cross-environment
claim, runtime activation, unauthorized write capability or missing
audit/rotation control must fail validation.

## Admitted workload identities

### Shared platform identities

The following identities are defined for `development`, `test`, `staging` and
`production` with exact environment claims and environment-prefixed secret
paths:

- `kong-gateway` — exact Kong runtime and upstream authentication material;
- `middleware-api` — API runtime credentials without provider master
  credentials;
- `middleware-worker` — effect-executor credentials separated by email, SMS,
  social, advertising, AI, telephony and crawler families;
- `n8n-automation` — exact Middleware client and orchestration credentials only;
- `odoo-integration` — exact Odoo integration credentials only;
- `prometheus-openbao` — private OpenBao metrics-client material plus the
  generated `sys/metrics` read capability. This OpenBao workload identity is
  bound to audience `openbao`, `azp=prometheus-openbao`, and the exact
  environment claim. It does not own or request the Keycloak `metrics.read`
  client scope.

### Separate monitoring API client

`monitoring-readonly` is a distinct Keycloak service client recorded in
`codestra/runtime-v1/keycloak-monitoring-readonly.v1.json`. It is bound to
audience `middleware-api`, has no default client scopes, and may explicitly
request the optional `health.read` and `metrics.read` scopes. Those scopes
authorize the bounded monitoring API contract; they do not grant access to an
OpenBao secret path or make `monitoring-readonly` equivalent to
`prometheus-openbao`.

### Provider adapter identities

The following identities are limited to `staging` and `production` and receive
only their exact provider namespace:

- `klyrow-email-adapter` — `middleware/worker/email/klyrow/`;
- `telnexa-sms-adapter` — `middleware/worker/sms/telnexa/`;
- `vicidial-adapter` — `middleware/worker/telephony/vicidial/`;
- `crawler-adapter` — `middleware/worker/crawler/kyqra/`.

Provider credentials are not granted to browser applications, Grafana, Odoo
users, n8n workflows, marketing applications, social applications or unrelated
adapters. Provider business effects remain disabled independently of
secret-read authority.

## Authentication and authorization invariants

Every generated role is bound to:

- Keycloak JWT authentication from
  `https://auth.codestra.co/realms/codestra`;
- audience `openbao`;
- exact `azp` service identity;
- exact `codestra_environment` claim;
- environment-prefixed `codestra/<environment>/...` paths;
- five-minute token TTL and maximum TTL;
- explicit owner, purpose, rotation, revocation and audit requirements;
- `runtimeBindingAuthorized=false`;
- `providerBusinessEffectsEnabled=false`.

The role authority records `read` as the admitted secret operation. The
deterministic HCL generator expands that narrow authority into these exact
capabilities only:

- `read` on the admitted `codestra/data/...` secret prefixes;
- `read` and `list` on the matching admitted `codestra/metadata/...` prefixes,
  solely so a consumer can traverse its own KV metadata;
- `read` on `auth/token/lookup-self`;
- `update` on `auth/token/renew-self` and `auth/token/revoke-self`, solely for
  the workload's own token lifecycle;
- `read` on `sys/metrics` only for `prometheus-openbao`.

No identity may receive an environment root, cross-service namespace,
cross-adapter namespace, recursive platform-wide read, secret-data `list`,
secret-data `create` or `update`, `delete`, `patch`, `sudo`, token creation or
policy-management capability. The exact metadata-list and self-token lifecycle
exceptions above are not general write authority and must not be broadened.

## Secret material rules

Permitted OpenBao records are configuration secrets needed by a specifically
admitted machine identity. OpenBao remains the only permitted storage
authority for those values; the source repository stores contracts and
sanitized metadata only.

The authority prohibits storing:

- access or refresh tokens as durable application records;
- customer, form, survey, message, lead, document, recording or provider
  payloads;
- root tokens, recovery or unseal material, private keys or bootstrap
  credentials in Git;
- secrets in container images, committed environment files, browser storage,
  CI logs, screenshots or evidence bundles.

Agent-rendered files must use atomic replacement, mode `0400`, fail startup
when required material is absent, renew agent authentication and dynamic
leases, rerender changed static KV material, and revoke dynamic child leases at
shutdown.

## Rotation, revocation and audit

Every admitted secret has an accountable owner and a maximum ninety-day age
unless a stricter provider rule applies. Rotation requires overlap, consumer
cutover proof, old-version revocation, subsequent-access denial and an audit
event. Emergency revocation must invalidate the auth token accessor and every
dynamic child lease without enabling an alternate broad credential path.

Audit evidence must identify the workload, environment, policy, path class,
request/correlation identifiers, decision and result while proving that no
secret value was captured.

## Promotion and activation boundary

Only a current `remediation/*` head or deterministic
`sync/openbao-upstream-*` head may target `development`. Protected promotion
then follows:

```text
development -> test -> staging -> production -> main
```

A protected merge only publishes source authority. Applying policies or roles
requires a separately approved plan tied to the exact source SHA and image
digest, an initialized and securely unsealed OpenBao cluster, offline recovery
custody, audit devices, off-host backup authority, staging readback,
cross-business denial tests, rotation/revocation proof, rollback evidence and
post-apply drift verification.

Until those gates pass:

```text
OPENBAO_RUNTIME_ACTIVATION=BLOCKED
OPENBAO_PRODUCTION_DEPLOYMENT=NO
```
