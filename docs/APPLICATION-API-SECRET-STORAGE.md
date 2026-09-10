# Application API secret storage

Codestra-OpenBao is the shared authority for the 11 requested repositories.
`config/application-secret-catalog.v1.json` records their actual source coverage,
backend identities and exact credential-to-file bindings. Application contracts
are extended in the four consumer repositories. No browser receives an OpenBao
credential or direct secret-read route. Source implementation is not runtime certification.

| Repository | Source role | OpenBao consumer |
| --- | --- | --- |
| `beyvra-frontend` | browser | `beyvra-api` |
| `beyvra-backend` | backend | `beyvra-api` |
| `Moneybee-frontend-` | browser | `moneybee-api` |
| `Moneybee-Backend` | backend | `moneybee-api` |
| `transportaion-Frontend` | planning-only | No admitted secret consumer |
| `transportation-backend-` | planning-only | No admitted secret consumer |
| `LARIM-A-Fornt-end` | browser | `larimia-api` |
| `LARIM-A-Backend` | backend | `larimia-api` |
| `Breero.com` | fullstack | `breero-api` |
| `booked4seasons` | public-form-bff | No admitted secret consumer |
| `Frontend-Resturant-` | browser-backend-unbound | No admitted secret consumer |

Transportation source is currently planning-only in the specifically requested
repositories. The restaurant frontend has no bound backend identity. The
booked4seasons public form BFF currently forwards to public intake endpoints
without a private credential; no unused identity or secret is issued for it.

## Secret scopes

All seven new identities are generated for development, test, staging and
production by the existing workload-authority, policy and JWT generators. Each
role gets a five-minute token, exact environment/client claims and read-only KV
access within its namespace. Operator secret writes and lifecycle operations are
separate from consumer policies. Existing platform identities are unchanged.

| Workload | Logical namespace after `codestra/<environment>/` |
| --- | --- |
| `moneybee-api` | `moneybee/api/runtime/` |
| `larimia-api` | `larim-a/api/runtime/` |
| `breero-api` | `breero/api/runtime/` |
| `beyvra-api` | `beyvra/api/runtime/` |
| `beyvra-trading-executor` | `beyvra/execution/provider/` |
| `beyvra-market-data` | `beyvra/market-data/providers/` |
| `beyvra-funding` | `beyvra/funding/providers/` |

Beyvra market-data, funding, trading and application runtime identities require
separate process bindings. A policy split alone does not isolate a monolith.
The API runtime policy cannot read the other three namespaces. Provider-specific
permissions must also be narrow enough; one all-purpose broker key would defeat
the intended separation even if stored under several paths.

## Private native APIs

| Operation | Endpoint | Authorized caller |
| --- | --- | --- |
| Workload login | `POST /v1/auth/jwt-codestra/login` | Agent using the admitted short-lived workload JWT |
| Read one secret | `GET /v1/codestra/data/<environment>/<namespace>/<secret-name>` | Scoped workload only |
| Inspect own secret metadata | `GET /v1/codestra/metadata/<environment>/<namespace>/<secret-name>` | Scoped workload only |
| Create/rotate version with CAS | `POST /v1/codestra/data/<environment>/<namespace>/<secret-name>` | Separately authorized secret operator |
| Renew/revoke own token | `POST /v1/auth/token/renew-self`, `POST /v1/auth/token/revoke-self` | Own token only |
| Health | `GET /v1/sys/health` | Private monitoring with sanitized output |

The data record holds a string `payload` field. Use check-and-set when writing a
new KV-v2 version. Applications get no secret-write, destroy, unseal or administration
capabilities. Do not proxy arbitrary OpenBao paths through Kong or Middleware.
References: [OpenBao KV-v2 API](https://openbao.org/api-docs/secret/kv/kv-v2/)
and [Agent templates](https://openbao.org/docs/agent-and-proxy/agent/template/).

## Render a reviewable bundle

```bash
python3 scripts/render_application_secrets.py \
  --identity moneybee-api --environment staging \
  --service-uid 10001 --service-gid 10001 \
  --include CODESTRA_MIDDLEWARE_CLIENT_SECRET \
  --output-dir /tmp/moneybee-staging-agent
```

UID/GID are an example and must match the actual non-root workload. The generated
bundle contains Agent HCL, per-secret templates, a path-only environment example
and a sanitized manifest. It performs no network calls, writes no secret values
and applies no policy. Install templates at their manifest paths and precreate
service-owned memory-backed destination directories before starting the Agent.
The runtime supervisor must wait for all required files before starting the API.
The existing workload issuer must replenish its JWT file as tokens expire.

Settings load at startup. After rotation, restart/recreate affected consumers,
verify cutover, then revoke the previous provider credential. Agent refreshing
static KV does not automatically rotate provider credentials or SDK objects.

## Deployment status

Runtime apply remains disabled. The most recent recorded OpenBao readiness
observation is in PR #52: uninitialized and sealed, not live secret delivery.
Initialize/unseal through the existing custody process; satisfy approved immutable
image, audit, recovery, isolated denial/rotation tests and protected promotion
before applying a reviewed exact-source plan. This source change does not
initialize the cluster or enable trading, payments, email or SMS effects.

## Consumer pull requests

- [Moneybee-Backend #78](https://github.com/appolon1908-hue/Moneybee-Backend/pull/78)
- [LARIM-A-Backend #8](https://github.com/appolon1908-hue/LARIM-A-Backend/pull/8)
- [Breero.com #127](https://github.com/appolon1908-hue/Breero.com/pull/127)
- [beyvra-backend #108](https://github.com/appolon1908-hue/beyvra-backend/pull/108)

The expanded shared API and record ownership requirements are in
[Product API integration](PRODUCT-API-INTEGRATION.md).
