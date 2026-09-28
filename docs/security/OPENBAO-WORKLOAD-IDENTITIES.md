# OpenBao workload identities

`config/policies/workload-identities.v1.json` is the owner and eligibility
inventory. `config/workload-secret-authority.v1.json` is generated authority;
`openbao/auth/jwt-roles.v1.json` contains the exact CEL roles. There are 78
prepared roles across four environments. All runtime bindings remain disabled.

| Identity | Owner | Environments | Purpose |
| --- | --- | --- | --- |
| `kong-gateway` | platform-edge | all | gateway runtime/upstream material |
| `middleware-api` | middleware-platform | all | API-only integration credentials |
| `middleware-worker` | middleware-platform | all | approved provider effect executor, split by provider family |
| `n8n-automation` | automation-platform | all | Middleware client/orchestration credential only |
| `odoo-integration` | business-integrations | all | exact Odoo integration credential only |
| `prometheus-openbao` | observability-platform | all | authenticated metrics only; no general secret reads |
| `grafana-runtime` | observability-platform | staging, production | datasource, Middleware read-token and OIDC client secret only |
| `alertmanager` | observability-platform | staging, production | Middleware alert-webhook bearer only |
| `alloy-collector` | observability-platform | staging, production | Loki push and OTLP gateway client credentials only |
| `otel-gateway` | observability-platform | staging, production | gateway receiver and Tempo/Loki exporter credentials only |
| `loki-runtime` | observability-platform | staging, production | Loki object-storage credentials only |
| `tempo-runtime` | observability-platform | staging, production | Tempo object-storage credentials only |
| `redis-exporter` | observability-platform | staging, production | monitoring-only Redis ACL user |
| `postgres-exporter` | observability-platform | staging, production | pg_monitor role credential only |
| `superset-analytics` | analytics-platform | staging, production | read-only projection/metadata database and OIDC client secret only |
| `klyrow-email-adapter` | klyrow-platform | staging, production | exact email adapter path; live effects remain disabled |
| `telnexa-sms-adapter` | telnexa-platform | staging, production | exact SMS adapter path; live effects remain disabled |
| `vicidial-adapter` | communications-platform | staging, production | exact telephony adapter path; dialing remains disabled |
| `crawler-adapter` | kyqra-platform | staging, production | exact Kyqra crawler adapter path |
| `beyvra-api` | beyvra-platform | all | read-only Beyvra API private configuration secrets |
| `beyvra-funding` | beyvra-platform | all | read-only Beyvra funding private configuration secrets |
| `beyvra-market-data` | beyvra-platform | all | read-only Beyvra market-data private configuration secrets |
| `beyvra-trading-executor` | beyvra-platform | all | read-only Beyvra trading-executor private configuration secrets |
| `breero-api` | breero-platform | all | read-only Breero API private configuration secrets |
| `larimia-api` | larim-a-platform | all | read-only Larimia API private configuration secrets |
| `moneybee-api` | moneybee-platform | all | read-only Moneybee API private configuration secrets |

An identity is admitted only when its owner, runtime consumer, exact Keycloak
client, environment claim, paths, TTL, rotation procedure, revocation procedure
and audit evidence exist. General repository membership is not eligibility.

Negative tests must prove wrong issuer, audience, environment, client, expiry,
lifetime, missing claim and replay are denied. Revoking one workload must not
affect unrelated workloads. The isolated source suite proves those JWT and JTI
boundaries; each deployed environment must repeat them against its real
Keycloak identity before certification.

## File-only agent handoff

`scripts/render_agent_config.py` renders one exact secret object for one listed
identity. The requested path must fall beneath that identity's environment
prefix and the destination must remain beneath
`/run/codestra-secrets/<identity>/`. The generated agent:

- authenticates to `auth/jwt-codestra` with the exact environment role;
- consumes and removes the short-lived workload JWT without following a
  symlink;
- keeps the renewable OpenBao token in memory and configures no token sink;
- renders the required `payload` key atomically with mode `0400`;
- creates no destination directory and therefore requires the deployer to
  pre-create it with the recorded non-root service UID/GID; and
- exits after exhausted authentication/template retries or a missing key.

The manifest contains paths, IDs and policy metadata only. It never contains a
JWT, OpenBao token or secret value. Environment-variable delivery and Agent
process-supervisor environment injection are prohibited.
