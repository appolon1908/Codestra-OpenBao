# Codestra OpenBao Authority

Principal repository: `appolon1908-hue/Codestra-OpenBao`
Canonical service host: `bao.codestra.media`
Canonical DNS target: `37.27.128.39`
TTL: `600`

DNS has been externally verified. No alternate authoritative hostname is permitted.

## Ownership
Own OpenBao server configuration, auth methods, policies, secret-engine configuration, PKI/seal/HA/backup/restore runbooks, audit-device policy and upgrade procedures. Do not store real secrets in Git. Do not own Caddy, Keycloak, application business logic or provider runtime credentials outside OpenBao-managed references/policies.

## Exposure
The UI/API is protected. Browser access may be allowed only through authenticated, tightly restricted HTTPS ingress. Direct OpenBao service ports remain private. Administrative/root-token operations are never exposed through public automation.

## Integration
Upstream clients: approved workloads and operators using least-privilege identities. Downstream: secret issuance/lookup, PKI and dynamic credentials where explicitly configured. Monitoring exports only non-secret health/metrics to the observability stack.

## Branch policy
Persistent: `main`, `development`, `test`, `staging`, `production`.
Temporary: `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, optional `release/*`, `rollback/*`.
Promotion: work -> development -> test -> staging -> production -> main.
