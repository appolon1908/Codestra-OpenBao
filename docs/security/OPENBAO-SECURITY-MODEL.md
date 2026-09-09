# OpenBao security model

## Trust boundaries

Git contains desired configuration and hashes, never secret values. Runtime
credentials originate from protected custody or short-lived identity. Workload
traffic is private; public browser administration terminates at the separately
owned authenticated edge.

The native listener requires TLS 1.3 and a trusted client certificate. Server
certificates, private keys and client CA files are mounted read-only from
protected paths. The Compose service uses a read-only root filesystem, drops
all capabilities, prohibits privilege escalation and publishes no host ports.
Host preflight rejects active unencrypted swap.

## Authentication

Workload JWTs must have issuer
`https://auth.codestra.co/realms/codestra`, audience `openbao`, the exact
workload `azp`, exact `codestra_environment`, and non-empty `iss`, `sub`, `aud`,
`azp`, `iat`, `exp`, `jti` and environment claims. `exp - iat` is at most 300
seconds. Wildcard client matching and the default policy are disabled.

The exact upstream OpenBao v2.6.2 JWT backend is wrapped by the external
`codestra-jwt-replay` auth plugin. After upstream signature, issuer, audience
and CEL validation succeeds, the wrapper claims a SHA-256 identifier derived
from issuer, client, environment and JTI in transactional Raft storage. Raw
tokens and raw JTIs are never stored or logged. Duplicate and transaction-
collision requests fail closed; expired hash entries are bounded and cleaned.

The plugin is built reproducibly from the exact upstream SHA with Go 1.25.13
and checksum-locked `golang.org/x/crypto` and `google.golang.org/grpc` security
overrides. The latter upgrades grpc-go to v1.83.1 for CVE-2026-84304. Version
v1.1.0 has binary digest
`332562de9c3f179b4598104cceb83c4cddf0896428df192697e7d91dc6651508`.
Because OpenBao Agent JWT auto-auth calls the standard `login` route while CEL
roles use `cel/login`, the dedicated mount maps standard login internally to
CEL login before upstream validation. Both paths then pass through the same
transactional JTI claim; standard JWT-role login cannot bypass CEL or replay
protection.
Sequential replay, sixteen-way concurrent replay and wrong/missing claim tests
pass in isolated OpenBao. `jtiReplayCacheImplemented=true` records that source
result; runtime application remains unauthorized until the environment gates
and protected apply are complete.

## Authorization and delivery

Every policy binds one service identity to one environment and exact path
prefixes. Cross-service, cross-environment, wildcard, system administration,
root and provider-master access are denied. Agent-rendered files must use
atomic replacement, mode `0400` and the service owner. Required missing files
fail startup. Dynamic leases renew and revoke on shutdown; static KV v2 values
re-render on version change.

## Audit and evidence

The file audit device is declarative server configuration rather than an
API-created device. API audit creation stays disabled. The device hashes
accessors and does not log raw values.
Sanitized audit records flow to Alloy/Loki. CI rejects common credential
formats in the working tree and full Git history. Plans, read-back and
certification evidence contain paths, hashes, counts and status only.

Before a runtime container is stopped, `verify_tls_material.sh` validates the
server and health-client chains, server and client purposes, canonical API and
node SANs, certificate/CA minimum validity windows, and certificate/private-key
public-key matches. It emits status and names only, never key material.

## Separate business authorization

OpenBao access never enables live email, SMS, dialing, Odoo writes, n8n
external effects, social publishing, advertising spend, AI mutations, trading,
payments or other provider effects. Those kill switches remain false and are
outside this platform release.
