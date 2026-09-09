# Codestra OpenBao Production Server and Native API Contract

## Authority

- Repository: `appolon1908-hue/Codestra-OpenBao`
- Role: corporate secrets, PKI, workload identity, lease, revocation, transit, and audit authority
- Canonical hostname: `bao.codestra.media`
- Central production host: `37.27.128.39`
- Status: `SOURCE_CONTRACT_PREPARED_NOT_DEPLOYED`

OpenBao owns its server configuration, integrated Raft, TLS/mTLS, audit devices, authentication methods, least-privilege policies, secret-path schema, PKI, dynamic credentials, backup/restore, release evidence, and rollback. It is not a workflow engine and never grants observability components business or financial mutation authority.

## Current vulnerability boundary

The currently pinned image contains affected `google.golang.org/grpc` v1.82.1 for `CVE-2026-84304`. The repository VEX disposition is valid only while **every OpenBao deployment and runtime-binding authority remains false**. It expires on **September 9, 2026** and cannot authorize staging runtime, production canary, or live deployment.

Before any OpenBao runtime activation, require one of the following:

```text
GRPC_GO_VERSION>=1.83.1
```

or a new, non-expired, evidence-backed security assessment that explicitly authorizes the exact image and runtime configuration. Until then:

```text
OPENBAO_RUNTIME_ACTIVATION=BLOCKED
OPENBAO_PRODUCTION_DEPLOYMENT=NO
```

## Native API surface

| Method | Path | Purpose | Boundary |
|---|---|---|---|
| `GET` | `/v1/sys/health` | cluster health/seal readiness | controlled health metadata only |
| `GET` | `/v1/sys/seal-status` | seal-state metadata | controlled health metadata only |
| authenticated | auth-method metadata API | enabled auth configuration | privileged read-only role |
| authenticated | PKI health API | issuer/role/expiry metadata | PKI operator/read-only role |
| authenticated | lease/revocation metadata | lease health and revocation proof | scoped operator role |
| authenticated | audit metadata | audit-device health | auditor role |

Certification must not read secret values into logs or evidence. Initialization, unseal, recovery, root-token use, policy mutation, secret mutation, and certificate issuance are separate controlled operations.

## Identity and isolation

- Use TLS 1.3 and required client-certificate verification on private native endpoints.
- Native API and Raft ports are never Internet-published.
- Human access uses the approved Keycloak OIDC client, PKCE S256, MFA, no default role, and short sessions.
- Workloads use short-lived, audience-bound identities scoped by business, application, and environment.
- Cross-business wildcards are prohibited.
- Grafana, Prometheus, Loki, Tempo, OpenTelemetry, Alloy, exporters, Superset, and n8n cannot read another business's secrets.
- Beyvra observability identities cannot read broker/exchange/custody credentials, decrypt protected trading payloads, export signing keys, or authorize/sign trades.
- Recovery shares, unseal material, root tokens, and usable private keys never enter Git, CI logs, chat, telemetry, or ordinary runtime containers.

## Production gates

```text
PROTECTED_PRODUCTION_SHA=PASS
OFFICIAL_SOURCE_LOCK=PASS
CVE_2026_84304_RUNTIME_BLOCK=RESOLVED
TLS13=PASS
MTLS=PASS
RAFT_HEALTH=PASS
AUDIT_DEVICES=PASS
OIDC_PKCE_MFA=PASS
WORKLOAD_IDENTITY=PASS
LEAST_PRIVILEGE_POLICIES=PASS
CROSS_BUSINESS_DENIAL=PASS
LEASE_AND_REVOCATION=PASS
IMMUTABLE_IMAGE_DIGEST=PASS
IMAGE_SIGNATURE=PASS
SBOM=PASS
PROVENANCE=PASS
SECRET_SCAN=PASS
RAFT_SNAPSHOT=PASS
ISOLATED_RESTORE=PASS
ROLLBACK_MANIFEST=PASS
```

If a new cluster requires initialization, use only the repository-documented quorum-controlled custody ceremony. If custody cannot be completed, leave OpenBao sealed and report a blocker; never invent or expose custody material.

## Runtime certification

```text
GET_/v1/sys/health=PASS
GET_/v1/sys/seal-status=PASS
AUTH_METHOD_METADATA=PASS
PKI_HEALTH_METADATA=PASS
AUDIT_DEVICE_HEALTH=PASS
OIDC_LOGIN=PASS
WRONG_ROLE_DENIED=PASS
WRONG_BUSINESS_DENIED=PASS
EXPIRED_CREDENTIAL_DENIED=PASS
REVOKED_CREDENTIAL_DENIED=PASS
LEASE_REVOCATION=PASS
SECRET_VALUES_IN_EVIDENCE=0
RAFT_SNAPSHOT=PASS
ISOLATED_RESTORE=PASS
UNEXPECTED_404=0
UNEXPECTED_5XX=0
SOURCE_RUNTIME_DRIFT=0
```

## Repository-first remediation

Stop the OpenBao wave on vulnerability, seal, Raft, audit, policy, identity, backup, restore, or authorization failure. Preserve the old healthy cluster and fix the owning source/configuration here with tests, protected review, signed immutable rebuild, BOM and rollback update, then retry. Never patch policies or server configuration only on the host.

## Safety

This document does not initialize, unseal, deploy, issue certificates, create secrets, or enable production access. SSH changes, business writes, communications delivery, provider effects, lending, payments, and trading remain outside scope and disabled.