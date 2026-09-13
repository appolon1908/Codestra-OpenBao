# Repository profile — `Codestra-OpenBao`

## Identity and authority

| Property | Authority |
| --- | --- |
| Repository | `appolon1908-hue/Codestra-OpenBao` |
| System | Codestra principal secrets, encryption, policy, lease and workload-identity authority |
| Orbit classification | `vendor-operator-ui` |
| Orbit adoption mode | `operator-theme-sso` |
| Canonical hostname | `bao.codestra.media` |
| Domain status | `verification-required` |
| Exposure | Restricted operator access plus private native API access; native ports `8200/8201` remain private |
| Integration branch | `development` |
| Validation branch | `test` |
| Pre-production branch | `staging` |
| Release branch | `production` |
| Final protected source | `main` |
| Admissible development heads | `remediation/*`, `sync/openbao-upstream-*` |
| Runtime owner | `platform-security` |
| Required independent reviewer | `@kazan555` |
| Upstream | `openbao/openbao` v2.6.2 at exact source and immutable image digests |
| Storage | Integrated Raft |
| Workload authentication | Keycloak JWT from `https://auth.codestra.co/realms/codestra` |
| Workload audience | `openbao` |
| Edge authority | External edge repository; this repository publishes a restricted handoff contract only |

## Purpose

This repository owns the desired OpenBao source, configuration, policies,
workload identities, security evidence, release controls, audit design,
backup and recovery contracts, and secret-consumer admission rules for the
Codestra platform.

It provides governed secret storage and access for approved applications and
operators without committing secret values, recovery material, client
credentials, access tokens, customer payloads or secret-bearing evidence to
Git.

## Owns

- OpenBao server configuration, integrated storage and HA design, listeners,
  seal/unseal strategy and audit devices.
- Auth methods, policies, workload roles, secret paths, leases, rotation,
  revocation, backup, restore, recovery and disaster-recovery source.
- Initialization, custody, recovery-key and break-glass procedures without
  storing their values in Git.
- Exact upstream source/image provenance, vulnerability gates,
  SBOM/provenance evidence, rollback contracts and source/runtime drift checks.
- Consumer admission for Kong, Middleware API and workers, n8n, Odoo,
  Prometheus and explicitly approved provider adapters.
- A bounded observability API contract. The shared control plane may obtain
  health/readiness metadata only and must never proxy secret values or mutation
  operations.
- A restricted operator-interface adoption contract that preserves native
  OpenBao security and operational behavior.

## Does not own

- Application business authorization, customer entitlements or Keycloak realm
  administration.
- DNS, host SSH access, Caddy/Kong runtime deployment, provider capability
  activation, communications delivery or financial/trading execution.
- Secrets, root tokens, unseal or recovery keys, OIDC client secrets, private
  keys or plaintext credentials in Git.
- Broad default roles, public unauthenticated access, browser token storage or
  cross-business secret access.
- Orbit package publication or the shared corporate design-system authority.

## Integration boundary

Production consumers are admitted individually through exact service identity,
environment claim, path prefix, read operation, TTL, rotation, revocation and
audit controls. A repository receives no OpenBao access merely because it is
part of Codestra.

The operator surface must retain native OpenBao authentication fallback,
session, logout, policy, namespace, lease, audit, seal/unseal, upgrade and
recovery behavior. Corporate branding or SSO may be added only through
supported configuration and must not expose secret material through shared
content, asset, footer or browser APIs.

## Current source and runtime state

The protected source contains the governed service API contract,
production-server contract, workload-authority schema v2, generated policy
inventory, native configuration validation, exact-head CI, supply-chain
evidence and fail-closed runtime/deployment guards.

The last repository-recorded production observation describes a
source-prepared bootstrap: OpenBao v2.6.1 on one uninitialized Raft node. That
observation is not a runtime certification. The desired v2.6.2 release, secure
initialization, HA, audit activation, monitoring activation, backup/restore
proof, workload authentication and consumer migrations remain uncertified as
applied.

```text
OPENBAO_RUNTIME_ACTIVATION=BLOCKED
OPENBAO_PRODUCTION_DEPLOYMENT=NO
ORBIT_ADOPTION_STATUS=blocked
```

## Promotion and safety

Only a current `remediation/*` head or a deterministic
`sync/openbao-upstream-*` head may target `development`. Protected promotion
then follows:

```text
development -> test -> staging -> production -> main
```

Every merge must use the reviewed exact head, successful required checks, zero
unresolved review threads and the required independent approval. Initialization,
unseal, policy apply, secret creation, credential issuance, runtime deployment
and production access are separate protected operations.

A source merge does not initialize or unseal OpenBao, write a secret, issue a
token or certificate, reload an edge proxy, change SSH or authorize provider,
communications, financial or trading effects.

## Account-wide catalog

See `appolon1908-hue/documentaions/REPOSITORY_CATALOG.md` for the account-wide
repository inventory and ownership map.
