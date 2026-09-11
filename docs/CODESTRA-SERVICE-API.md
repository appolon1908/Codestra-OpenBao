# Codestra service API contract: OpenBao

This repository owns the **secrets-pki-workload-identity-authority** for the Codestra observability, analytics, telemetry, and secrets suite.

## Communication rule

OpenBao keeps its native API and protocol. The shared Codestra control plane in `appolon1908-hue/Codestra-Telemetry` performs only sanitized health, readiness, contract, topology, and immutable-release read-back. It never proxies seal, leader, secret, identity, PKI, token, policy, transit, audit, initialization, unseal, or credential-issuance APIs.

Canonical hostname: `bao.codestra.media`
Native exposure: `private_strong_auth`
Deployment class: `central`
Contract: `codestra/api/service-contract.v1.json`
Authority map: `codestra/api/native-api-authority.v1.json`
Validator: `scripts/validate_codestra_service_contract.py`

The contract lists every native OpenBao operation this repository governs. The authority map binds each operation to its mount, governing ACL paths, capabilities, permitted caller classes and the repository evidence that proves the binding. The validator fails when the two files, the secret-engine and auth-method sources, the generated workload policies or this document disagree.

## Caller classes

| Caller class | Authentication | Authority |
| --- | --- | --- |
| `control-plane-readback` | private mTLS client certificate | `codestra/api/service-contract.v1.json#managementReadback` |
| `workload` | auth/jwt-codestra CEL role with bound audience openbao and a five-minute JWT lifetime | `config/workload-secret-authority.v1.json` |
| `service-runtime` | auth/jwt-codestra runtime roles under codestra/runtime-v1 | `codestra/runtime-v1/desired-state.json` |
| `operator` | auth/oidc with client openbao-secrets, PKCE S256 and MFA | `codestra/runtime-v1/oidc-plan.v1.json` |
| `auditor` | auth/oidc with the auditor policy | `codestra/runtime-v1/policies/auditor.hcl` |
| `platform-security` | bootstrap or ceremony token that is revoked after use; never a workload identity | `REPO_AUTHORITY.md` |

A workload identity holds read-only access to exactly one environment namespace beneath `codestra/` plus token self-management. It never holds write, credential-issuance, encryption, lease, policy or system capability. Every generated policy denies the other environments, `database/*`, `pki-*`, `transit-*`, `sys/*` and `auth/token/create*` explicitly; `sys/metrics` is granted to `prometheus-openbao` alone.

## Native operations

The table order is the contract order. `access` is the schema classification; the control-plane rule column is derived from the authority map.

### Status and topology

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/v1/sys/health` | health | read_only | HTTP status observed by the control plane; body discarded; never proxied |
| `GET` | `/v1/sys/health` | readiness | read_only | HTTP status observed by the control plane; body discarded; never proxied |
| `GET` | `/v1/sys/seal-status` | query | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/leader` | query | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/metrics` | metrics | read_only | granted to `prometheus-openbao`; never proxied |
| `GET` | `/v1/sys/storage/raft/configuration` | query | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/storage/raft/autopilot/state` | query | read_only | no workload grant; never proxied |

### Authentication and tokens

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `POST` | `/v1/auth/jwt-codestra/login` | authentication | mutation | secret-bearing response; unauthenticated path; granted to workload identities; never proxied |
| `POST` | `/v1/auth/oidc/oidc/auth_url` | authentication | query | unauthenticated path; no workload grant; never proxied |
| `GET` | `/v1/auth/oidc/oidc/callback` | authentication | mutation | secret-bearing response; unauthenticated path; no workload grant; never proxied |
| `GET` | `/v1/auth/token/lookup-self` | token | read_only | granted to workload identities; never proxied |
| `POST` | `/v1/auth/token/renew-self` | token | mutation | secret-bearing response; granted to workload identities; never proxied |
| `POST` | `/v1/auth/token/revoke-self` | token | mutation | granted to workload identities; never proxied |

### Versioned static secrets (`codestra/`)

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/v1/codestra/data/{environment}/{namespace}/{key}` | secret_read | read_only | secret-bearing response; granted to workload identities; never proxied |
| `GET` | `/v1/codestra/metadata/{environment}/{namespace}/{key}` | secret_metadata | read_only | granted to workload identities; never proxied |
| `GET` | `/v1/codestra/metadata/{environment}/{namespace}/?list=true` | secret_metadata | read_only | granted to workload identities; never proxied |
| `POST` | `/v1/codestra/data/{environment}/{namespace}/{key}` | secret_write | mutation | no workload grant; never proxied |
| `GET` | `/v1/codestra/config` | secret_metadata | read_only | no workload grant; never proxied |

### Dynamic credentials, certificates and encryption

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/v1/database/creds/{role}` | credential_issue | mutation | secret-bearing response; no workload grant; never proxied |
| `POST` | `/v1/pki-codestra/issue/{role}` | credential_issue | mutation | secret-bearing response; no workload grant; never proxied |
| `POST` | `/v1/transit-codestra/encrypt/{key}` | encryption | mutation | no workload grant; never proxied |
| `POST` | `/v1/transit-codestra/decrypt/{key}` | encryption | mutation | secret-bearing response; no workload grant; never proxied |
| `POST` | `/v1/transit-codestra/sign/{key}` | signing | mutation | no workload grant; never proxied |
| `POST` | `/v1/transit-codestra/verify/{key}` | signing | query | no workload grant; never proxied |

### Leases

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `PUT` | `/v1/sys/leases/renew` | lease | mutation | no workload grant; never proxied |
| `PUT` | `/v1/sys/leases/revoke` | lease | mutation | no workload grant; never proxied |

### Protected administration

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `POST` | `/v1/sys/init` | administration | mutation | secret-bearing response; no workload grant; never proxied |
| `POST` | `/v1/sys/unseal` | administration | mutation | no workload grant; never proxied |
| `GET` | `/v1/sys/storage/raft/snapshot` | backup | read_only | secret-bearing response; no workload grant; never proxied |
| `POST` | `/v1/sys/storage/raft/snapshot-force` | recovery | mutation | no workload grant; never proxied |
| `GET` | `/v1/sys/policies/acl/{name}` | administration | read_only | no workload grant; never proxied |
| `PUT` | `/v1/sys/policies/acl/{name}` | administration | mutation | no workload grant; never proxied |
| `GET` | `/v1/auth/jwt-codestra/config` | administration | read_only | no workload grant; never proxied |
| `POST` | `/v1/auth/jwt-codestra/config` | administration | mutation | no workload grant; never proxied |
| `GET` | `/v1/auth/jwt-codestra/cel/role/{name}` | administration | read_only | no workload grant; never proxied |
| `POST` | `/v1/auth/jwt-codestra/cel/role/{name}` | administration | mutation | no workload grant; never proxied |
| `GET` | `/v1/sys/mounts` | administration | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/auth` | administration | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/audit` | administration | read_only | no workload grant; never proxied |
| `GET` | `/v1/sys/plugins/catalog/auth/{name}` | administration | read_only | no workload grant; never proxied |

Health statuses `200`, `429`, `472`, and `473` indicate a reachable OpenBao node in documented active, standby, disaster-recovery, or performance-standby states. The control API reports only bounded state and status metadata and discards the native body.

`kv-metadata-list` is the HTTP form of the OpenBao `LIST` verb (`GET` with `?list=true`). `oidc-callback` is the direct-callback redirect target that the OpenBao JWT/OIDC backend registers at `oidc/callback` beneath the `oidc` mount; the browser UI uses `/ui/vault/auth/oidc/oidc/callback`.

The `database/`, `pki-codestra/` and `transit-codestra/` engines are prepared but disabled. Their operations are part of the governed surface so that admission rules exist before any consumer is proposed; today no caller other than the protected `platform-security` ceremony path may reach them and every generated workload policy denies them.

## Suite integrations

| Peer | Direction | Signal | Protocol | Purpose |
|---|---|---|---|---|
| `suite-workloads` | outbound | `identity-certificates-secrets` | `openbao-http-api` | issue policy-scoped short-lived runtime material |
| `prometheus` | outbound | `metrics` | `prometheus-scrape` | publish sanitized security and availability metrics |

Workload credentials must be short lived, policy scoped, delivered through mounted files or an approved agent, and never returned by the observability control API. Initialization, unseal, root-token generation, policy mutation, secret writes, and PKI issuance require the native OpenBao authorization path and independent production controls.

## Identity and correlation

Every private request should propagate `X-Correlation-ID` and W3C `traceparent` when the native protocol supports them. `request_id`, `trace_id`, and `tenant_id` remain structured, protected, non-indexed fields. Metrics use only the bounded dimensions `codestra_business`, `application`, `service`, `environment`, `server`, `region`, and `deployment`.

Business identity is deployment-controlled. Caller-supplied business identity, cross-business defaults, anonymous management access, insecure TLS verification, inline tokens, inline unseal keys, and inline root credentials are prohibited.

## Release and runtime boundary

The control plane reads source revision and image digest only from deployment environment variables. A valid release requires a 40-character Git SHA and `sha256:<64 lowercase hex>` image digest. This source change does not initialize, unseal, configure, deploy, expose, authenticate to, write to, or issue credentials from OpenBao; it does not activate metrics scraping or any business mutation.

## Contract authority handoff

- Canonical schema repository: `appolon1908-hue/Codestra-Telemetry`
- Canonical merged Telemetry SHA: `c35d880a730ca5206d445e8a9a688cb465ae2ad4`
- Contract version: `1.0.0`
- Downstream exact head: this PR branch commit; the authoritative literal SHA is the GitHub PR `headRefOid` recorded after this handoff commit.
- Deployment authorization: unauthorized until staging certification and protected production promotion are complete.
