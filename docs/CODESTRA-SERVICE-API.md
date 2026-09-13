# Codestra service API contract: OpenBao

This repository owns the **secrets-pki-workload-identity-authority** for the Codestra observability, analytics, telemetry, and secrets suite.

## Communication rule

OpenBao keeps its native API and protocol. The shared Codestra control plane in `appolon1908-hue/Codestra-Telemetry` performs only sanitized health, readiness, contract, topology, and immutable-release read-back. It never proxies seal, leader, secret, identity, PKI, token, policy, transit, audit, initialization, unseal, or credential-issuance APIs.

Canonical hostname: `bao.codestra.media`
Native exposure: `private_strong_auth`
Deployment class: `central`
Contract: `codestra/api/service-contract.v1.json`

## Native operations

| Method | Path | Category | Access | Control-plane rule |
|---|---|---|---|---|
| `GET` | `/v1/sys/health` | health | read_only | body discarded; never proxied |
| `GET` | `/v1/sys/health` | readiness | read_only | body discarded; never proxied |
| `GET` | `/v1/sys/seal-status` | query | read_only | never proxied by the Codestra control API |
| `GET` | `/v1/sys/leader` | query | read_only | never proxied by the Codestra control API |
| `GET` | `/v1/sys/metrics` | metrics | read_only | never proxied by the Codestra control API |
| `POST` | `/v1/{mount}/issue/{role}` | credential_issue | mutation | native policy-scoped workflow only; never proxied |

Health statuses `200`, `429`, `472`, and `473` indicate a reachable OpenBao node in documented active, standby, disaster-recovery, or performance-standby states. The control API reports only bounded state and status metadata and discards the native body.

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
