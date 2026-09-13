# OpenBao architecture

## Intended production topology

```text
administrative browser -> authenticated Caddy edge -> private OpenBao client network
Keycloak workload JWT  -> replay-protected auth plugin -> scoped token/lease
OpenBao Agent          -> atomic service-owned file -> workload
three OpenBao voters   -> private 8201 Raft network
OpenBao audit file     -> Alloy -> Loki -> Grafana
OpenBao metrics        -> private mTLS Prometheus -> Grafana/alerts
Raft snapshot          -> age encryption -> protected local + immutable off-host copy
```

The public edge must not expose native port 8200, Raft port 8201, unauthenticated
metrics, initialization or recovery operations. This repository owns the
OpenBao-side contract but not the edge deployment.

## Desired nodes and networks

| Environment | Voting nodes | Client network | Raft network | Observability network |
| --- | ---: | --- | --- | --- |
| development | 1 | `codestra-security-development` | `codestra-openbao-cluster-development` | `codestra-observability-development` |
| test | 1 | `codestra-security-test` | `codestra-openbao-cluster-test` | `codestra-observability-test` |
| staging | 3 | `codestra-security-staging` | `codestra-openbao-cluster-staging` | `codestra-observability-staging` |
| production | 3 | `codestra-security-production` | `codestra-openbao-cluster-production` | `codestra-observability-production` |

All networks are external deployment inputs. Compose publishes no host port.
TLS 1.3 and client-certificate verification are enforced on the native API;
8201 is private to Raft peers.

The server image remains the exact official digest. The separately built,
SBOM-scanned `codestra-jwt-replay` binary is mounted read-only under
`/openbao/plugins`, registered by exact version and checksum, and read back
before authentication is certified.

## Storage and seal model

Integrated Raft is the only configured storage backend. Source never deletes,
reinitializes or replaces Raft state. Production certification requires three
voters and tested quorum behavior. Seal/recovery custody is deliberately
external to Git and GitHub artifacts. Until an approved automatic-seal
authority exists, five Shamir shares with a three-share threshold are written
once to protected offline custody by the guarded initializer.

## Observed production divergence (2026-09-01)

Production currently has one OpenBao v2.6.1 container, one non-internal Docker
bridge, a loopback host mapping `127.0.0.1:18200 -> 8200`, cleartext container
listener, no initialized cluster and no Raft quorum. Nginx currently serves
`bao.codestra.media`; Caddy is not the observed edge. These facts are recorded
as blockers, not accepted as the target architecture.
