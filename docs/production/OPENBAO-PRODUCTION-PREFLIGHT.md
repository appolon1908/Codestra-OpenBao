# OpenBao production preflight

Read-only observation time: `2026-09-01T18:21:23Z`

Host: `37.27.128.39` (`bao.codestra.media`)

No runtime, network, firewall or SSH mutation was performed during this
read-back.

| Item | Observed state | Result |
| --- | --- | --- |
| OpenBao version | v2.6.1, source `ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f` | FAIL: desired v2.6.2 differs |
| Image | linux/amd64 `ghcr.io/openbao/openbao@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0` | FAIL: desired digest differs |
| Initialized | `false` | FAIL |
| Sealed | `true` | FAIL; expected for uninitialized bootstrap |
| Cluster ID | absent | FAIL |
| Configured node ID | `codestra-openbao-1` | WARNING: differs from desired node identity |
| Storage | integrated Raft at `/opt/codestra-openbao/data` | WARNING: configured but uninitialized |
| Raft peers/quorum | none / one intended container | FAIL |
| Listener | container cleartext 8200, mapped only to `127.0.0.1:18200`; 8201 not host-published | FAIL native TLS/mTLS; PASS no public native port |
| Public TLS | valid certificate for `bao.codestra.media`; TLS 1.3 handshake succeeds | WARNING: edge is Nginx, not required Caddy authority |
| Auth methods | unavailable on uninitialized cluster | FAIL |
| Secret engines | unavailable on uninitialized cluster | FAIL |
| Audit devices | no audit file/device evidence | FAIL |
| Policies/mounts | unavailable on uninitialized cluster | FAIL |
| Container hardening | read-only root, all capabilities dropped, no-new-privileges | PASS |
| Runtime networks | one non-internal bridge `codestra-openbao_openbao_private` | FAIL: desired three private network boundaries absent |
| Data volume | host bind `/opt/codestra-openbao/data`, mode 0700; Raft DB mode 0600 | WARNING: persistent but not backup-certified |
| Swap | active 32 GiB `/dev/md0`, non-crypt block type | FAIL |
| Backup age/timer | no OpenBao/Raft backup timer observed | FAIL |
| Prometheus | no active OpenBao target in current Prometheus | FAIL |
| Audit shipping | no Alloy or Loki runtime observed for OpenBao | FAIL |
| Source label | absent from container | FAIL |
| Desired voting nodes | 3; observed usable voters 0 | FAIL |
| SSH | normalized files, effective config and exact port-22 firewall rules stable | PASS |

The existing Raft files must be preserved. Even though the health endpoint says
uninitialized, production initialization is prohibited until exact immutable
source, three-node topology or an explicit HA exception, recovery custody,
encrypted/disabled swap, protected backup storage, edge handoff and staging
certification are approved.

`PRECHANGE_BACKUP=FAIL`; no production mutation is authorized.
