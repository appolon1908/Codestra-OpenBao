# OpenBao production certification

Assessment date: 2026-09-01

| Category | Status | Evidence |
| --- | --- | --- |
| Repository authority | WARNING | remediation evidence SHA `6bb2e306bd65e0f1219993d311b7092de9a99530` passed all eleven exact-head required contexts; protected promotion is blocked on independent review and source is not yet promoted |
| Upstream provenance | PASS | exact v2.6.2 tag commit and image identity verified |
| Image immutability | PASS | desired source uses exact linux/amd64 manifest digest only |
| SBOM | PASS | image and replay-plugin CycloneDX inventories regenerated and matched |
| Provenance | FAIL | protected release attestation has not run |
| Vulnerability gate | PASS | image has zero unresolved exploitable HIGH/CRITICAL under expiring VEX; plugin has zero observed HIGH/CRITICAL |
| Secret scan | PASS | working tree and full Git history clean |
| HCL/config validation | PASS | semantic server startup and policy format tests pass |
| TLS | FAIL | desired TLS 1.3 source exists; live native listener is cleartext |
| mTLS | FAIL | desired client-certificate enforcement is not live |
| Storage | WARNING | live integrated Raft files exist but cluster is uninitialized |
| Raft health | FAIL | no initialized cluster/peer list |
| HA | FAIL | desired three voters; live bootstrap has one container |
| Initialization safety | PASS | only guarded initializer exists and refuses initialized/ambiguous state |
| Seal/recovery | FAIL | runtime custody and restart proof absent |
| Keycloak authentication | FAIL | source roles and replay plugin pass isolated positive/negative tests; live authentication not configured |
| Audience validation | FAIL | source tested; live negative test absent |
| Environment isolation | FAIL | source tested; live cross-environment denial absent |
| Policy least privilege | PASS | generated exact policies and negative source tests pass |
| KV security | FAIL | source plans and reads back CAS, version retention and deletion policy; live KV v2 is not configured |
| Dynamic credentials | N/A | no compatible consumer has been authorized for migration |
| Lease renewal | FAIL | no runtime consumer evidence |
| Rotation | FAIL | no staged N/N+1 runtime evidence |
| Revocation | FAIL | no runtime identity/lease revocation evidence |
| Audit device | FAIL | no live audit device |
| Audit shipping | FAIL | no OpenBao Alloy/Loki pipeline observed |
| Metrics | FAIL | no active OpenBao Prometheus target |
| Alerts | FAIL | source rules validate; live alert evaluation absent |
| Backup | FAIL | no scheduled verified production snapshot |
| Off-host backup | FAIL | no immutable storage evidence |
| Restore | FAIL | isolated restore has not run |
| RPO | FAIL | no measurement |
| RTO | FAIL | no measurement |
| Disaster recovery | FAIL | required drills have not run |
| Drift detection | WARNING | read-only workflow exists but private runner/runtime evidence absent |
| Consumer integration | FAIL | no workload is migrated/certified |
| Staging certification | FAIL | no production-equivalent staging evidence |
| Rollback | FAIL | package workflow exists; runtime rollback drill absent |
| Production read-back | FAIL | live source/image/config do not match desired authority |
| SSH unchanged | PASS | normalized before/after SSH files, effective config and port-22 rules match |

Open critical issues: 6

1. Production-equivalent three-voter staging and production HA are unavailable.
2. Production has active unencrypted swap.
3. Backup, immutable off-host storage and isolated restore evidence are absent.
4. Live native TLS/mTLS, Keycloak auth, audit and observability do not match desired source.
5. Protected environment reviewer `@kazan555` is pending collaborator
   acceptance; environment variables/private runners and promotions are not
   complete. Promotion-branch protections and exact branch policies are active.
6. The live uninitialized v2.6.1 bootstrap differs from the desired immutable
   v2.6.2 release and the observed edge is Nginx rather than required Caddy.

`OVERALL_VERDICT=NO_GO`
