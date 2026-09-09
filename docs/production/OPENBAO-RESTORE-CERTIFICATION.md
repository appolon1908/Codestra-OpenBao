# OpenBao restore certification

Certification date: 2026-09-01

| Evidence | Status | Basis |
| --- | --- | --- |
| Encrypted Raft snapshot | FAIL | no runtime snapshot evidence |
| Local protected copy | FAIL | no scheduled production artifact observed |
| Immutable off-host copy | FAIL | no storage attestation or read-back evidence |
| Independent checksum | FAIL | no production snapshot checksum evidence |
| Isolated target exclusion | PASS | source automation refuses production and same-cluster targets |
| Snapshot restore | FAIL | no completed isolated restore run |
| Unseal/recovery | FAIL | no protected runtime custody evidence available to this run |
| Policy/auth/mount metadata | FAIL | no restored runtime read-back |
| Representative secret hash | FAIL | no non-production restore probe evidence |
| Audit/telemetry after restore | FAIL | no restored runtime evidence |
| RPO | FAIL | no measured snapshot age |
| RTO | FAIL | no measured restore duration |

`RESTORE_CERTIFIED=NO`

The guarded workflow and scripts are source-valid, but source preparation is
not recovery evidence. Production certification remains blocked until a real
production-compatible snapshot is restored on an isolated target and all rows
above pass without exposing a secret value.
