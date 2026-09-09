# OpenBao disaster recovery

All recovery actions start with source/runtime identity, quorum and backup
read-back. No scenario authorizes production reinitialization.

| Scenario | Expected/fail-safe state and alert | Recovery and rollback |
| --- | --- | --- |
| Server loss | quorum remains with two of three voters; leader/peer alerts | replace node from immutable image, join as new peer, verify catch-up; remove dead peer only after review |
| Container loss | data and custody remain; restart alert | pull exact digest and reuse existing data/config; roll back to prior digest without replacing data |
| Volume corruption | node leaves service; storage alert | quarantine node, restore only to isolated/new target or rebuild follower; never overwrite healthy quorum |
| One Raft peer lost | two voters retain quorum; peer-count alert | repair/rejoin one node at a time; roll back its runtime definition |
| Network partition | minority fails closed; leader-change alert | restore private network, verify one leader and peer health before traffic |
| TLS failure | clients fail closed; certificate alert | restore prior protected certificate files and chain; do not enable cleartext |
| Keycloak unavailable | new workload login fails; existing bounded tokens expire | restore Keycloak; do not issue broad static tokens |
| OpenBao sealed | secret access stops; sealed alert | use approved unseal/auto-seal recovery custody; never initialize |
| Audit unavailable | protected operations fail closed; audit alert | restore protected audit path/shipping; do not disable the audit device as a workaround |
| Backup unavailable | deployment blocked; backup age/failure alert | repair local/off-host path and prove checksum/read-back before mutation |
| Rotation failure | retain overlap credential; rotation alert | roll back consumer to N, repair N+1, avoid premature N revocation |
| Expired/revoked identity | target workload denied; auth/denial alert | renew or re-authorize only exact identity; unrelated workloads stay online |
| Corrupt configuration | startup fails before serving; config/drift alert | restore exact prior checksummed config and image; retain Raft volume |

Network partition, peer loss, corruption, restore and RTO/RPO drills have not
yet run on a production-equivalent three-node staging cluster. Disaster
recovery certification is therefore `FAIL`, not assumed from this runbook.
