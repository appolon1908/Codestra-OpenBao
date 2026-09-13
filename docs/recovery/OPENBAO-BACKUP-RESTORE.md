# OpenBao backup and restore

The implemented Raft backup path creates a snapshot, verifies it, encrypts it
with age X25519, independently decrypts and inspects it, stores a mode-`0400`
local copy, writes a SHA-256, and copies both objects to an immutable rclone
destination. The destination must attest object lock and at least 30 days of
retention. Daily, weekly and monthly targets are 30/12/12; RPO is 24 hours and
RTO is four hours.

`scripts/backup.sh` never prints or uploads snapshot data. GitHub may retain
only sanitized backup metadata. A snapshot command without local artifact,
checksum, decrypt/inspect proof and off-host read-back is not a passing backup.
`scheduled-backup.yml` is the daily 02:17 UTC production trigger after final
promotion; its environment is restricted to `main`, it checks out and verifies
the exact `production` branch, and it artifacts only the sanitized evidence
JSON.

## Isolated restore

`backup-restore-test.yml` moves the encrypted artifact directly from off-host
storage to a dedicated restore runner; GitHub artifacts never transport it.
`scripts/restore-test.sh` requires:

- a non-production target address identifying an already isolated cluster;
- a target cluster ID different from the source/production cluster;
- explicit isolated-restore acknowledgement;
- protected age identity and unseal shares;
- checksum and snapshot inspection;
- a representative non-production secret hash; and
- measured restore duration.

The restore forcibly loads the snapshot only after those exclusion checks and
unseals from protected files. The token that authorized the destructive load is
then discarded because the restored snapshot replaces the target token store.
It is never reused for post-restore certification.

### Restored probe credential

The protected restore environment must provide:

- `OPENBAO_RESTORED_PROBE_TOKEN_FILE`, pointing to a regular, non-symlinked,
  non-repository file with no group or world permissions; and
- `OPENBAO_RESTORED_PROBE_EXPECTED_POLICY`, naming the token's one exact
  read-only policy.

The token must have been created before the source snapshot, must therefore be
contained in the restored token store, and must be held outside Git and outside
GitHub artifacts. It must differ from the pre-restore operator token, carry
exactly the expected policy with no `default` or `root` policy, be
non-renewable, and retain a positive TTL at certification time.

After unseal, the script authenticates with this bounded credential, verifies
its policy through token lookup, validates the representative secret hash
without printing the value, revokes the token, and proves the revoked token can
no longer authenticate. Sanitized evidence records only that the credential
was distinct, its policy-name hash, and successful revocation; it never records
the token, accessor, secret value, or policy body.

## Current evidence

No scheduled production backup run, protected immutable off-host destination
attestation or successful isolated restore evidence was observed on 2026-09-01.
Therefore `BACKUP=FAIL`, `OFFHOST_BACKUP=FAIL`, `RESTORE=FAIL`, `RPO=FAIL` and
`RTO=FAIL`. The scheduled source is prepared; the runtime gates have not passed.
