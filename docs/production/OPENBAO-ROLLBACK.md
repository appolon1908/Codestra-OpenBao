# OpenBao rollback

Rollback never reinitializes OpenBao, deletes a Raft volume, replaces recovery
material, disables audit or restores a snapshot over production merely because
desired source differs.

## Required package

The immutable release bundle contains exact source, manifest, authority hashes,
SBOM/vulnerability identities, staging/recovery evidence and a checksum. The
bundle is keyless-signed and receives GitHub build provenance. Production
deployment records the previous image digest, source label, Compose/systemd
definition, config checksum, volume identity and fresh off-host snapshot.

The runtime deployer retains the stopped previous container under a
timestamped `-rollback-` name and retains every SHA-named configuration/plugin
directory. It does not delete either copy. Promotion evidence must record that
container name before any rollback is authorized.

## Runtime rollback

1. Stop further promotion and consumer migration.
2. Preserve sanitized failure evidence and confirm Raft quorum.
3. Verify the pre-change snapshot and previous immutable image/config hashes.
4. Roll one voter at a time to the previous exact image and configuration,
   retaining its existing Raft data directory.
5. Confirm leader, peer catch-up, unsealed state, TLS/mTLS, audit and metrics
   after each node.
6. Revert consumers individually to their prior secret version/authority.
7. Prove SSH and provider kill switches are unchanged.

Control-plane policy rollback is a new reviewed, checksummed, non-destructive
plan. The saved forward plan is never edited. Destructive policy/mount removal
requires separate approval and is unsupported by `scripts/apply.sh`.

## Current previous runtime record

The observed bootstrap image is
`ghcr.io/openbao/openbao@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`
(OpenBao v2.6.1). It is not itself certified and must not be treated as a safe
rollback release without compatibility and vulnerability review. No production
rollback drill has passed, so `ROLLBACK=FAIL`.
