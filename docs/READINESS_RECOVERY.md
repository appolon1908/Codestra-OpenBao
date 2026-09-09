# OpenBao readiness recovery

On September 9, 37.27.128.39 returned HTTP 501 from the native health API:
`initialized:false`, `sealed:true`. Docker still reported healthy because the
legacy check overrides both failure codes to 200. This is an uninitialized
cluster, not a lost-unseal-key diagnosis. No initialization or unseal occurred.

`deploy/compose/compose.legacy-readiness.yaml` is a narrow correction for the
inventoried `/opt/codestra-openbao/compose.yaml` loopback HTTP deployment. It
removes those overrides while retaining standby support. Validate the merged
configuration, preserve the current manifest and digest, and recreate only the
OpenBao service through the authorized host deployment path. Keep the exact
existing data/config mounts and image. The health state should then become
unhealthy until initialization and unseal are complete. This correction does
not initialize the cluster or enable clients.

Do not apply this legacy overlay to a native mTLS deployment. The current
development Compose authority already uses `bao status` with a client
certificate. Promotion to that full authority is a separate exact-image,
configuration, PKI, and restore-verified release.

Pipe `bao status -format=json` or the native health response into
`python3 scripts/readiness_status.py` for a sanitized readiness result. Status
returns exit 1 for uninitialized, sealed, malformed, or contradictory input.
It does not accept Docker health as evidence, and a ready process does not
claim verified policies or backups. The textfile exporter now rejects malformed
status fields, and missing/stale status exports fire a separate critical alert.

For a genuinely new cluster, use the existing `scripts/initialize.sh` only
after the designated operators establish protected offline custody. It
requires an exact environment confirmation, a non-temporary custody path, and
acknowledgement of custody. Do not generate root/recovery material in chat or
ordinary deployment logs. Existing initialization, unseal, policy, backup,
restore and exact-image release gates remain in force.

The current SentinelX identity cannot write the root-owned runtime manifest,
and sudo is blocked by its no-new-privileges policy. An authorized host
deployment/operator session is required to apply this reviewed correction.
No production changes are claimed. Evidence is in
`docs/evidence/provider-recovery-20260909.json`.
