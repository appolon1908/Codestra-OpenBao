# OpenBao operations

## Routine read-only checks

Use mTLS and a short-lived operator or observer token from a protected local
file. Never pass a secret on the command line or enable shell tracing.

```bash
bao status -format=json
bao operator raft list-peers -format=json
bao audit list -format=json
bao auth list -format=json
bao secrets list -format=json
scripts/drift.sh
scripts/verify.sh
```

Evidence must omit token values, secret values, private keys and unseal shares.

## Initialization and unseal

Initialization is a one-time custody operation. First confirm the exact target,
empty/new storage, `initialized=false`, protected offline destination and human
authorization. `scripts/initialize.sh` is the only implementation and refuses
initialized or ambiguous state. Its JSON output goes directly to offline
custody and is never logged or uploaded.

Unseal shares are read from distinct protected files by
`scripts/unseal_from_files.py`; only the number submitted is printed. Never
reinitialize, replace recovery material or reset Raft to resolve drift.

## Plan and apply

1. Promote and validate the exact environment branch.
2. Run the protected `plan.yml` workflow on a private runner.
3. Inspect the sanitized plan and its SHA-256. Destruction or warnings block
   apply.
4. Dispatch the matching `deploy-<environment>.yml` with exact source SHA, plan
   run ID, plan hash and confirmation.
5. Obtain protected-environment approval from `@kazan555`.
6. Preflight exact image/source/HA/network/memory state.
7. Take and verify encrypted local and immutable off-host Raft snapshots.
8. Apply only the downloaded saved plan; never regenerate it during apply.
9. Read back every operation, runtime identity and SSH hash baseline.

Apply supports only exact-checksum registration of the replay-protected JWT
plugin, creation of its auth mount, and creation/update of the reviewed KV v2
engine, CEL roles and policies. The file audit device is declarative server
configuration because OpenBao 2.6 rejects API audit creation by default; a
missing or drifted live device blocks the plan. Delete, plugin-version
overwrite, mount replacement, API audit mutation and initialization are
unsupported.

## Runtime image deployment

Runtime installation is a separate protected workflow and never occurs inside
saved-plan apply. Outside production, `runtime-deploy.yml` accepts only the
exact current environment SHA and plugin artifact from a successful
image-authority run whose `head_sha` matches. Production instead requires the
exact immutable GitHub release whose tag resolves to the current production
SHA; it downloads all release assets, verifies the asset checksum and Sigstore
workflow identity, validates the internal checksum manifest and release
manifest, and takes the plugin only from that signed bundle.
`scripts/deploy_runtime.sh` then:

1. verifies runtime authority and the `@kazan555` environment approval;
2. validates exact image/plugin digests, TLS/mTLS chains, SANs, certificate
   purposes, validity and key matches, file ownership/private-key modes,
   external networks, and writable Raft/audit directory ownership;
3. requires an immediate encrypted immutable off-host snapshot whenever state
   exists, and always in production;
4. renders an immutable SHA-named configuration without overwriting a previous
   release;
5. stops and renames the previous container instead of deleting it;
6. starts the exact image with no build and no host port publication; and
7. reads back labels, read-only root, port bindings and SSH state.

No Raft directory, Docker volume, recovery material or prior container is
deleted. The workflow is currently fail-closed because runtime authorization is
false and required protected-environment review is not installed.

## Shutdown and restart

Before a planned restart, verify a current off-host snapshot, healthy Raft
quorum and recovery custody. Restart one voter at a time. Confirm leader,
peers, unsealed state, audit, metrics and workload renewals before proceeding.
Dynamic consumers must revoke child leases on shutdown.

The Prometheus rules cover sealed/uninitialized state, leader and Raft quorum,
token creation, lease failures, restart loops, capacity, backup age/failure,
credential expiry, rotation/revocation and drift. The companion Loki ruler file
evaluates sanitized JSON audit metadata for stream silence, root-token use,
denial/authentication surges, initialization failures and policy/control-plane
mutations. Runtime alerting remains FAIL until both rule groups are loaded and
firing-path tests reach the configured Alertmanager.

## Scheduled backup and certification

After final promotion, `scheduled-backup.yml` runs daily at 02:17 UTC from
`main`, checks out the exact `production` authority, encrypts and verifies a
Raft snapshot, and copies it with immutable semantics to the attested off-host
remote. Only sanitized metadata evidence is uploaded to GitHub.

`runtime-certification.yml` is non-production and approval-gated. It executes
the owner-provided read-only/verifier callbacks through `rotate-test.sh` and
`revoke-test.sh`; callback output is suppressed. A PASS requires CAS N→N+1,
`0400` Agent refresh under the service UID/GID, new credential success, old
credential revocation and failure, target identity denial, unrelated workload
health, cross-environment denial and the sanitized audit alert.

## Incidents

Seal state, audit failure, unavailable leader, auth surge, denial surge,
rotation/revocation failure, backup age and drift page the platform-security
owner. Preserve logs and sanitized accessors; never paste credentials into an
incident channel.

The current production container is uninitialized and must not be initialized
until the production release, HA, custody and preflight gates are satisfied.
