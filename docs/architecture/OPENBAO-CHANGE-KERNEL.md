# OpenBao change kernel

The change kernel (`codestra/change_kernel`) is the one path from a reviewed
saved plan to an OpenBao mutation. It does not replace the saved-plan,
approval or runtime workflows; it sits underneath them and makes them share
one lock, one actuator and one audit trail.

## What it guarantees

- **One actuator.** Only `codestra/change_kernel/actuator.py` issues plan
  mutations (`plugin register`, `secrets enable`, `auth enable`,
  `policy write`, `write`). `scripts/apply.sh` delegates to it. A test fails
  if any other script or workflow issues OpenBao mutation commands outside a
  short, justified allow-list.
- **One lock per cluster.** The lock key is resolved on the server from
  `config/environments/<env>/environment.json`
  (`openbao:<environment>:<cluster host>`). Every acquisition increments a
  fence token; only the newest token may act, and only the holder with that
  token may release.
- **Nothing happens without a recorded intent.** Before each OpenBao call the
  kernel re-checks the fence and persists a dispatch intent in one
  transaction. Only readback confirms an operation. A crash, timeout or
  accepted call that does not read back becomes UNKNOWN, and the change moves
  to RECONCILIATION_REQUIRED until readback resolves it. Nothing is resent
  blindly.
- **The exact reviewed plan.** A change binds the plan digest, source SHA,
  authority checksums, live-state fingerprint, tenant, environment,
  authorization digest and production gate. Execution refuses if any of them
  changed, if the approval expired, or if the runtime gate is closed.
- **Idempotency.** Tenant, `Idempotency-Key` and request fingerprint return the
  same change, or `409 IDEMPOTENCY_CONFLICT`.
- **No secret values.** Records reject secret-named fields and secret-shaped
  values. Plans carry policy text and configuration, never secret values.

OpenBao does not enforce a custom fence. A process that passed the check can
still finish one in-flight call after its lease expires. The lease length
bounds that window, and the unresolved intent forces reconciliation.

## Lifecycle

```text
plan.sh (records liveStateSha256) -> review -> approval
apply.sh: require_mutation_lease -> collect_live_state -> submit -> approve
       -> actuator: begin_attempt (revalidate) -> per operation:
          readback? -> fenced intent -> bao call -> readback -> resolve
       -> SUCCEEDED | RETRY | RECONCILIATION_REQUIRED | DEAD_LETTER
```

## Workflow and script locking

Seven mutation workflows share the concurrency group
`openbao-<environment>-mutation` with `cancel-in-progress: false`. Each
acquires the durable lease before its first effect step and releases it in an
`always()` step. GitHub concurrency alone does not stop manual runs or other
repositories, so `scripts/require_mutation_lease.sh` runs immediately before
the first effect in backup, runtime deploy, rollback, initialization,
rotation, revocation and saved-plan apply.

Plan and drift jobs take no lease. Drift records the lease state before and
after observing and reports `OPENBAO_DRIFT=INCONSISTENT`, leaving the drift
metric unchanged, when a lease is held or its state cannot be read.

## Runner configuration required before use

| Setting | Purpose |
| --- | --- |
| `vars.OPENBAO_CHANGE_KERNEL_DATABASE_URL` | Durable store shared by every workflow that can touch one cluster: `postgresql://…` (psycopg 3) or `sqlite:////protected/path/kernel.db` for a single runner host |

Without it, mutation workflows fail closed at lease acquisition, and drift
reports INCONSISTENT. Runtime application also stays blocked while any
`runtimeApplyAuthorized` flag is false.

## Commands

```bash
python3 -m codestra.change_kernel.cli lock-status --environment staging
python3 -m codestra.change_kernel.cli status --change-id chg_...
python3 -m codestra.change_kernel.cli reconcile --change-id chg_... --evidence-ref <run>
python3 -m codestra.change_kernel.cli metrics --environment staging --output openbao_v3.prom
```

## Not covered here

Tenant, project and consumer metadata belong to the management-plane
control-plane lane and are recorded by the kernel only as opaque identifiers.
PKI, transit, database roles, rotation, cluster and custody changes are
classified but not executable by the kernel; they remain protected workflows
or human ceremonies.
