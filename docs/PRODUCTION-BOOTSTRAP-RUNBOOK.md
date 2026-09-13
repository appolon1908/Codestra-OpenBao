# Production OpenBao bootstrap runbook

## Safety boundary

OpenBao is initialized once with three PGP-encrypted Shamir shares and a threshold of two. The initial root token is also PGP-encrypted. Private keys, decrypted shares, and decrypted tokens never enter Git, CI, tickets, chat, terminal recording, or shared storage.

## Custody prerequisites

Prepare four public PGP keys:

- custodian-1.pgp
- custodian-2.pgp
- custodian-3.pgp
- root-token.pgp, held separately from the server operator

Record each custodian identity and fingerprint in the change record. Each custodian independently retains their private key.

## Deploy

1. Check out an approved immutable commit.
2. Copy deploy/compose.yaml, config/openbao.hcl, scripts, and policies to the host.
3. Preserve the existing Raft data volume. Never replace or delete it during an upgrade.
4. Run `docker compose -f deploy/compose.yaml config`.
5. Start the service and run `scripts/verify-deployment.sh`.

## Initialize and unseal

Run `scripts/init-2of3.sh` only once, with a new OUTPUT_DIR. Distribute encrypted shares separately. Two custodians decrypt their own share locally and submit it directly through a protected operator session. Do not paste shares into chat or save them in shell history.

Decrypt the initial root token only for bootstrap. Configure the audit device, KV v2 mount, policies, and workload authentication, then revoke the initial root token. Day-to-day administration uses short-lived named identities.

## Production namespaces

- codestra/production/middleware
- codestra/production/odoo
- codestra/production/telnexa
- codestra/production/klyrow
- codestra/production/vicidial

Service identities are denied cross-service and cross-environment reads. Secret values are written out-of-band through audited operator sessions.

## Acceptance

- Native port 8200 is not publicly reachable.
- Public edge uses TLS and strong authentication.
- Audit records are durable and contain no raw secret values.
- Restart leaves the cluster sealed until two custodians participate, unless an independently approved auto-unseal design replaces Shamir custody.
- Each workload reads only its exact production prefix with a short-lived identity.
- Root token is revoked after bootstrap.
