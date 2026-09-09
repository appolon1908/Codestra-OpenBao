# OpenBao rotation and revocation

Each credential family has one owner. Static credentials have a maximum age of
90 days; shorter provider limits win. Dynamic database credentials use their
engine lease limits. Rotation evidence contains version numbers, hashes,
accessors and timestamps only.

## Static KV v2 rotation

1. Confirm the consumer, exact environment/path and rollback owner.
2. Write version N+1 using CAS against the observed metadata version.
3. Wait for atomic agent render to a service-owned `0400` file.
4. Reload the consumer without putting the value in an environment variable.
5. Prove N+1 works with external effects disabled.
6. Revoke N at the provider after the overlap window.
7. Prove N fails and the service remains healthy.
8. Record audit metadata and monitoring status.

Rollback restores the previous KV metadata version only while the provider
credential remains valid. Destroy is a separate protected operation and is not
part of ordinary rotation.

## Dynamic credentials

The consumer must renew before lease expiry and revoke on shutdown. Rotate the
database engine root credential through the reviewed root-rotation operation,
then issue a test lease, verify bounded database privileges, revoke it and prove
login failure. Stable application accounts are not replaced without staged
compatibility evidence.

## Identity revocation

Disable or revoke the exact Keycloak client identity, revoke all OpenBao token
accessors and dynamic child leases for that identity, then prove:

- the target workload loses access;
- other workloads remain healthy;
- staging cannot read production;
- no provider write occurs; and
- denial and revocation audit alerts fire.

Rotation and revocation are currently source-defined but not runtime-certified;
their production certification state is `FAIL` until development, test and
staging evidence exists.

The file-render contract is generated per exact secret object. For example,
the following prepares a secret-free staging bundle; it does not authenticate
or read the secret:

```bash
scripts/render_agent_config.py \
  --environment staging \
  --identity kong-gateway \
  --secret-path codestra/staging/kong/runtime \
  --destination /run/codestra-secrets/kong-gateway/runtime.json \
  --service-uid 10001 \
  --service-gid 10001 \
  --output-dir /protected/release/agent-kong-staging
```

The consumer deployment must run the Agent as that UID/GID, pre-create the
destination directory for only that service, and mount the JWT and TLS files
read-only. The application starts only after the `0400` destination exists.
