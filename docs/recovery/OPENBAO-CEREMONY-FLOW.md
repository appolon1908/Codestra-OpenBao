# Initialization and unseal flow

`scripts/initialize.sh` remains the only initialization entry point. A merge
does not authorize a ceremony or a runtime change. Apply the source, runtime,
protected-environment approval, PKI, memory protection and offline-custodian
requirements in `REPO_AUTHORITY.md` and the recovery runbook first.

## Before initialization

The operator provisions an existing persistent custody parent directory owned
by the execution user with mode `0700`. Its path must be absolute, outside the
checkout and temporary directories, with no symbolic components. The script
does not create or change permissions on that parent. Set
`OPENBAO_INIT_CUSTODY_DIR` to a new child directory for this ceremony.

Provide five colon-separated absolute public-key paths through
`OPENBAO_UNSEAL_PGP_KEY_FILES` and a sixth through
`OPENBAO_ROOT_TOKEN_PGP_KEY_FILE`. Each file must contain exactly one public
primary key and no private material. All six primary fingerprints must be
distinct; separate files containing the same key do not satisfy custody.
Paths cannot contain commas, colons or control characters. Obtain the actual
public keys and acknowledgements from the authorized custodians offline.

Set `CODESTRA_ENVIRONMENT`, the matching
`INITIALIZE_NEW_<ENVIRONMENT>_CLUSTER` confirmation, and the independently
established `OPENBAO_OFFLINE_CUSTODY_ACKNOWLEDGED=true`. A workflow must obtain
the acknowledgement from protected configuration; it must not invent one.
`OPENBAO_INIT_RAM_ROOT` defaults to `/dev/shm` and must be writable tmpfs or
ramfs. That filesystem check does not replace the host memory/swap gate.

`python3 scripts/initialization_preflight.py` validates paths without contacting
OpenBao, creating files or changing permissions. The initializer then checks
scratch storage, reads server status, validates complete GPG key metadata,
and requests PGP-encrypted 3-of-5 shares and an encrypted initial root token
once. Missing, ambiguous or already-initialized status stops the flow.

## Completion and failure handling

Successful initialization exports five encrypted share files, the encrypted
root-token file, a public-fingerprint manifest and checksums into the private
custody directory. Files become `0400`; the filesystem is synced before the
encrypted RAM response is removed. Only sanitized success markers are printed.

If initialization was attempted and a nonempty response exists but export,
validation or persistence fails, the command exits unsuccessfully with
`OPENBAO_CUSTODY_EXPORT=INCOMPLETE RAM_BUFFER_RETAINED=YES DO_NOT_REINITIALIZE`.
The encrypted response remains in the execution user's private `0700`
`openbao-init.*` directory under the reviewed RAM root. This is an emergency
recovery buffer, not durable custody or a backup. Do not restart the host,
clean its RAM directory or retry initialization. Have the authorized custody
operator reconcile the server state and securely finish the encrypted export
and verification using the existing offline ceremony procedure. Never copy
the response into logs, Git, CI artifacts or chat. No automatic retry is
performed, and an existing custody destination is never overwritten.

A transport failure may leave the server initialized without delivering any
response. In that case the script cannot recover missing material: stop and
escalate through the recovery authority. Do not infer that initialization
failed merely from a nonzero command status.

## Unseal and restore callers

`scripts/unseal_from_files.py` requires an explicit environment and a plain
`BAO_ADDR` origin. HTTPS requires the trusted CA plus both the client
certificate and private-key paths, with TLS 1.3. Redirects and environment
proxies are disabled. HTTP is allowed only for loopback development/test
fixtures; staging and production restore callers must supply native mTLS.

The custodian-controlled `OPENBAO_UNSEAL_KEY_FILES` list contains one to five
absolute nonsymbolic regular files owned by the execution user, mode `0400`
or `0600`, each nonempty and at most 16 KiB. The entire batch is validated
before any share is submitted; duplicate files and duplicate values fail.
Submission stops as soon as a Boolean `sealed:false` response is received.
Errors print sanitized categories, never share contents or server exceptions.
The helper does not decrypt PGP files or provision custodians. Decrypted
shares remain subject to the existing offline custody and RAM-only policy;
clearing Python references does not guarantee cryptographic memory erasure.

## Workflow compatibility

The initializer requires `OPENBAO_INIT_CUSTODY_DIR`,
`OPENBAO_UNSEAL_PGP_KEY_FILES` and `OPENBAO_ROOT_TOKEN_PGP_KEY_FILE`.
The historical `OPENBAO_INIT_CUSTODY_FILE` variable is unsupported and must not
be restored as a plaintext compatibility path. The separate workflow wiring
repair must pass review and be applied with authorized workflow-write access
before the guarded dispatch can succeed. Its source SHA, runtime identity,
approval checks and non-production-only selection remain required.
