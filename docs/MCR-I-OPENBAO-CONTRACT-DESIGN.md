# MCR-I secret-reference and policy contract design

Status: DESIGN ONLY — implementation and validation pending pre-change gates.
No runtime, initialization, unseal, policy application, secret issuance, or
provider effects are authorized by this document.

## Authority and scope

MCR-I owns secret references for legitimate campaign sender credentials,
authorized provider adapters, and service authentication. It does not own
campaign eligibility, dispatch, identity issuance, or business routing.

Sources inspected on 2026-09-24:

- [PAS-239](https://linear.app/passion-fruit/issue/PAS-239/plat-secrets-openbao-secrets-authority-initialization-and),
  the existing secrets/security and production-convergence authority.
- [MCR charter](https://app.notion.com/p/3e57518c3e0681f9a5ead29d6790d0b5),
  including its frozen MCR-A milestone and channel authority corrections.
- [OpenBao recovery mission](https://app.notion.com/p/3e57518c3e068181b3e4c9c045621883).
- This repository's `docs/CODESTRA-SECRETS-AUTHORITY.md` and `REPO_AUTHORITY.md`.
- Locally available PAS-239 candidate
  `ebc35a1356f10460a659ce2e38334227734de44e`, reported in Linear as PR #83's
  reviewed head. Its remote head and CI could not be independently refreshed.

Reuse the candidate's `config/workload-secret-authority.v1.json`,
`config/auth/keycloak-jwt.v1.json`, `config/secrets/engines.v1.json`,
`config/audit/audit.v1.json`, `config/recovery/backup.v1.json`, policy/role
generators, and supply-chain gates. These files are absent from this checkout's
base. Do not copy a second deployment, auth plugin, supply-chain exception, or
workload authority into MCR-I. Reconcile the additive contract against the
accepted PAS-239 candidate before runtime integration.

Klyrow owns email/SMS campaign definitions and email execution; Telnexa owns
SMS transport; Codestra WhatsApp owns WhatsApp business state; Evolution API is
the thin WhatsApp adapter behind Middleware; VICIdial owns voice execution.
Middleware owns authorization, decisions, commands, adapter orchestration and
reconciliation. OpenBao is solely the secrets control plane.

## Proposed artifacts and implementation sequence

1. Add failing contract and policy tests using Python's standard library.
2. Add `config/mcr-secret-contract.v1.json` with closed, versioned fields,
   non-secret example references, authority pointers and disabled gates.
3. Add an offline validator for scope, reference syntax, ownership, auth,
   lifecycle and readiness requirements. Reject unknown fields and values
   outside each field's allowed type/range; never print rejected payloads.
4. Add deterministic exact-path HCL generation and a drift check, compatible
   with PAS-239's `codestra/` KV-v2 mount and generated-policy conventions.
   Keep MCR output separate until the PAS-239 generator integration is reviewed.
5. Run unit/negative tests, validator, generated-output drift check and
   `git diff --check`. Run the existing PAS-239 security validators only after
   their source and dependencies are available; do not claim them green here.
6. Commit/push only after required checks pass and Git metadata is writable.
   Verify the remote SHA before reporting a push. No protected merge or deploy.

## Reference-only data model

Each binding must carry schema version, environment, tenant ID, service
identity, credential class, owner, logical path, immutable secret version,
rotation policy and audit requirement. Additional sender/provider/client IDs
are mandatory for their respective classes. No arbitrary `value`, secret
payload, headers, connection strings or free-form secret-bearing metadata is
accepted. A field selector is a field name only, never a credential.

Identifiers use a bounded ASCII slug grammar. Reject empty IDs, `.`/`..`,
slashes, backslashes, URL encodings, whitespace, `*`, `+`, braces, quotes and
control characters. The reference parser must use an exact full match.
Never accept a client-supplied URL, mount or path as an authorization decision.
Environment/tenant/service are checked against trusted workload identity and
server-side ownership records before a reference is resolved.

KV-v2 paths follow the existing logical namespace and preserve the owning
service subtree. Add tenant and resource specificity beneath that subtree.
For example, the existing Klyrow adapter prefix is
`codestra/<environment>/middleware/worker/email/klyrow/`; an MCR sender object
would extend it with `tenants/<tenant>/senders/<sender>/smtp`.
The exact path inventory must distinguish these credential classes:

| Class | Required scope and consumer boundary |
| --- | --- |
| Sender SMTP | One tenant, approved sender, and admitted email execution workload |
| Sender provider API | One tenant, approved sender and provider account; email executor only |
| Sender-domain signing | One tenant, verified brand/domain and signing workload; no general worker grant |
| Provider adapter | One tenant, provider account and admitted email/SMS/WhatsApp/voice adapter |
| Service auth | One tenant, service client and target API; client credential only for its consumer |
| Callback verification | One tenant/provider callback verifier; separated from send credentials |

Existing identity prefixes from PAS-239 are reused where they exist. New
signing, WhatsApp or tenant-specific identities require explicit registration
with PAS-239 and MCR-H; the design does not silently authorize them. A shared
service credential that cannot be tenant-restricted is not admitted as a
tenant-scoped credential. Use a separately reviewed platform role if needed.

No provider credential grants to the browser, Leads Workstation, Thunderbird,
observability, generic planner or N8N. N8N receives only its own authorized
Middleware client reference. Sender registration and brand ownership are
checked by business authorities; possession of a secret reference does not
authorize a send. Credential rotation must not change sender identity to evade
provider enforcement or bypass suppression.

## Policy and authentication contract

Resolve the logical `codestra/<environment>/...` path to
`codestra/data/<environment>/...` for KV-v2 reads. Grant `read` to the exact
object, with no wildcard tenant, service, provider or sender prefixes. Do not
grant metadata listing to consumers; a separately admitted operator may need
it. No write/delete/destroy, token creation, auth administration, `sys/*`,
database, PKI or transit grants are introduced by an MCR reader policy.
Other environments remain denied. Tokens receive only their exact MCR policy
and required self-token operations, with no default or broad legacy policy.
Test effective policy composition, not just an isolated policy file.

Reuse Keycloak workload JWT authentication through PAS-239's `jwt-codestra`
mount, CEL validation and reviewed replay plugin. In the inspected candidate,
issuer is `https://auth.codestra.co/realms/codestra`, audience is `openbao`,
algorithm is RS256, maximum JWT/token lifetime is 300 seconds and clock skew is
30 seconds. Runtime integration must read these from accepted authority rather
than introducing divergent issuer or plugin configuration.

Require signature, issuer, audience, exact AZP/service account subject,
environment and tenant binding, `iat`, `exp`, `jti`, and validity of `nbf` when
present. Tenant claim naming and service-account subject IDs must be frozen
with MCR-H before generating runtime roles. Enforce replay rejection and
fail closed if replay storage is unavailable. No human session, wildcard AZP,
unsigned JWT, shared static root token or fallback broad token is permitted.

Avoid circular bootstrap: a workload cannot obtain the client credential
needed for its initial Keycloak login using that same login. A separately
reviewed bootstrap/workload identity mechanism must deliver initial client
material through protected files. This design does not issue an AppRole,
bootstrap token, certificate or client secret.

## Delivery, leases, rotation and revocation

Reuse agent-rendered, service-owned `0400` files, private tmpfs, atomic
replacement and file references. Never store values in environment variables,
images, repositories, queues, API responses or telemetry. Do not log secret
readback or file contents. Missing/expired/revoked material blocks startup or
stops protected work; stale-cache fallback is forbidden.

Static KV-v2 data has versions, not renewable secret leases. Re-read and
atomically rerender on approved version changes. OpenBao auth tokens have
bounded lifetimes; renew only within their maximum TTL, then reauthenticate.
Dynamic credentials, if separately admitted, use engine-specific bounded
leases, renewal-before-expiry and revocation on shutdown. MCR-I does not enable
dynamic engines or treat static provider keys as automatically leased.

Each family has an owner and rotation deadline of at most 90 days, or the
provider's shorter limit. Rotation requires CAS write of N+1, bounded overlap,
atomic consumer reload, metadata-only readback and an effects-disabled
acceptance check. Then revoke N at the provider and prove N is rejected while
the new version and unrelated tenants remain healthy. Rollback to N is allowed
only while it remains valid; never revive a compromised/revoked credential.

Emergency revocation disables the exact service/client or provider credential,
revokes OpenBao tokens and dynamic child leases, invalidates cached/rendered
material, halts affected dispatch and verifies subsequent denial. Deleting a
KV version or revoking an OpenBao token alone does not invalidate a copied
static provider credential. A secret-read lease is distinct from a campaign
execution lease and provides no business authorization.

## Audit and readiness requirements

Reuse PAS-239's protected JSON audit device, raw logging disabled, accessor
HMAC enabled, file mode `0600`, and approved Alloy-to-Loki redaction. Audit
availability is required before secret use. Record only allowlisted outcome,
request/correlation ID, authorized identity, tenant/environment, reference ID,
version, operation and timestamps. Never publish raw accessors, tokens, JWTs,
credential fingerprints or sensitive response bodies as routine telemetry.
Prove auth denials, foreign-tenant denials, rotation and revocation are audited.
Alerts cover audit failure, sealed state, auth/replay failure, expiry, rotation
failure, backup age and unauthorized policy changes.

All readiness flags begin false. Tests of local contracts do not set them true:

- **Initialization:** inventory existing storage and initialized/sealed status;
  preserve existing state. A reviewed custody ceremony with protected key
  recipients and separated roles is required for a genuinely new cluster.
  Never reinitialize existing storage or collect root/unseal material in Git,
  chat, CI, logs or documents. Bootstrap root-token revocation needs evidence.
- **Unseal:** approved quorum/auto-unseal custody and recovery access, protected
  TLS/network/storage, exact configuration and audit prerequisites. Sealed
  state blocks consumer access; never use initialization as recovery.
- **Supply chain:** reuse PAS-239 exact source/image/plugin identities, SBOM,
  checksums, provenance/signature and vulnerability gates. Its inspected VEX
  includes a disabled-runtime disposition, which cannot authorize activation.
  Revalidate current evidence and the grpc-go runtime gate for the exact image.
- **Readback:** exact source/image/config/policy hashes, auth role and KV mount
  version; one admitted consumer's successful reference resolution without
  exposing bytes; wrong tenant/service/environment denials; no provider writes.
- **Recovery:** encrypted/checksummed off-host immutable Raft backups, verified
  custody, freshness and isolated restore. The inspected PAS-239 targets are
  RPO 24 hours, RTO 4 hours and maximum backup age 26 hours. Reuse accepted
  authority, rehearse restart/restore and reconcile post-snapshot revocations
  before resuming service. An old snapshot must not revive retired access.
- **Rollback:** exact prior image/config/policy artifact, preserved data and
  custody, tested consumer reload and valid credential overlap. Demonstrate
  audit/alerts and denial invariants after rollback.

Production effects remain disabled until separate explicit approval after all
required evidence is fresh. This task must make no network call to OpenBao.

## Required test matrix

Positive fixtures contain non-secret IDs and paths only. Negative tests cover
each class and mutate one condition at a time:

- Unknown/value-bearing fields, invalid types, duplicate IDs, missing version,
  malformed paths, traversal, encoding tricks and wildcard injection.
- Cross-tenant, cross-environment, wrong-service, wrong-sender and
  wrong-provider references; forged ownership and shared-service grants.
- Missing/wrong issuer, audience, AZP, subject, environment or tenant bindings;
  unbounded TTL; missing replay/fail-closed requirements; broad default policy.
- Policy write/list/delete grants, arbitrary mounts, metadata enumeration,
  admin/token creation and union with broad legacy policies.
- Static-KV lease confusion, absent rotation owner/deadline, missing provider
  revocation, indefinite overlap and unsafe rollback to revoked credentials.
- Raw audit logging, missing audit/recovery/readback requirements and any
  enabled runtime/provider/init/unseal flag.
- Deterministic generation, stale/generated-file drift and sanitized validator
  errors. Local checks must require no server, credentials or network.

Real auth, lease, audit, restore and effective ACL behavior require separately
authorized isolated integration tests. Offline tests certify only the contract
and generated source, never runtime security or PAS-239 completion.
