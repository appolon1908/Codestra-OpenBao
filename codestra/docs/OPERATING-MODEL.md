# Codestra OpenBao operating model

## Product boundary

OpenBao is the source of truth for approved application secrets, short-lived database credentials, service PKI and approved cryptographic operations. It is not the identity source of truth, communications platform, observability store, business workflow engine, lender gateway or trading order system. Keycloak authenticates humans and workloads; OpenBao decides which secret or cryptographic capability that identity may use.

## Isolation model

Every Codestra-managed business receives a dedicated KV v2 mount named `kv-<business>/`. Application data is stored beneath `<application>/<environment>/<secret-domain>/...`. Policies are generated from reviewed deployment inventory, never customer input. A business policy never contains a wildcard that reaches another business mount.

Development, test, staging and production identities and paths remain separate. Production workloads cannot use non-production roles. Observability products may receive health, lease, audit-delivery and rotation metrics but never secret values.

## Human access

Human access uses Keycloak OIDC Authorization Code flow with PKCE. Privileged roles require MFA. Daily root-token use is prohibited. Security administrators, auditors and business-scoped secret administrators are separate roles. Auditors can review health, mount/auth/policy metadata and audit configuration without reading secret values.

Break-glass material is held offline under dual control, is time-bound when used and triggers immediate review, credential rotation and evidence capture.

## Workload identity

JWT is the preferred workload method. Every role binds issuer, audience `openbao`, business, application and environment claims. Tokens default to 15 minutes and cannot exceed one hour without a separately reviewed exception. Static long-lived service tokens and unbounded periodic tokens are prohibited.

Workloads receive the minimum KV prefix, database role, PKI role and transit key needed for one application/environment. They cannot create child tokens, alter mounts/auth/audit configuration or enumerate other businesses.

## Secrets and rotation

Dynamic database credentials are preferred. Static provider, OAuth, SMTP, Redis ACL and webhook secrets require an owner, rotation SLA and versioned cutover plan. Webhook/HMAC rotations support dual-active versions. Deployment retirement, operator departure, suspected exposure and provider expiry trigger revocation or rotation.

OpenBao lease, revocation, rotation-failure and audit-delivery evidence is exported as safe aggregate telemetry. Secret values, tokens and unredacted audit fields never enter Prometheus, Loki, Tempo, Grafana or Superset.

## PKI

The preferred model uses an offline root and an online OpenBao intermediate. Service certificate roles constrain business, application, environment and approved DNS names. Default certificate TTL is 24 hours and maximum TTL is seven days. `allow_any_name` and default IP SAN issuance are prohibited. Private keys are non-exportable by default where the engine supports server-side generation.

## Audit and recovery

At least two audit devices are required, including a remote tamper-evident copy. Audit-device failure is release-blocking and alerting is mandatory. Production uses at least three integrated-Raft voting nodes with Autopilot. Encrypted snapshots and restore validation are required; a backup without recent restore evidence is not considered healthy.

## Beyvra high-security compartment

Beyvra uses dedicated `kv-beyvra/` and `transit-beyvra/` mounts. Grafana, Superset, Prometheus, Loki, Tempo, Alloy, n8n and other business workloads are denied secret-value access. Broker, exchange or custody signing is disabled by default. Activation requires dual approval, exact workload binding, non-exportable keys, audit evidence and a separate production change. OpenBao never grants trade-order authority.

## Upstream source integrity

Official OpenBao source is imported from a locked upstream commit. GitHub push-protection-sensitive upstream test fixtures are replaced only by deterministic invalid placeholders, with original block hashes and paths recorded in a sanitization manifest. The importer opens a reviewable PR; it never pushes source directly to production or staging branches.

## Promotion

Promotion is `feature/* -> development -> test -> staging -> production -> main`. A green source PR does not initialize, unseal, configure, deploy or expose OpenBao. Production additionally requires immutable images, TLS, approved seal custody, OIDC/JWT tests, business denial tests, audit devices, PKI constraints, dynamic-credential revocation, Raft restore evidence and explicit Beyvra approval where applicable.
