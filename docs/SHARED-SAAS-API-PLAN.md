# Shared SaaS and client API implementation plan

Status: **planned; endpoints and runtime are not implemented by this change**.
This extends the [product API contract](PRODUCT-API-INTEGRATION.md) for Beyvra,
Moneybee, LARIMÍA, Breero, Transportation, Klyrow, Telnexa and Social. One person
can join several client companies and subscribe to several products with separate
permissions and usage limits. `config/shared-saas-api-plan.v1.json` is the
machine-readable index. All routes below are proposed, relative to a future
approved gateway; they do not rename current routes or authorize deployment.

## Responsibility and record ownership

| Component | Authority |
| --- | --- |
| Keycloak | Human and service identity, email login, Google sign-in, MFA, sessions and enterprise SSO. Identity is not a purchase or membership grant. |
| Shared SaaS backend | Organizations, workspaces, invitations, memberships, product assignments, versioned plans, subscription projections, entitlements, quota reservations and usage ledger. Implementation repository is not yet bound. |
| Kong | Approved client registration, credential validation, routing and request rate limits. Each backend still authorizes resources and enforces purchased features and business quotas. |
| Middleware + n8n | Authorized integration commands, event delivery, onboarding, reminders, retry/reconciliation and agreed CRM synchronization. Workflows call owner APIs. |
| OpenBao | Scoped provider credentials, OAuth client secrets and admitted integration secrets. Business records, subscription state and usage stay in application databases. |
| Klyrow / Postal / Mautic | Tenant-scoped transactional and marketing email, sender/domain verification, consent, suppressions and delivery state. |
| Telnexa / Social | Tenant-scoped SMS and publishing, their provider adapters and authoritative delivery/publication records. |
| Billing provider | Payment and invoice facts for SaaS purchases. Stripe documentation is a reference, not a selected or provisioned provider. |
| Odoo | CRM and explicitly mapped accounting/support records; no implicit write authority over subscription access or product balances. |

The shared backend must receive an explicit repository, database, migration owner,
service identity and deployment binding before implementation is admitted. Do not
put its HTTP server or business database in the OpenBao repository. Middleware is
an integration boundary, not automatically the owner of subscription records.
Existing product owners remain unchanged: LARIMÍA bookings, Breero work orders,
Moneybee funding applications, Transportation shipments and Beyvra trading records.

## Organizations, workspaces and authorization

An organization represents a client company and owns its billing account and
subscription items. It has one or more workspaces. A workspace is the product-data
boundary and maps to one immutable `tenant_id`; a workspace belongs to exactly one
organization. Existing tenant IDs need an explicit migration map before rollout.
Every product resource, integration, API credential, idempotency record and event
has a workspace/tenant binding. Organization-wide administration requires a
separate permission and cannot be inferred from a workspace token.

Keycloak's stable `(issuer, subject)` identifies a person. The SaaS backend owns
memberships and product assignments. Never auto-join a workspace from an email
domain or a caller-supplied tenant header. Validate current membership, workspace
status, requested action, resource ownership, product assignment and entitlement
on every request. List, search, export, background jobs, media URLs, cache keys
and WebSocket subscriptions follow the same binding. Database constraints and
row isolation complement API checks. Revocation invalidates cached grants;
unavailable or expired authorization information denies new billable effects.

| Role | Default authority, narrowed by workspace and product permissions |
| --- | --- |
| Owner | Billing, lifecycle, ownership transfer and administrator membership. Require step-up authentication for sensitive changes; prevent removal of the last active owner. |
| Admin | Team invitations and configured product operations within assigned workspaces; no automatic ownership transfer or billing authority. |
| Member | Explicitly assigned product actions and resources; no team, credential-issuance or subscription administration by default. |
| Service principal | Explicit workspace, product, scopes, expiry and quotas; no inherited human owner/admin role. |

Invitations are single-use, expiring, stored as hashes and bound to workspace,
inviter, recipient and allowed roles. Acceptance checks verified recipient identity
and current inviter authority. Seat allocation is atomic. Granting a role or scope
cannot exceed the grantor's delegated authority. Moving a resource to another
workspace is an audited migration, not an editable `tenant_id` field.

## Proposed shared API groups

The prefix is `/saas/v1`. Braces denote resource IDs. Every organization/workspace
ID must be authorized; none is a credential. Paths are a planning index, not a
complete OpenAPI specification or deployed API inventory.

| Category | Proposed resources/actions | Required behavior |
| --- | --- | --- |
| Organizations and workspaces | `/organizations`, `/organizations/{id}/workspaces`, `/workspaces/{id}/settings` | Company creation, settings and strict record separation. |
| Users, teams and permissions | `/me`, `/workspaces/{id}/invitations`, `/workspaces/{id}/memberships`, `/workspaces/{id}/product-assignments` | Invitations, roles, seats, membership revocation and product-specific access. |
| Login and SSO | Keycloak OIDC discovery/authorization/token/logout; `/organizations/{id}/sso-connections` for setup metadata | Email login, Google, MFA and enterprise identity connections; no application password store. |
| Products and plans | `/products`, `/plans`, `/plans/{id}/features` | Versioned tiers, prices, currencies, billing periods, add-ons, seats and feature definitions. |
| Subscriptions | `/organizations/{id}/subscriptions`, `/subscriptions/{id}/changes`, `/subscriptions/{id}/cancellation` | Trials, renewals, upgrades, downgrades and effective dates; verified provider facts determine paid access. |
| Billing and payments | `/organizations/{id}/checkout-sessions`, `/billing-portal-sessions`, `/invoices`, `/refund-requests` | Hosted payment collection, payment-method management, receipts, refunds and failed-payment workflows. |
| Feature access and quotas | `/workspaces/{id}/entitlements`, `/workspaces/{id}/quotas` | Backend enforcement with versioned grants; private worker APIs reserve, commit or release quota atomically. |
| Usage metering | `/workspaces/{id}/usage`, `/workspaces/{id}/usage-exports` | Readable usage and billable units; only admitted producer services may write meter events. |
| Client integrations | `/workspaces/{id}/integrations`, `/integrations/{id}/authorization-sessions`, `/integrations/{id}/disconnect` | Gmail, social, calendars and other authorized connections with status, scopes and ownership. |
| Developer credentials | `/workspaces/{id}/credentials`, `/credentials/{id}/rotations`, `/credentials/{id}/revocation` | Scoped issuance, bounded expiry, rotation, revocation, usage and request history. |
| Webhooks | `/workspaces/{id}/webhooks`, `/webhooks/{id}/deliveries`, `/deliveries/{id}/replay` | Signed outgoing workspace events, retries, delivery history and bounded authorized replay. |
| Branding and domains | `/workspaces/{id}/branding`, `/workspaces/{id}/domains`, `/domains/{id}/verification` | Logos, colors, templates and verified custom domains with explicit routing ownership. |
| Onboarding and lifecycle | `/workspaces/{id}/onboarding`, `/organizations/{id}/lifecycle-requests` | Provisioning progress, suspension, reactivation and closure with product-specific effects. |
| Audit and data management | `/workspaces/{id}/audit-events`, `/exports`, `/retention-settings`, `/deletion-requests` | Sanitized history, scoped exports, retention and asynchronous deletion tracking. |
| Developer portal and support | `/developer/docs`, `/developer/sdks`, `/sandbox-sessions`, `/support-tickets`, `/service-status` | Versioned contracts, SDKs, isolated sandbox, usage dashboards, status and tenant-scoped support. |

## Client websites, apps and connected services

The proposed prefix is `/client/v1`. These routes use the same workspace,
membership, scope, entitlement and usage checks as product APIs. `/client/v1/webhooks`
and SaaS webhook administration address one canonical registration store; they
must not create separate subscriptions or duplicate deliveries.

| Capability | Proposed API surface | Owner / integration |
| --- | --- | --- |
| Google sign-in | Keycloak authorization code flow; no Google password endpoint | Keycloak brokers Google identity. Public browser/mobile clients use PKCE and registered redirect URIs. |
| Transactional email | `POST /email/messages`, `GET /email/messages/{id}`, `GET /email/messages/{id}/events` | Klyrow/Postal, verified tenant sender/domain and authorized recipients. |
| Email marketing | `/email/contacts`, `/email/lists`, `/email/templates`, `/email/campaigns`, `/email/suppressions`, `/email/unsubscribes` | Klyrow/Mautic, consent and unsubscribe enforcement before dispatch. |
| Gmail connection | `POST /integrations/google/authorization-sessions`, `GET /integrations/{id}`, `POST /integrations/{id}/disconnect`, `POST /gmail/messages` | Dedicated Google adapter; mailbox-read routes require a separately requested feature and consent. |
| Social connections | `POST /social/authorization-sessions`, `GET /social/accounts`, `DELETE /social/accounts/{id}` | Social backend maps external account/page ownership to one workspace connection. |
| Publishing and scheduling | `POST /social/media-uploads`, `POST /social/posts`, `GET /social/posts/{id}`, `POST /social/posts/{id}/approval`, `POST /social/posts/{id}/cancellation` | Social backend with selected Postly or Postiz adapter, approvals and durable per-destination outcomes. |
| Social analytics | `GET /social/analytics` | Only the workspace's accounts/posts; expose provider metric availability and time range. |
| Client workspaces | `GET /workspaces`, `GET /workspaces/{id}` | SaaS backend returns only memberships and assigned products; no cross-workspace account discovery. |
| Developer access | `GET /usage`, `GET /requests`; credential lifecycle under SaaS API | Shared SaaS backend + Keycloak/Kong admission. |
| Outgoing webhooks | `POST /webhooks`, `GET /webhooks/{id}`, `DELETE /webhooks/{id}` | Middleware delivers subscribed workspace events from authoritative producers. |

Google login requests identity scopes; Gmail authorization is a separate consent
flow requesting only the mailbox operation the user enables. Validate OAuth state,
nonce where applicable, issuer, audience and exact registered redirects. Bind each
connection attempt to the current principal and workspace, expire and consume it
once, and never link accounts using an unverified email address. Store consented
scopes, external account ID, owner, expiry and status in the database; provider
tokens stay server-side. Disconnect disables queued work, revokes provider access
where supported and removes token access, with reconciliation for failures.
Google describes [identity scopes](https://developers.google.com/identity/openid-connect/openid-connect)
separately from [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes).
Required provider verification/review is a launch dependency for the selected scopes.

Client API scopes should be product/action specific, such as `email.messages.write`,
`social.posts.write` and `social.analytics.read`. Browser apps never hold a client
secret, OpenBao token or provider credential. Machine access uses separately
registered, workspace-bound confidential clients and short-lived credentials;
any opaque API-key option must use one-time display, a nonreversible verifier,
expiry and revocation. Backend checks remain mandatory after Kong validation.
Customer API credentials must not be accepted by the platform's existing internal
control-plane endpoints. CORS, CSRF protections for cookie sessions and registered
origins/redirects are client-specific; origins alone do not authorize records.

Postly documents discovery, uploads, publishing, analytics and webhooks;
[Postly API](https://postly.ai/api). Postiz documents its own integration surface;
[Postiz API](https://docs.postiz.com/public-api/introduction). Choose one adapter
per admitted connection after checking its current operations, quotas and account
mapping. Discovery through a shared provider account must be filtered by verified
workspace mappings. Do not promise every network supports the same media,
analytics, approvals, cancellation or webhook features.

## Subscription state, entitlements and financial separation

Keep SaaS subscription billing in its own provider integration, ledger,
credentials, webhook verifier and reconciliation workflow. It cannot debit,
credit, offset or refund trading balances, loan disbursements, shipment
settlements or provider payouts. Telnexa product wallets also retain their product
ledger authority. Shared customer IDs are references, not authority to move money.

Use hosted checkout/payment-method pages; clients submit approved price IDs and
requested changes, never trusted prices or entitlement flags. Verify raw billing
webhook signatures and provider account/environment binding. Persist a durable
inbox before acknowledging; deduplicate by provider account/environment/event ID.
Resolve subscription/customer ownership from server-held mappings. Handle retries,
out-of-order events and concurrent changes through a serialized subscription
projection and authoritative provider reconciliation. Never grant access from a
checkout success redirect or a caller-supplied `paid=true`.

Entitlements combine verified provider state with a versioned local plan and trial
policy. Trial start/end, grace periods, proration, refunds, seat rules and downgrade
effective dates must be explicit; no invented prices or commercial terms are set
here. A failed or incomplete purchase cannot activate paid features. Plan edits do
not rewrite historical purchases. Cancellation-at-period-end retains only the
agreed access until its effective end. Refunds produce ledger adjustments and an
explicit entitlement decision, not automatic deletion of product records. Stripe
explains its [subscription lifecycle](https://docs.stripe.com/billing/subscriptions/overview);
the selected provider adapter must map its actual states before launch.

Product backends enforce a versioned entitlement snapshot with bounded freshness,
plus current membership and product authorization. Publish invalidation events
through a durable outbox and reconcile missed updates. Recheck at execution time
for scheduled sends/posts; denied work releases any safe-to-release reservation.

SaaS suspension blocks new purchased effects according to each product's policy;
it must preserve approved safety and reconciliation operations. For Beyvra, plan
and test cancel-order/risk-reduction access separately from opening exposure.
Loan, payout and settlement reconciliation must continue under their existing
business authority. Account closure coordinates pending jobs, credentials,
connections, exports, retention requirements and product balances; it must not
silently delete or strand financial records. Subscriptions never enable live
trading or override the existing paper-trading/runtime gates.

## Metering and quota contract

The SaaS backend owns an append-only usage ledger. Product services produce
authenticated facts containing event ID, schema/meter version, organization,
workspace, product, source operation, quantity, unit, occurred/received time and
provider reference where available. Meter ingestion is private; clients can read
their usage but cannot submit billable quantities. Unique producer/event keys
prevent replay; corrections reference the original event instead of rewriting it.

The following are proposed base units; the approved rate card must define prices,
rounding, inclusion, billing windows, late-event cutoff and adjustment treatment.

| Meter | Base unit and counting point |
| --- | --- |
| Email | One provider-accepted recipient delivery; fan-out counts per recipient. Retries of the same delivery are deduplicated; delivery/bounce outcomes are separate facts. |
| SMS | Provider-accepted segment for one recipient; reconcile actual encoding/segmentation with provider records, not just request count. |
| Calls | Connected seconds from finalized call records; versioned rate cards define billable-minute rounding. Duplicate callbacks do not add duration. |
| Social publishing | One successful publication to one destination account; multi-network posts count each successful destination once. |
| Storage | Byte-hours integrated from authoritative storage inventory changes; reconciliation repairs missing measurements. |
| API usage | One authorized accepted logical operation; an idempotent replay is not a second billable operation. Network attempts and rate limiting have separate counters. |
| Seats | One active human member assigned to a product within an organization, deduplicated across its workspaces; alternate commercial rules require a new plan version. |

Quota keys include organization, workspace or explicit organization-wide pool,
product, meter and billing window. Organization pools and workspace sublimits are
reserved in one atomic operation so neither can be overspent by concurrent work.
Reserve before dispatch, commit after the defined counting point, and release on
confirmed nonexecution. Unknown provider outcomes remain pending reconciliation;
blind retry or releasing a reservation can double-send or overspend. Deduplicate
both quota operations and ledger events. Freeze units and window boundaries in
the plan version; represent unlimited explicitly, not with a magic zero value.
Kong request throttles complement, but do not replace, durable quotas.

## Webhooks, data management and API contracts

Outgoing event families include `subscription.changed`, `entitlement.changed`,
`invoice.paid`, `invoice.payment_failed`, `email.delivered`, `email.failed`,
`social.post.published`, `social.post.failed`, `integration.reconnection_required`
and authorized product business events. Every event has a stable ID, version,
workspace/product/source binding, occurrence time and correlation ID; payloads
exclude provider tokens and unnecessary personal data. A subscriber's permissions
bound event types and record visibility; registration alone cannot widen access.

Use verified HTTPS destinations, bounded bodies/timeouts, egress restrictions,
public-address validation on connection and redirect rejection to protect internal
services. Sign the timestamp and raw payload with a per-destination secret and
key ID. Store durable delivery attempts, retry with backoff, expose failures and
allow authorized replay. Delivery is at least once; consumers deduplicate stable
event IDs and enforce timestamp freshness. Rotation has an explicit bounded
overlap. Internal provider webhook ingress is distinct from client event egress.

Public OpenAPI contracts must define strict schemas, scopes, workspace selection,
cursor pagination, stable errors, correlation IDs and `Idempotency-Key` for
side-effecting operations. Bind a key to workspace, principal, action and payload
hash: identical retries return the stored result; a changed payload conflicts.
Long operations return `202` and a tenant-scoped operation/status resource. Specify
timeouts, replay retention and reconciliation before enabling provider effects.
SDKs must preserve these semantics and never retry an unknown financial or
publishing result blindly. Publish deprecation/versioning policy and a sandbox with
separate credentials, records, limits and provider test connections.

Audit privileged changes with actor, organization/workspace, action, target,
outcome, correlation and sanitized change metadata. Export jobs and downloads are
authorized and expire. Retention and deletion requests follow explicit product
policies, including required holds; do not promise immediate deletion of records
that must be retained. Domain onboarding verifies ownership, prevents duplicate
binding, sanitizes branding assets/templates and releases routing on closure.
Support access is scoped, time-bounded and audited; a support ticket grants no
automatic data access.

## Existing source evidence and implementation sequence

Middleware main commit `039c3aeb61853a18ad5d8629ba5494364a77dd1a` was inspected:
`app/api_inputs.py`, `app/control_plane_auth.py`, `app/appolon_factory.py`,
`app/domain_api.py`, `app/communications.py` and the connector-runtime API.
There are tenant-checked messaging/command APIs and admitted machine callers.
Those callers are not general customer applications. Connector webhook ingress
does not establish outgoing client webhook delivery. No full shared SaaS backend,
customer credential issuer or Gmail consent flow is certified by that inspection.
Keycloak supports [identity brokering](https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker);
Google/enterprise provider setup still needs a source-reviewed configuration and
registered clients. Source evidence is not live deployment evidence.

| Phase | Deliverables | Acceptance evidence before rollout |
| --- | --- | --- |
| 1. Ownership and tenancy | Bind SaaS repository/database; workspace-to-tenant migration; schemas, role rules and OpenAPI contracts | Cross-workspace denial for reads, mutations, lists, jobs, exports, caches and streams; invitation, last-owner and membership-revocation cases. |
| 2. Identity and developer access | Keycloak email/Google/MFA/SSO; public PKCE clients; scoped machine credentials and Kong routes | Invalid issuer/audience, revoked identity, wrong workspace/scope, expired invitations and unauthorized role escalation rejected; client credentials cannot reach platform control APIs. |
| 3. Plans and billing | Catalog, subscriptions, hosted checkout, verified event inbox/outbox, entitlement propagation | Forged, replayed and out-of-order events do not grant access; cancellation/grace/downgrade tested; financial ledgers and provider credentials remain separated. |
| 4. Metering and quotas | Private usage ingestion, atomic reservations, reconciliation and dashboards | Concurrent quota exhaustion, duplicate sends/events, unknown outcomes, boundary windows and late corrections produce one accurate ledger result. |
| 5. Client integrations | Transactional/marketing email, Gmail consent, social connections/media/approvals/publishing/analytics and outgoing webhooks | Workspace account mapping, consent changes, unsubscribe, revocation, scheduled permission recheck, delivery retries and webhook destination controls pass in provider sandboxes. |
| 6. Lifecycle and developer portal | Branding/domains, onboarding, closure, exports/retention, SDKs, sandbox, support and status | Domain ownership, export isolation, closure with pending jobs, safe financial access during suspension and documented support access verified. |
| 7. Product rollout | Onboard each of the eight products separately with rollback and reconciliation | Exact source, migrations, telemetry, provider permissions, secret admission and existing protected deployment approvals are satisfied for each product. |

OpenBao admission for future SaaS billing, Google mailbox, social-publishing and
outgoing-webhook workloads requires exact environment/process/secret bindings.
Customer connection tokens require a reviewed write, refresh, revoke and deletion
lifecycle; the current read-only application roles cannot provision those tokens.
Do not broaden them or reuse a universal worker credential. Resolve the intended
tenant/connection secret partition and writer authority before rollout. This plan
adds no secret role, secret value, provider connection or runtime permission.
