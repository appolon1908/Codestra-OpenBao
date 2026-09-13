# Shared SaaS API secret boundary

## Purpose

The shared SaaS layer gives client companies one tenant-aware control plane across
Beyvra, Moneybee, LARIMÍA, Breero, Transportation, Klyrow, Telnexa, Social,
booked4seasons and Restaurant. It owns organizations/workspaces, memberships,
roles, product subscriptions, entitlements, quotas, metering, client integration
metadata, developer credentials, webhook registrations, branding, onboarding and
audit/lifecycle metadata.

It does **not** own product-domain money or records. Trading balances and orders,
loan disbursements, shipment settlements, provider payouts, bookings, work orders
and other product records remain in their owning systems.

`config/shared-saas-api-secrets.v1.json` is the requirements contract for this
boundary. The contract is source-only and does not admit a live OpenBao consumer.

## Admission status

```text
SHARED_SAAS_REQUIREMENTS=MAPPED
SHARED_SAAS_CONSUMER_REPOSITORY=UNBOUND
SHARED_SAAS_OPENBAO_ROLE=NOT_ADMITTED
SHARED_SAAS_RUNTIME_APPLY=false
SHARED_SAAS_PRODUCTION_CHANGED=false
```

A future workload identity named `shared-saas-api` is reserved only as a planning
name. No policy or JWT role may be generated for it until a concrete backend
repository, runtime process and deployment unit are reviewed. This follows the
same fail-closed rule used for other unbound application consumers.

## API groups

The shared control plane requires these versioned API groups:

| API group | Responsibility |
| --- | --- |
| Organizations/workspaces | Tenant creation, settings and isolation |
| Users/teams/permissions | Invitations, membership and owner/admin/member roles |
| Login/SSO | User identity handoff from Keycloak; login alone does not authorize product data |
| Products/plans | Products, price plans, add-ons, seats and feature definitions |
| Subscriptions | Trials, activation, renewal, upgrades, downgrades and cancellation |
| Billing/payments | SaaS checkout, invoices, receipts, refunds and failed-payment handling only |
| Entitlements/quotas | Which products/features a tenant purchased and allowed limits |
| Usage metering | Billable email, SMS, call minutes, social publishing, storage and API units |
| Client integrations | Connection metadata and authorization state for Gmail/social/calendars/providers |
| Developer credentials | Issue, rotate and revoke tenant-scoped API credentials |
| Webhooks | Tenant destinations, event subscriptions, signatures, retries and delivery history |
| Branding/domains | Logos, theme metadata, custom domains and branded templates |
| Onboarding/lifecycle | Provisioning, suspension, reactivation and closure |
| Audit/data management | Activity history, exports, retention and deletion requests |
| Developer portal/support | API documentation, SDK metadata, sandbox/status/support references |

Proposed route groups are recorded in the JSON contract. They are requirements,
not a claim of deployed endpoints.

## Authorization model

A successful login identifies a person. Access to a client workspace or product
requires all of the following independently:

1. authenticated principal;
2. workspace membership;
3. an allowed workspace/product role;
4. an active product entitlement/subscription where applicable;
5. quota/rate checks where applicable; and
6. record-level authorization in the owning product backend.

Kong may enforce route-level authentication and rate controls, but it does not
replace the product backend's record authorization. Odoo, Middleware and n8n do
not become universal data owners because they participate in integrations.

## SaaS billing boundary

SaaS subscription billing is a control-plane concern and must remain separate
from customer/domain money. A subscription billing provider credential may be
held under a future `shared-saas/billing/provider/` namespace after the consumer
is admitted.

The shared SaaS service must not use that credential to custody or move:

- Beyvra trading balances or broker/custody funds;
- Moneybee loan proceeds or lender settlement funds;
- Transportation carrier/customer settlement funds;
- LARIMÍA or Breero provider payout funds; or
- Restaurant/customer order funds unless the owning Restaurant backend explicitly
  owns and authorizes that payment flow.

Those credentials remain under the appropriate product namespace and workload.

## Secret ownership

OpenBao stores server-side configuration secrets for admitted machine identities.
It does not store workspace records, subscriptions, usage rows, messages,
documents or other business records.

Planned shared SaaS secret classes are intentionally narrow:

```text
shared-saas/billing/provider/*
shared-saas/integrations/gmail/*
shared-saas/integrations/encryption/*
shared-saas/developer-credentials/authority/*
shared-saas/webhooks/signing/*
```

Google login remains owned by Keycloak's external identity-provider integration.
Klyrow email provider credentials remain Klyrow-owned. Telnexa SMS provider
credentials remain Telnexa-owned. Social publishing provider credentials remain
Social-owned. Product payment, KYC, broker, lender, maps, carrier and payout
credentials remain in the owning product's namespaces.

The shared SaaS API may keep identifiers and connection state pointing to these
services, but it must not copy their master provider credentials into a global
secret namespace.

## Google sign-in versus Gmail

Google sign-in and Gmail authorization are separate grants. Keycloak owns the
Google login client used to identify a person. Gmail access requires a separate
OAuth application and user/tenant consent for requested mailbox scopes.

A Gmail OAuth application client secret may be an OpenBao configuration secret.
Per-user or per-tenant access/refresh tokens must not be dumped into a global KV
prefix readable by one broad workload role.

## Tenant OAuth-token protection

The preferred model is:

```text
provider access/refresh token
    -> tenant-scoped integration record
    -> envelope encryption
    -> ciphertext in integration database
    -> key authority in OpenBao Transit or equivalently reviewed encryption service
```

This lets the integration store enforce tenant ownership while OpenBao protects
key authority. If a future design uses KV for individual OAuth tokens instead,
it must use tenant-scoped paths and narrowly generated policies; a wildcard
`shared-saas/*` token reader is prohibited.

## Developer API credentials

For tenant developer API keys:

- generate a high-entropy credential server-side;
- show plaintext only at creation time;
- store a key identifier, tenant, scopes, status, timestamps and a one-way hash in
  the SaaS database;
- never persist the plaintext API key after issuance;
- keep any server-side pepper/signing material in OpenBao;
- support explicit rotation, overlap, revocation and audit;
- enforce tenant, product, scope and quota checks at Kong/backend boundaries.

OpenBao therefore protects the authority material used by the issuer, not a
plaintext archive of every client API key.

## Webhooks

Client webhook destinations are business configuration and belong in the SaaS
database. Signing authority can be held in OpenBao or be derived per tenant from
an admitted signing service. Deliveries require event IDs, tenant IDs, timestamp
and replay-window checks, bounded retries, dead-letter handling, idempotent
consumer guidance and sanitized audit records.

Provider webhooks first terminate at the product/provider adapter that owns that
provider secret. Middleware can route normalized events after signature
verification and deduplication.

## OpenBao UI and KV-v2 path model

For the UI shown in the OpenBao Secrets Engines screen, the human-facing KV v2
mount can be `codestra`. Logical secret examples then look like:

```text
codestra/production/moneybee/api/runtime/...
codestra/production/beyvra/execution/provider/...
codestra/production/shared-saas/billing/provider/...
```

KV v2 ACLs must target the internal API forms:

```text
codestra/data/production/<namespace>/*
codestra/metadata/production/<namespace>/*
```

Do not put secret values in Git, PRs, issues, CI logs or screenshots. Do not
create a shared SaaS role manually from the UI before the canonical source
inventory admits the concrete workload.

## Runtime activation gates

Before `shared-saas-api` can read any production secret, all of these are
required:

- exact backend repository and deployment process binding;
- canonical workload identity inventory update;
- deterministic policy and Keycloak JWT-role generation;
- exact environment and audience/client claims;
- cross-tenant, cross-product and cross-environment denial tests;
- audit-device proof without secret values;
- developer-key issuance/revocation proof without plaintext retention;
- tenant OAuth-token encryption/deletion proof;
- billing webhook signature/replay tests;
- rotation and emergency revocation proof; and
- protected promotion through `development -> test -> staging -> production -> main`.

Until then, this document and its JSON contract are architecture/source authority
only. No secret value, token, policy or runtime binding is created by this change.
