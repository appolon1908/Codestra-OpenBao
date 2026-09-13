# Product API integration and record ownership

The requested API groups and shared-service rules are captured in
`config/product-api-integration.v1.json`. This contract covers 19 application
repositories across 13 product/service groups. It is a requirements and ownership
contract, not a claim that every API is implemented or deployed. The proposed
`/<product>/v1/` prefixes are examples supplied in the brief; existing routes are
not renamed by this change. Eight additional repository main trees are recorded
in `config/integration-source-observations.v1.json`, without runtime claims.

The [shared SaaS and client API plan](SHARED-SAAS-API-PLAN.md) extends these
product boundaries with organizations, workspaces, teams, Google/SSO login,
subscriptions, entitlement enforcement, quotas, metering, developer credentials,
email/Gmail/social integrations and outgoing client webhooks. The eight requested
SaaS products retain their domain records. This additional layer is planned;
its implementation repository and runtime bindings still require admission.

A separate cross-product SaaS control-plane contract is recorded in
`config/shared-saas-api-secrets.v1.json` and documented in
[Shared SaaS API secrets](SHARED-SAAS-API-SECRETS.md). It defines organizations,
workspaces, memberships, subscriptions, entitlements, quotas, metering, client
integrations, developer credentials and webhook requirements without inventing a
runtime consumer or granting a new OpenBao role.

| Product/service | Authoritative source | Requested API groups |
| --- | --- | --- |
| larimia | `appolon1908-hue/LARIM-A-Backend` | service-catalog, providers, verification, service-areas, availability, pricing, bookings, rescheduling, dispatch, job-status, payments, refunds, payouts, reviews, disputes |
| breero | `appolon1908-hue/Breero.com` | properties, service-requests, estimates, technicians, availability, matching, work-orders, dispatch, arrival-tracking, job-photos, customer-acceptance, invoices, payments, warranties |
| moneybee | `appolon1908-hue/Moneybee-Backend` | borrowers, businesses, consent, applications, documents, financial-connections, underwriting, lender-criteria, lender-matches, submissions, offers, signatures, funding-status |
| transportation | `appolon1908-hue/transportation-backend-` | shippers, carriers, carrier-verification, equipment, quotes, loads, tenders, assignments, dispatch, tracking, appointments, proof-of-delivery, invoices, settlements, claims |
| klyrow | `appolon1908-hue/klyrow.com` | accounts, domains, verification, senders, messages, templates, contacts, campaigns, suppressions, unsubscribes, events, usage, billing, plans, signup, onboarding, subscriptions, support |
| telnexa | `appolon1908-hue/telnexa` | messages, status, senders, routing, inbound, receipts, consent, opt-outs, wallets, pricing, usage, billing, plans, coverage, signup, business-verification, sender-registrations, onboarding, support |
| vicidial | `appolon1908-hue/Vicidialer-Codestra` | agents, campaigns, assignments, availability, queues, calls, transfers, callbacks, dispositions, events, recordings, supervisor-reporting |
| social | `appolon1908-hue/social.codestra.co` | channels, media, drafts, approvals, calendar, scheduling, publishing-status, analytics, engagement |
| realtime | `appolon1908-hue/Websocket-` | session, subscriptions, call-state, screen-pops, presence, reconnect, resume, acknowledgement |
| odoo | `appolon1908-hue/Odoo` | contacts, leads, opportunities, campaign-assignments, activities, quotations, invoices, payment-reconciliation, support-tickets, product-references |
| beyvra | `appolon1908-hue/beyvra-backend` | authentication, kyc, instruments, market-data, orders, accounts, portfolio, funding, risk, research, notifications, reports, operations |
| booked4seasons | `appolon1908-hue/booked4seasons` | service-requests, contact, provider-interest |
| restaurant | `Backend unbound` | reservations, orders, tables, kitchen, staff |

LARIMÍA owns bookings, Breero owns work orders, Moneybee owns funding applications
and Transportation owns shipments. Odoo receives selected fields and references
through integrations. Until an explicit field map is approved, no Odoo-to-product
field is writable. Every mapped event needs source system, record ID, version,
tenant, correlation and event identifiers, plus deduplication and reconciliation.
Odoo's own CRM/accounting records remain separate records with their own authority.

The shared API controls require tenant/record/role authorization, a versioned
contract, sanitized audit events and duplicate-request protection. Idempotency is
scoped to tenant, principal and operation; a repeated key with a different payload
must conflict. Outbound side effects and provider-event processing need durable
results, replay controls and reconciliation. These requirements do not claim all
existing route handlers have already passed their implementation tests.

## Shared SaaS control plane

The shared SaaS layer applies across the products without becoming the owner of
product-domain data. Its API groups are:

- organizations and workspaces;
- users, teams and permissions;
- login and SSO integration;
- products and plans;
- subscriptions and SaaS billing;
- feature entitlements and quotas;
- usage metering;
- client integrations;
- developer credentials;
- client webhooks;
- branding and domains;
- onboarding and account lifecycle;
- audit/data-management controls; and
- developer portal and support metadata.

A successful login identifies the principal only. Workspace membership, role,
product entitlement and record-level authorization still decide what data and
actions are available. One account can subscribe to multiple products while each
product keeps separate permissions and usage limits.

SaaS subscription billing is explicitly separate from customer money. The SaaS
control plane must not custody or move Beyvra trading balances, Moneybee funding,
Transportation settlements, LARIMÍA/Breero provider payouts or other product-domain
funds merely because the same tenant has a paid SaaS subscription.

The planned `shared-saas-api` identity is **not admitted** to OpenBao yet because
no exact backend repository/runtime process has been bound in the reviewed source.
Do not compensate with a manual wildcard role. The shared SaaS contract instead
records narrow planned authority for subscription-billing configuration, Gmail
OAuth application configuration, webhook signing, integration encryption and
developer-credential authority material. Product/provider master credentials stay
in their owning namespaces.

Tenant developer API keys should be shown once and stored as a one-way hash plus
metadata; any server-side pepper/signing material belongs in OpenBao. Tenant OAuth
access/refresh tokens should be tenant-scoped and encrypted in the integration
store using OpenBao Transit or an equivalently reviewed envelope-encryption key,
not placed as plaintext under one globally readable KV prefix.

Existing `klyrow-email-adapter`, `telnexa-sms-adapter`, `vicidial-adapter` and
`odoo-integration` policies cover their admitted platform integrations. They are
not universal native-provider administration roles. Social and realtime require
separate exact workload admission before new secret access; no broad worker
policy is handed to browser-facing applications. Websocket- carries authorized
call-state events and screen pops, without audio transport.

Jasmin supplies SMS submission, receipts, balance/rate queries and metrics; the
customer API still needs the application authorization, consent and billing
contract. [Jasmin HTTP API](https://docs.jasminsms.com/en/latest/apis/http/index.html).
Postiz exposes social integrations, posts, uploads and analytics; application
approval and tenant controls remain part of the integration.
[Postiz API](https://docs.postiz.com/public-api/introduction).

See [Application secret storage](APPLICATION-API-SECRET-STORAGE.md) for the seven
newly admitted workload identities and four backend consumer changes. See
[Shared SaaS API secrets](SHARED-SAAS-API-SECRETS.md) for the cross-product SaaS
control-plane secret boundary. Provider credentials stay in their scoped private
OpenBao namespaces; user, booking, funding, shipment, message and call records
stay in their domain stores.
