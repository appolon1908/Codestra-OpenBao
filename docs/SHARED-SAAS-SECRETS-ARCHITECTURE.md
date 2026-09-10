# Shared SaaS secret-storage architecture

## Scope

This document defines how OpenBao stores and authorizes secrets for the shared SaaS platform and the product repositories that consume it. Secret values remain in OpenBao and never in Git.

Covered products and services:

- beyvra-frontend / beyvra-backend
- Moneybee-frontend- / Moneybee-Backend
- transportaion-Frontend / transportation-backend-
- LARIM-A-Fornt-end / LARIM-A-Backend
- Breero.com
- booked4seasons
- Frontend-Resturant-
- klyrow.com / klyrow-Website-
- telnexa / Telnexa-web
- Vicidialer-Codestra
- social.codestra.co
- Odoo
- Middleware-
- n8n
- Kong
- Keycloak

## Mount and environment model

Use a KV v2 engine mounted at `codestra/`.

Human-facing secret paths use:

```text
codestra/staging/<service>/<secret-group>
codestra/production/<service>/<secret-group>
```

KV v2 ACLs must target the internal API paths:

```text
codestra/data/<environment>/<service>/*
codestra/metadata/<environment>/<service>/*
```

Production identities must not inherit staging policies and staging identities must never receive production policies.

## Shared SaaS secret groups

The `shared-saas` namespace owns credentials used by the common tenant/workspace platform rather than by a single product.

Recommended groups:

```text
codestra/production/shared-saas/identity/*
codestra/production/shared-saas/billing/*
codestra/production/shared-saas/google-login/*
codestra/production/shared-saas/gmail/*
codestra/production/shared-saas/social/*
codestra/production/shared-saas/webhooks/*
codestra/production/shared-saas/developer-credentials/*
codestra/production/shared-saas/storage/*
codestra/production/shared-saas/notifications/*
```

The shared SaaS backend owns organizations, workspaces, memberships, product entitlements, plans, subscriptions, quotas, metering, integration connections, developer credentials, webhooks, branding metadata and lifecycle state. OpenBao stores only credentials or signing material required to operate those features; customer/business records remain in application databases.

## Product secret groups

### Beyvra

```text
codestra/production/beyvra/market-data/*
codestra/production/beyvra/broker/*
codestra/production/beyvra/exchange/*
codestra/production/beyvra/custody/*
codestra/production/beyvra/funding/*
codestra/production/beyvra/kyc/*
codestra/production/beyvra/webhooks/*
codestra/production/beyvra/signing/*
```

Trading execution credentials are backend-only and require a dedicated execution identity. Browser identities, n8n, observability tooling and unrelated products receive no read capability to these paths.

### Moneybee

```text
codestra/production/moneybee/financial-data/*
codestra/production/moneybee/kyc/*
codestra/production/moneybee/lenders/*
codestra/production/moneybee/esign/*
codestra/production/moneybee/payments/*
codestra/production/moneybee/webhooks/*
```

### Transportation

```text
codestra/production/transportation/carrier-verification/*
codestra/production/transportation/tracking/*
codestra/production/transportation/maps/*
codestra/production/transportation/payments/*
codestra/production/transportation/webhooks/*
```

### LARIMÍA

```text
codestra/production/larim-a/maps/*
codestra/production/larim-a/payments/*
codestra/production/larim-a/provider-verification/*
codestra/production/larim-a/notifications/*
codestra/production/larim-a/webhooks/*
```

### Breero

```text
codestra/production/breero/maps/*
codestra/production/breero/payments/*
codestra/production/breero/technician-verification/*
codestra/production/breero/notifications/*
codestra/production/breero/webhooks/*
```

### booked4seasons

```text
codestra/production/booked4seasons/lead-delivery/*
codestra/production/booked4seasons/captcha/*
codestra/production/booked4seasons/analytics/*
```

### Restaurant

```text
codestra/production/restaurant/payments/*
codestra/production/restaurant/notifications/*
codestra/production/restaurant/delivery/*
codestra/production/restaurant/webhooks/*
```

### Klyrow

```text
codestra/production/klyrow/smtp/*
codestra/production/klyrow/postal/*
codestra/production/klyrow/mautic/*
codestra/production/klyrow/domain-signing/*
codestra/production/klyrow/webhooks/*
```

### Telnexa

```text
codestra/production/telnexa/jasmin/*
codestra/production/telnexa/providers/*
codestra/production/telnexa/sender-registration/*
codestra/production/telnexa/webhooks/*
```

### VICIdial / voice

```text
codestra/production/vicidial/didww/*
codestra/production/vicidial/twilio/*
codestra/production/vicidial/ami/*
codestra/production/vicidial/webhooks/*
```

### Social

```text
codestra/production/social-codestra/postiz/*
codestra/production/social-codestra/postly/*
codestra/production/social-codestra/oauth/*
codestra/production/social-codestra/webhooks/*
```

### Platform services

```text
codestra/production/keycloak/*
codestra/production/kong/*
codestra/production/middleware/*
codestra/production/n8n/*
codestra/production/odoo/*
```

## Frontend rule

Frontend/browser applications never authenticate directly to OpenBao and never receive provider secrets. Frontends call their backend or same-origin BFF. The backend uses a short-lived workload identity to read only the required OpenBao paths.

This rule applies to Beyvra frontend, Moneybee frontend, Transportation frontend, LARIMÍA frontend, Klyrow website, Telnexa web, booked4seasons and Restaurant frontend code.

## API-to-secret ownership

Authentication and SSO secrets belong under Keycloak/shared-saas identity paths. Billing-provider credentials belong under shared-saas billing. Email credentials belong under Klyrow. SMS credentials belong under Telnexa. Social publishing provider credentials belong under social-codestra. Product-specific payment, KYC, broker, maps, lender, carrier or provider credentials remain under the owning product namespace.

Middleware may hold integration signing keys and adapter credentials that are genuinely middleware-owned, but it must not become a universal copy of every product secret.

## Access-policy rules

1. One environment per policy.
2. One service identity per policy.
3. Read/list only where possible; write/delete require a separate operator policy.
4. Frontends receive no OpenBao policy.
5. n8n receives only workflow-specific integration paths and never Beyvra execution credentials.
6. Observability receives no application provider secrets.
7. Production break-glass/operator access is separate from workload access and fully audited.
8. Rotation and revocation must be tested before a credential becomes production-authoritative.
9. Secret values must not appear in CI logs, PR bodies, issues, screenshots, traces, metrics or analytics datasets.

## SaaS API integration model

The public API surface remains behind Caddy + Kong. Keycloak identifies the caller. The shared SaaS backend resolves organization/workspace membership, role, product entitlement and quota. Product backends enforce record ownership and product-specific authorization. Middleware carries integration events and webhooks. n8n handles approved asynchronous workflows. OpenBao provides the credentials those trusted server-side workloads need.

Login alone never grants access to a workspace or product. Authorization requires membership + role + entitlement + record-level checks.

## Bootstrap

`scripts/bootstrap-codestra-secret-authority.sh` can enable the `codestra/` KV v2 engine and install least-privilege read policies. It writes no secret values. Runtime execution requires an already initialized and unsealed OpenBao plus an authorized operator token.

Production trading activation, root/recovery material, unseal custody and secret migration remain separate controlled operations.
