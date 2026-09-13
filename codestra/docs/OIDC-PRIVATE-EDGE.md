# Codestra OpenBao OIDC and Private-Edge Contract

## Purpose

This contract preserves the exact human-identity and private-access requirements for the Codestra OpenBao authority at `https://bao.codestra.media`. It is source configuration only and does not enable OpenBao, Keycloak, Caddy, a client secret, a policy, or a login path.

## Authority boundaries

- **Keycloak** authenticates human operators and emits the approved identity, realm-role, business and environment claims.
- **OpenBao** remains the final authorization authority. Successful OIDC authentication never grants secret access without an independently reviewed OpenBao policy.
- **Caddy** may provide the reviewed edge network gate, but it never replaces OpenBao mTLS, authentication or policy enforcement.
- **OpenBao runtime** uses TLS 1.3 and required client-certificate verification on its private service network. Native ports 8200 and 8201 are never Internet-published.

## Canonical client

```text
issuer:       https://auth.codestra.co/realms/codestra
client ID:    openbao-secrets
secret file:  /run/secrets/openbao_oidc_client_secret
PKCE:         S256
```

Approved callbacks are limited to:

```text
https://bao.codestra.media/v1/auth/oidc/callback
https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback
http://localhost:8250/oidc/callback
```

No default OpenBao OIDC role is allowed. A user must select an approved role and present the matching Keycloak realm role.

## Human roles

```text
Keycloak secrets-operator -> OpenBao codestra-secrets-operator
Keycloak secrets-admin    -> OpenBao codestra-secrets-admin
```

Both roles require MFA, audience `openbao-secrets`, an approved callback, a `codestra_business` claim and an `environment` claim. Generated policies must be limited to that exact business and environment. Cross-business wildcards, `root`, broadly permissive `default` policy use and all-secrets policies are prohibited.

The operator role uses a 15-minute TTL and 30-minute maximum. The admin role uses a 10-minute TTL and 15-minute maximum. Privileged sessions must not become long-lived substitutes for workload identity.

## Workload separation

Human OIDC is not the normal application authentication path. Workloads use short-lived audience-bound JWT identities or an explicitly approved exception mechanism. Grafana, Loki, Tempo, Prometheus, OpenTelemetry, Superset, n8n and other observability or analytics identities cannot authenticate into a human secrets role or inherit a human policy.

Beyvra observability identities remain unable to read broker, exchange or custody credentials, decrypt protected trading payloads, export transit keys or sign trades.

## Required negative tests

Before any apply, prove all of the following:

1. Wrong issuer, audience or callback is denied.
2. Missing Keycloak role is denied.
3. Missing MFA is denied for both privileged roles.
4. Missing business or environment claim is denied.
5. A role for one business cannot receive another business policy.
6. Observability and analytics roles cannot enter an OpenBao secrets role.
7. A secrets operator cannot acquire an admin policy.
8. Native API and cluster ports are unreachable from the public Internet.
9. Revoked Keycloak sessions and tokens cannot continue indefinitely.
10. No client secret, OpenBao token, recovery share, private key or secret value appears in Git, CI logs, edge logs or observability data.

## Activation blockers

The following remain mandatory and false in source-first mode:

- Keycloak client applied;
- client secret installed;
- OIDC auth method enabled;
- roles or policies applied;
- privileged MFA enforcement proven;
- negative tests passed;
- production login enabled.

A green pull request validates the desired-state contract only. It does not authorize initialization, unseal, OIDC apply, edge reload, public exposure, secret installation or production access.
