# Repository Authority

Canonical service hostname: `bao.codestra.media`
Canonical DNS A target: `37.27.128.39`
DNS TTL: `600`

This repository is the principal source authority for the Codestra OpenBao
deployment and configuration. Do not introduce alternate public hostnames or
legacy domain names in configuration, documentation, examples, health checks
or deployment manifests.

Exposure policy: **restricted operator and private API access only**.
`bao.codestra.media` may be routed through the external edge authority only
with strong authentication, strict network policy, TLS, security headers, rate
limits, audit logging and least-privilege policies. Native storage, cluster and
administration ports must remain private. Never expose bootstrap or recovery
material, root tokens, private keys, secret values or provider credentials.

Approved platform services authenticate to OpenBao with individually admitted,
least-privilege machine identities. OpenBao returns only their scoped secrets
or leases. Audit metadata and bounded operational health flow to the
observability stack. OpenBao is not a general data store and must never bypass
Middleware business authorization.

## Branch and promotion authority

Persistent protected branches:

```text
development -> test -> staging -> production -> main
```

Only these temporary branch classes may target `development`:

```text
remediation/*
sync/openbao-upstream-*
```

Other historical branch prefixes may remain visible for traceability, but they
are not admissible into a protected integration branch. Their valid changes
must be rebuilt on the current `development` head under `remediation/*`.
Deterministic upstream synchronization may target `development` only through a
reviewed `sync/openbao-upstream-*` pull request.

Protected branches must never be force-pushed or bypassed. Upgrades must not be
performed directly on `test`, `staging`, `production` or `main`.

## Runtime mutation boundary

Runtime mutation is not implied by a merge. A checksummed plan must be created
from the exact current environment branch, independently reviewed and applied
without regeneration only after `@kazan555` approves the protected environment.

Initialization, recovery custody, operator access, business-effect
authorization and SSH access are separate authorities. Orbit adoption is also
separate: a valid consumer manifest does not install packages, alter native
OpenBao behavior, publish a domain, enable SSO or authorize runtime
deployment.
